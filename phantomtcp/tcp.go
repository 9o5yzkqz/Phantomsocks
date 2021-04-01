package phantomtcp

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConnectionInfo struct {
	Link gopacket.LinkLayer
	IP   gopacket.NetworkLayer
	TCP  layers.TCP
}

type SynInfo struct {
	Number uint32
	Option uint32
}

var ConnSyn sync.Map
var ConnInfo4 [65536]chan *ConnectionInfo
var ConnInfo6 [65536]chan *ConnectionInfo
var ConnWait4 [65536]uint32
var ConnWait6 [65536]uint32
var TFOCookies sync.Map
var TFOPayload [64][]byte
var TFOSynID uint8 = 0

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func IsAddressInUse(err error) bool {
	//return errors.Is(err, syscall.EADDRINUSE)
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	return false
}

func IsNormalError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	switch e := errOpError.Err.(type) {
	case *os.SyscallError:
		errErrno, ok := e.Err.(syscall.Errno)
		if !ok {
			return false
		}

		if errErrno == syscall.ETIMEDOUT ||
			errErrno == syscall.ECONNREFUSED ||
			errErrno == syscall.ECONNRESET {
			return true
		}
	default:
		//logPrintln(2, reflect.TypeOf(e))
		return true
	}

	return false
}

func AddConn(synAddr string, option uint32) {
	result, ok := ConnSyn.LoadOrStore(synAddr, SynInfo{1, option})
	if ok {
		info := result.(SynInfo)
		info.Number++
		info.Option = option
		ConnSyn.Store(synAddr, info)
	}
}

func DelConn(synAddr string) {
	result, ok := ConnSyn.Load(synAddr)
	if ok {
		info := result.(SynInfo)
		if info.Number > 1 {
			info.Number--
			ConnSyn.Store(synAddr, info)
		} else {
			ConnSyn.Delete(synAddr)
		}
	}
}

func GetLocalAddr(name string, ipv6 bool) (*net.TCPAddr, error) {
	if name == "" {
		return nil, nil
	}

	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		localAddr, ok := addr.(*net.IPNet)
		if ok {
			var laddr *net.TCPAddr
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP[0] == 0xfe {
					continue
				}
				ip := make([]byte, 16)
				copy(ip[:16], localAddr.IP)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			} else {
				if ip4 == nil {
					continue
				}
				ip := make([]byte, 4)
				copy(ip[:4], ip4)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			}

			return laddr, nil
		}
	}

	return nil, nil
}

func Dial(addresses []net.IP, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	device := ""
	offset := 0
	length := 0

	if conf != nil {
		device = conf.Device
		if b != nil {
			if conf.Option|OPT_MODIFY != 0 {
				offset, length = GetSNI(b)
			}
		}
	}

	if length > 0 {
		rand.Seed(time.Now().UnixNano())

		fakepaylen := 1280
		if len(b) < fakepaylen {
			fakepaylen = len(b)
		}
		fakepayload := make([]byte, fakepaylen)
		copy(fakepayload, b[:fakepaylen])

		min_dot := offset + length
		max_dot := offset
		for i := offset; i < offset+length; i++ {
			if fakepayload[i] == '.' {
				if i < min_dot {
					min_dot = i
				}
				if i > max_dot {
					max_dot = i
				}
			} else {
				fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
			}
		}
		if min_dot == max_dot {
			min_dot = offset
		}
		cut := (min_dot + max_dot) / 2

		var tfo_payload []byte = nil
		if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
			if (conf.Option & OPT_TFO) != 0 {
				tfo_payload = b
			} else {
				tfo_payload = b[:cut]
			}
		}

		var synpacket *ConnectionInfo
		for i := 0; i < 5; i++ {
			ip := addresses[rand.Intn(len(addresses))]

			laddr, err := GetLocalAddr(device, ip.To4() == nil)
			if err != nil {
				return nil, errors.New("invalid device")
			}

			raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}

			conn, synpacket, err = DialConnInfo(laddr, raddr, conf, tfo_payload)

			logPrintln(2, ip, port, err)
			if err != nil {
				if IsNormalError(err) {
					continue
				}
				return nil, err
			}

			break
		}

		if synpacket == nil {
			if conn != nil {
				conn.Close()
			}
			return nil, errors.New("connection does not exist")
		}

		synpacket.TCP.Seq++
		count := 1
		if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
			if (conf.Option & OPT_HTFO) != 0 {
				_, err = conn.Write(b[cut:])
				if err != nil {
					conn.Close()
					return nil, err
				}
			}
		} else {
			if conf.Option&OPT_SSEG != 0 {
				_, err = conn.Write(b[:4])
				if err != nil {
					conn.Close()
					return nil, err
				}
			}

			if conf.Option&OPT_MODE2 != 0 {
				synpacket.TCP.Seq += uint32(cut)
				fakepayload = fakepayload[cut:]
				count = 2
			} else {
				if conf.Option&OPT_MODE3 != 0 {
					for i := 0; i < length; i++ {
						fakepayload[i] = byte(rand.Intn(256))
					}
				}
				err = ModifyAndSendPacket(synpacket, fakepayload, conf.Option, conf.TTL, count)
				if err != nil {
					conn.Close()
					return nil, err
				}
			}

			if conf.Option&OPT_SSEG != 0 {
				_, err = conn.Write(b[4:cut])
			} else {
				_, err = conn.Write(b[:cut])
			}
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = ModifyAndSendPacket(synpacket, fakepayload, conf.Option, conf.TTL, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		return conn, err
	} else {
		ip := addresses[rand.Intn(len(addresses))]

		var laddr *net.TCPAddr = nil
		if conf.Device != "" {
			laddr, err = GetLocalAddr(device, ip.To4() == nil)
			if err != nil {
				return nil, err
			}
		}

		raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
		conn, err = net.DialTCP("tcp", laddr, raddr)
		if err != nil {
			return nil, err
		}

		if b != nil {
			_, err = conn.Write(b)
			if err != nil {
				conn.Close()
			}
		}

		return conn, err
	}
}

func HTTP(client net.Conn, addresses []net.IP, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	if b != nil {
		offset, length := GetHost(b)

		if length > 0 {
			rand.Seed(time.Now().UnixNano())

			fakepaylen := 1280
			if len(b) < fakepaylen {
				fakepaylen = len(b)
			}
			fakepayload := make([]byte, fakepaylen)
			copy(fakepayload, b[:fakepaylen])

			min_dot := offset + length
			max_dot := offset
			for i := offset; i < offset+length; i++ {
				if fakepayload[i] == '.' {
					if i < min_dot {
						min_dot = i
					}
					if i > max_dot {
						max_dot = i
					}
				} else {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}
			if min_dot == max_dot {
				min_dot = offset
			}
			cut := (min_dot + max_dot) / 2

			var connInfo *ConnectionInfo
			for i := 0; i < 5; i++ {
				ip := addresses[rand.Intn(len(addresses))]

				laddr, err := GetLocalAddr(conf.Device, ip.To4() == nil)
				if err != nil {
					continue
				}

				raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
				conn, connInfo, err = DialConnInfo(laddr, raddr, conf, nil)
				logPrintln(2, ip, port, err)
				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}
			}

			if connInfo == nil {
				return nil, errors.New("connection does not exist")
			}

			count := 1
			if conf.Option&OPT_MODE2 == 0 {
				err = ModifyAndSendPacket(connInfo, fakepayload, conf.Option, conf.TTL, 1)
				if err != nil {
					conn.Close()
					return nil, err
				}
			} else {
				connInfo.TCP.Seq += uint32(cut)
				fakepayload = fakepayload[cut:]
				count = 2
			}

			_, err = conn.Write(b[:cut])
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = ModifyAndSendPacket(connInfo, fakepayload, conf.Option, conf.TTL, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}

			connInfo.TCP.Seq += uint32(len(b))
			go func() {
				var b [1460]byte
				for {
					n, err := client.Read(b[:])
					if err != nil {
						conn.Close()
						return
					}

					err = ModifyAndSendPacket(connInfo, fakepayload, conf.Option, conf.TTL, 2)
					if err != nil {
						conn.Close()
						return
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						conn.Close()
						return
					}
					connInfo.TCP.Seq += uint32(n)
				}
			}()

			return conn, err
		} else {
			ip := addresses[rand.Intn(len(addresses))]

			var laddr *net.TCPAddr = nil
			if conf.Device != "" {
				laddr, err = GetLocalAddr(conf.Device, ip.To4() == nil)
				if err != nil {
					return nil, err
				}
			}

			raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err != nil {
				return nil, err
			}
			_, err = conn.Write(b)
			if err != nil {
				conn.Close()
				return conn, err
			}
			go io.Copy(conn, client)
			return conn, err
		}
	}

	ip := addresses[rand.Intn(len(addresses))]
	raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
	conn, err = net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return conn, err
	}

	go io.Copy(conn, client)
	return conn, err
}

func DialProxy(address string, proxy string, header []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	u, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}

	proxyhost := u.Host
	scheme := u.Scheme
	proxy_err := errors.New("invalid proxy")

	var synpacket *ConnectionInfo
	var method uint32 = 0

	host, port := splitHostPort(address)
	proxyaddr, proxyport := splitHostPort(proxyhost)
	if proxyport == 0 {
		if scheme == "nat64" {
			proxyhost = net.JoinHostPort(proxyaddr+host, strconv.Itoa(port))
		} else {
			proxyhost = net.JoinHostPort(proxyaddr, strconv.Itoa(port))
		}
	}

	if conf != nil {
		if header != nil {
			if conf.Option&OPT_HTTP != 0 {
				var request_host string = ""
				if header[0] == 0x16 {
					offset, length := GetSNI(header)
					request_host = string(header[offset : offset+length])
				} else {
					offset, length := GetHost(header)
					request_host = string(header[offset : offset+length])
				}
				if host != request_host {
					return nil, proxy_err
				}
			}
			method = conf.Option & OPT_MODIFY
		}

		raddr, err := net.ResolveTCPAddr("tcp", proxyhost)
		if err != nil {
			return nil, err
		}
		laddr, err := GetLocalAddr(conf.Device, raddr.IP.To4() == nil)
		if err != nil {
			return nil, err
		}

		if method != 0 {
			method = conf.Option
			conn, synpacket, err = DialConnInfo(laddr, raddr, conf, nil)
			if err != nil {
				return nil, err
			}

			if synpacket == nil {
				if conn != nil {
					conn.Close()
				}
				return nil, errors.New("connection does not exist")
			}
			synpacket.TCP.Seq++
		} else {
			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err != nil {
				return nil, err
			}
		}
	} else {
		conn, err = net.Dial("tcp", proxyhost)
		if err != nil {
			return nil, err
		}
	}

	var proxy_seq uint32 = 0
	switch scheme {
	case "http":
		{
			request := []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", address))
			fakepayload := make([]byte, len(request))
			var n int = 0
			if method != 0 {
				if method&OPT_SSEG != 0 {
					n, err = conn.Write(request[:4])
					if err != nil {
						conn.Close()
						return nil, err
					}
				} else if method&OPT_MODE2 != 0 {
					n, err = conn.Write(request[:10])
					if err != nil {
						conn.Close()
						return nil, err
					}
				}

				proxy_seq += uint32(n)
				err = ModifyAndSendPacket(synpacket, fakepayload, method, conf.TTL, 2)
				if err != nil {
					conn.Close()
					return nil, err
				}

				if method&OPT_SSEG != 0 {
					n, err = conn.Write(request[4:])
				} else if method&OPT_MODE2 != 0 {
					n, err = conn.Write(request[10:])
				} else {
					n, err = conn.Write(request)
				}
				if err != nil {
					conn.Close()
					return nil, err
				}
				proxy_seq += uint32(n)
			} else {
				n, err = conn.Write(request)
				if err != nil {
					conn.Close()
					return nil, err
				}
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				conn.Close()
				return nil, errors.New("failed to connect to proxy")
			}
		}
	case "socks":
		{
			var b [264]byte
			if method != 0 {
				err := ModifyAndSendPacket(synpacket, b[:], method, conf.TTL, 2)
				if err != nil {
					conn.Close()
					return nil, err
				}
			}

			n, err := conn.Write([]byte{0x05, 0x01, 0x00})
			if err != nil {
				conn.Close()
				return nil, err
			}
			proxy_seq += uint32(n)
			_, err = conn.Read(b[:])
			if err != nil {
				conn.Close()
				return nil, err
			}

			if b[0] != 0x05 {
				conn.Close()
				return nil, proxy_err
			}

			copy(b[:], []byte{0x05, 0x01, 0x00, 0x03})
			hostLen := len(host)
			b[4] = byte(hostLen)
			copy(b[5:], []byte(host))
			binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
			n, err = conn.Write(b[:7+hostLen])
			if err != nil {
				conn.Close()
				return nil, err
			}
			proxy_seq += uint32(n)
			n, err = conn.Read(b[:])
			if err != nil {
				conn.Close()
				return nil, err
			}
			if n < 2 {
				conn.Close()
				return nil, proxy_err
			}
			if b[0] != 0x05 {
				conn.Close()
				return nil, proxy_err
			}
			if b[1] != 0x00 {
				conn.Close()
				return nil, proxy_err
			}
		}
	case "ss":
		cipher := u.User.Username()
		password, _ := u.User.Password()

		if u.Path != "" {
			extHeader, err := base64.StdEncoding.DecodeString(u.Path[1:])
			if err != nil {
				conn.Close()
				return nil, err
			}
			_, err = conn.Write(extHeader)
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		conn, err = ShadowsocksDial(conn, host, port, cipher, password)
		if err != nil {
			conn.Close()
			return nil, err
		}
	case "redirect":
	case "nat64":
	default:
		conn.Close()
		return nil, proxy_err
	}

	if method == 0 {
		if header != nil {
			_, err = conn.Write(header)
			if err != nil {
				conn.Close()
			}
		}
		return conn, err
	} else if header == nil {
		return conn, err
	}

	offset, length := GetSNI(header)
	if length > 0 {
		fakepaylen := 1280
		if len(header) < fakepaylen {
			fakepaylen = len(header)
		}
		fakepayload := make([]byte, fakepaylen)
		copy(fakepayload, header[:fakepaylen])

		min_dot := offset + length
		max_dot := offset
		for i := offset; i < offset+length; i++ {
			if fakepayload[i] == '.' {
				if i < min_dot {
					min_dot = i
				}
				if i > max_dot {
					max_dot = i
				}
			} else {
				fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
			}
		}
		if min_dot == max_dot {
			min_dot = offset
		}
		cut := (min_dot + max_dot) / 2

		count := 1
		if method&OPT_SSEG != 0 {
			_, err = conn.Write(header[:4])
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		synpacket.TCP.Seq += proxy_seq
		if method&OPT_MODE2 != 0 {
			synpacket.TCP.Seq += uint32(cut)
			fakepayload = fakepayload[cut:]
			count = 2
		} else {
			err = ModifyAndSendPacket(synpacket, fakepayload, method, conf.TTL, count)
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		if method&OPT_SSEG != 0 {
			_, err = conn.Write(header[4:cut])
		} else {
			_, err = conn.Write(header[:cut])
		}
		if err != nil {
			conn.Close()
			return nil, err
		}

		err = ModifyAndSendPacket(synpacket, fakepayload, method, conf.TTL, count)
		if err != nil {
			conn.Close()
			return nil, err
		}

		_, err = conn.Write(header[cut:])
		if err != nil {
			conn.Close()
			return nil, err
		}

		return conn, err
	} else {
		_, err = conn.Write(header)
		if err != nil {
			conn.Close()
		}
		return conn, err
	}
}
