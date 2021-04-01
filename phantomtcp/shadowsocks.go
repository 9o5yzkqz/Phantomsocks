package phantomtcp

import (
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const MaxAddrLen = 1 + 1 + 255 + 2

// Listen on addr for incoming connections.
func ShadowsocksTCPRemote(addr string, shadow func(net.Conn) net.Conn) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logPrintln(1, "failed to listen on", addr, err)
		return
	}

	logPrintln(1, "listening TCP on", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logPrintln(1, "failed to accept:", err)
			continue
		}

		go func() {
			defer c.Close()

			c.(*net.TCPConn).SetKeepAlive(true)
			c = shadow(c)

			var b [MaxAddrLen]byte
			_, err := io.ReadFull(c, b[:1]) // read 1st byte for address type
			if err != nil {
				logPrintln(3, c.RemoteAddr(), err)
				return
			}

			var host string
			var port int

			var config Config
			var ok = false

			switch b[0] {
			case socks.AtypDomainName:
				_, err = io.ReadFull(c, b[1:2]) // read 2nd byte for domain length
				if err != nil {
					logPrintln(3, err)
					return
				}
				_, err = io.ReadFull(c, b[2:2+b[1]+2])
				if err != nil {
					logPrintln(3, err)
					return
				}
				host = string(b[2 : 2+b[1]])
				port = int(binary.BigEndian.Uint16(b[2+b[1] : 2+b[1]+2]))

				config, ok = ConfigLookup(host)
			case socks.AtypIPv4:
				_, err = io.ReadFull(c, b[1:1+net.IPv4len+2])
				if err != nil {
					logPrintln(3, err)
					return
				}

				port = int(binary.BigEndian.Uint16(b[1+net.IPv4len : 1+net.IPv4len+2]))
				if port == 53 {
					var b [1024]byte
					n, err := c.Read(b[:])
					if err != nil {
						logPrintln(3, err)
						return
					}
					if n != int(binary.BigEndian.Uint16(b[:2])+2) {
						logPrintln(3, err)
						return
					}
					response := NSRequest(b[2:n], true)
					resLen := uint16(len(response))
					binary.BigEndian.PutUint16(b[:], resLen)
					copy(b[2:], response)
					c.Write(b[:resLen+2])
					return
				}

				if b[1] == 6 {
					index := int(binary.BigEndian.Uint16(b[3:5]))
					if index >= len(Nose) {
						return
					}
					host = Nose[index]
					config, ok = ConfigLookup(host)
				} else {
					host = net.IPv4(b[1], b[2], b[3], b[4]).String()
					config, ok = DomainMap[host]
				}

			case socks.AtypIPv6:
				_, err = io.ReadFull(c, b[1:1+net.IPv6len+2])
				if err != nil {
					logPrintln(3, err)
					return
				}

				port = int(binary.BigEndian.Uint16(b[1+net.IPv6len : 1+net.IPv6len+2]))
				if port == 53 {
					var b [1024]byte
					n, err := c.Read(b[:])
					if err != nil {
						logPrintln(3, err)
						return
					}
					if n != int(binary.BigEndian.Uint16(b[:2])+2) {
						logPrintln(3, err)
						return
					}
					response := NSRequest(b[2:n], true)
					resLen := uint16(len(response))
					binary.BigEndian.PutUint16(b[:], resLen)
					copy(b[2:], response)
					c.Write(b[:resLen+2])
					return
				}

				host = net.IP(b[1 : 1+net.IPv6len]).String()

				config, ok = DomainMap[host]
			default:
				logPrintln(2, "not supported")
				return
			}

			var rc net.Conn
			if ok {
				if config.Option&OPT_PROXY == 0 {
					_, ips := NSLookup(host, config.Option, config.Server)
					if len(ips) == 0 {
						logPrintln(1, host, "no such host")
						return
					}

					if config.Option == 0 {
						rc, err = Dial(ips, port, nil, nil)
						if err != nil {
							logPrintln(1, err)
							return
						}
					} else {
						var b [1500]byte
						n, err := c.Read(b[:])
						if err != nil {
							logPrintln(1, err)
							return
						}

						if b[0] == 0x16 {
							offset, length := GetSNI(b[:n])
							var conf *Config = nil
							if length > 0 {
								host = string(b[offset : offset+length])
								config, ok = ConfigLookup(host)
								conf = &config
							}

							logPrintln(1, "Shadowsocks:", c.RemoteAddr(), "->", host, port, config)

							rc, err = Dial(ips, port, b[:n], conf)
							if err != nil {
								logPrintln(1, host, err)
								return
							}
						} else {
							logPrintln(1, "Shadowsocks:", c.RemoteAddr(), "->", host, port, config)
							if config.Option&OPT_HTTPS != 0 {
								HttpMove(c, "https", b[:n])
								return
							} else if config.Option&OPT_MOVE != 0 {
								HttpMove(c, config.Server, b[:n])
								return
							} else if config.Option&OPT_STRIP != 0 {
								ip := ips[rand.Intn(len(ips))]
								rc, err = DialStrip(ip.String(), "")
								if err != nil {
									logPrintln(1, err)
									return
								}
								_, err = rc.Write(b[:n])
							} else {
								rc, err = HTTP(c, ips, port, b[:n], &config)
								if err != nil {
									logPrintln(1, err)
									return
								}
								io.Copy(c, rc)
								return
							}
						}
					}
				} else {
					logPrintln(1, "Shadowsocks:", c.RemoteAddr(), "<->", host, port, config)

					if (config.Option & OPT_MODIFY) != 0 {
						var b [1500]byte
						n, err := c.Read(b[:])
						if err != nil {
							logPrintln(1, err)
							return
						}
						rc, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), config.Server, b[:n], &config)
					} else if config.Device != "" {
						rc, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), config.Server, nil, &config)
					} else {
						rc, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), config.Server, nil, nil)
					}

					if err != nil {
						logPrintln(1, host, err)
						return
					}
				}
			} else {
				addr := net.JoinHostPort(host, strconv.Itoa(port))
				logPrintln(1, "Shadowsocks", c.RemoteAddr(), "<->", addr)
				rc, err = net.Dial("tcp", addr)
				if err != nil {
					logPrintln(1, "failed to connect to target:", addr, err)
					return
				}
			}

			if rc == nil {
				logPrintln(1, "failed to connect to target:", addr)
				return
			}

			defer rc.Close()
			switch rc := rc.(type) {
			case *net.TCPConn:
				rc.SetKeepAlive(true)
			}

			_, _, err = relay(c, rc)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logPrintln(1, "relay error:", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func relay(left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

type mode int

const (
	remoteServer mode = iota
	relayClient
	socksClient
)

const udpBufSize = 64 * 1024

// Listen on addr for encrypted packets and basically do UDP NAT.
func ShadowsocksUDPRemote(addr string, shadow func(net.PacketConn) net.PacketConn) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		logPrintln(1, "UDP remote listen error:", err)
		return
	}
	defer c.Close()
	c = shadow(c)

	UDPTimeout := time.Minute * 5
	nm := newNATmap(UDPTimeout)
	buf := make([]byte, udpBufSize)

	logPrintln(1, "listening UDP on", addr)
	for {
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			logPrintln(1, "UDP remote read error:", err)
			continue
		}

		tgtAddr := socks.SplitAddr(buf[:n])
		if tgtAddr == nil {
			logPrintln(1, "failed to split target address from packet:", buf[:n])
			continue
		}

		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			logPrintln(1, "failed to resolve target UDP address:", err)
			continue
		}

		payload := buf[len(tgtAddr):n]

		var pc net.PacketConn
		if tgtUDPAddr.Port == 53 {
			request := make([]byte, len(payload))
			copy(request, payload)
			go func(peer net.Addr, dst net.PacketConn, request []byte) {
				response := NSRequest(request, true)
				dst.WriteTo(response, peer)
			}(raddr, c, request)
		} else {
			pc = nm.Get(raddr.String())
			if pc == nil {
				pc, err = net.ListenPacket("udp", "")
				if err != nil {
					logPrintln(1, "UDP remote listen error:", err)
					continue
				}
				nm.Add(raddr, c, pc, remoteServer)
			}

			_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
			if err != nil {
				logPrintln(1, "UDP remote write error:", err)
				continue
			}
		}
	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func newNATmap(timeout time.Duration) *natmap {
	m := &natmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *natmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *natmap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *natmap) Add(peer net.Addr, dst, src net.PacketConn, role mode) {
	m.Set(peer.String(), src)

	go func() {
		timedCopy(dst, peer, src, m.timeout, role)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(dst net.PacketConn, target net.Addr, src net.PacketConn, timeout time.Duration, role mode) error {
	buf := make([]byte, udpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		switch role {
		case remoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteTo(buf[:len(srcAddr)+n], target)
		case relayClient: // client -> user: strip original packet source
			srcAddr := socks.SplitAddr(buf[:n])
			_, err = dst.WriteTo(buf[len(srcAddr):n], target)
		case socksClient: // client -> socks5 program: just set RSV and FRAG = 0
			_, err = dst.WriteTo(append([]byte{0, 0, 0}, buf[:n]...), target)
		}

		if err != nil {
			return err
		}
	}
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func ShadowsocksServer(addr string) {
	addr, cipher, password, err := parseURL(addr)
	if err != nil {
		log.Fatal(err)
	}

	host, port, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if ip == nil {
		addr = net.JoinHostPort("", port)
	}

	cipher = strings.ToUpper(cipher)

	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		log.Fatal(err)
	}

	go ShadowsocksUDPRemote(addr, ciph.PacketConn)
	go ShadowsocksTCPRemote(addr, ciph.StreamConn)
}

func ShadowsocksDial(conn net.Conn, host string, port int, cipher, password string) (net.Conn, error) {
	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}

	conn = ciph.StreamConn(conn)
	ip := net.ParseIP(host)

	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			var tgt [7]byte
			tgt[0] = socks.AtypIPv4
			copy(tgt[1:], ip4)
			binary.BigEndian.PutUint16(tgt[5:], uint16(port))
			_, err = conn.Write(tgt[:7])
		} else {
			var tgt [19]byte
			tgt[0] = socks.AtypIPv6
			copy(tgt[1:], ip)
			binary.BigEndian.PutUint16(tgt[17:], uint16(port))
			_, err = conn.Write(tgt[:19])
		}
	} else {
		var tgt [MaxAddrLen]byte
		tgt[0] = socks.AtypDomainName
		tgt[1] = byte(len(host))
		copy(tgt[2:], []byte(host))
		binary.BigEndian.PutUint16(tgt[tgt[1]+2:], uint16(port))
		_, err = conn.Write(tgt[:tgt[1]+4])
	}

	return conn, err
}
