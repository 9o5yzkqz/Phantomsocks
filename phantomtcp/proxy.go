package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func SocksProxy(client net.Conn) {
	defer client.Close()

	host := ""
	var conf Config
	var ok bool

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			log.Println(client.RemoteAddr(), err)
			return
		}

		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if n != 4 {
				return
			}

			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[4:6]))
				addr := net.TCPAddr{IP: b[:4], Port: port, Zone: ""}
				conf, ok := ConfigLookup(addr.IP.String())
				if ok {
					logPrintln(1, "Socks:", addr.IP.String(), addr.Port, conf)
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					n, err = client.Read(b[:])

					ip := addr.IP
					result, ok := ACache.Load(ip.String())
					var addresses []net.IP
					if ok {
						addresses = make([]net.IP, len(result.(DomainIP).Addresses))
						copy(addresses, result.(DomainIP).Addresses)
					} else {
						addresses = []net.IP{ip}
					}
					conn, err = Dial(addresses, port, b[:n], &conf)
				} else {
					logPrintln(1, "Socks:", addr.IP.String(), addr.Port)

					conn, err = net.DialTCP("tcp", nil, &addr)
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				}
			case 0x03: //Domain
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[n-2:]))
				addrLen := b[0]
				host = string(b[1 : addrLen+1])
				conf, ok = ConfigLookup(host)
				if ok {
					if conf.Option&OPT_PROXY == 0 {
						logPrintln(1, "Socks:", host, port, conf)

						_, ips := NSLookup(host, conf.Option, conf.Server)
						if len(ips) == 0 {
							logPrintln(1, host, "no such host")
							return
						}

						if conf.Option == 0 {
							conn, err = Dial(ips, port, nil, nil)
							if err != nil {
								logPrintln(1, err)
								return
							}

							n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
							if err != nil {
								conn.Close()
								logPrintln(1, err)
								return
							}
						} else {
							n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
							if err != nil {
								logPrintln(1, err)
								return
							}

							n, err = client.Read(b[:])
							if err != nil {
								logPrintln(1, err)
								return
							}

							if b[0] != 0x16 {
								if conf.Option&OPT_HTTPS != 0 {
									HttpMove(client, "https", b[:n])
									return
								} else if conf.Option&OPT_MOVE != 0 {
									HttpMove(client, conf.Server, b[:n])
									return
								} else if conf.Option&OPT_STRIP != 0 {
									rand.Seed(time.Now().UnixNano())
									ipaddr := ips[rand.Intn(len(ips))]
									conn, err = DialStrip(ipaddr.String(), "")
									if err != nil {
										logPrintln(1, err)
										return
									}
									_, err = conn.Write(b[:n])
								} else {
									conn, err = HTTP(client, ips, 80, b[:n], &conf)
									if err != nil {
										logPrintln(1, err)
										return
									}
									io.Copy(client, conn)
									return
								}
							} else {
								conn, err = Dial(ips, port, b[:n], &conf)
								if err != nil {
									logPrintln(1, host, err)
									return
								}
							}
						}
					} else {
						logPrintln(1, "SocksoverProxy:", client.RemoteAddr(), "->", host, port, conf)

						if conf.Option&OPT_MODIFY != 0 {
							n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
							if err != nil {
								conn.Close()
								logPrintln(1, err)
								return
							}

							n, err = client.Read(b[:])
							if err != nil {
								logPrintln(1, err)
								return
							}

							conn, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), conf.Server, b[:n], &conf)
						} else {
							conn, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), conf.Server, nil, nil)
							if err != nil {
								logPrintln(1, host, err)
								return
							}

							n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						}
					}
				} else {
					addr := net.JoinHostPort(host, strconv.Itoa(port))
					logPrintln(1, "Socks:", addr)
					conn, err = net.Dial("tcp", addr)
					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				}
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				port := int(binary.BigEndian.Uint16(b[16:18]))
				addr := net.TCPAddr{IP: b[:16], Port: port, Zone: ""}
				logPrintln(1, "Socks:", addr.IP.String(), addr.Port)
				conn, err = net.DialTCP("tcp", nil, &addr)
				client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			default:
				logPrintln(1, "not supported")
				return
			}
		} else {
			return
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func splitHostPort(hostport string) (host string, port int) {
	var err error
	host = hostport
	port = 0

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		port, err = strconv.Atoi(host[colon+1:])
		if err != nil {
			port = 0
		}
		host = host[:colon]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

func HTTPProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var method, host string
		var port int
		fmt.Sscanf(string(b[:bytes.IndexByte(b[:], '\n')]), "%s%s", &method, &host)

		if method == "CONNECT" {
			fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
			n, err = client.Read(b[:])
			if err != nil {
				logPrintln(1, err)
				return
			}
		} else {
			if strings.HasPrefix(host, "http://") {
				host = host[7:]
				index := strings.IndexByte(host, '/')
				if index != -1 {
					host = host[:index]
				}
			} else {
				return
			}
		}

		host, port = splitHostPort(host)
		if port == 0 {
			port = 80
		}

		conf, ok := ConfigLookup(host)

		if ok {
			if conf.Option&OPT_PROXY == 0 {
				logPrintln(1, "HTTP:", host, port, conf)

				_, ips := NSLookup(host, conf.Option, conf.Server)
				if len(ips) == 0 {
					logPrintln(1, host, "no such host")
					return
				}

				if b[0] == 0x16 {
					conn, err = Dial(ips, port, b[:n], &conf)
					if err != nil {
						logPrintln(1, host, err)
						return
					}
				} else {
					if conf.Option&OPT_HTTPS != 0 {
						HttpMove(client, "https", b[:n])
						return
					} else if conf.Option&OPT_MOVE != 0 {
						HttpMove(client, conf.Server, b[:n])
						return
					} else if conf.Option&OPT_STRIP != 0 {
						ip := ips[rand.Intn(len(ips))]
						conn, err = DialStrip(ip.String(), "")
						if err != nil {
							logPrintln(1, err)
							return
						}
						_, err = conn.Write(b[:n])
					} else {
						conn, err = HTTP(client, ips, port, b[:n], &conf)
						if err != nil {
							logPrintln(1, err)
							return
						}
						io.Copy(client, conn)
						return
					}
				}
			} else {
				logPrintln(1, "HTTPoverProxy:", client.RemoteAddr(), "->", host, port, conf)

				conn, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), conf.Server, b[:n], &conf)
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			}
		} else {
			host = net.JoinHostPort(host, strconv.Itoa(port))
			logPrintln(1, host)

			conn, err = net.Dial("tcp", host)
			if err != nil {
				logPrintln(1, err)
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				logPrintln(1, err)
				return
			}
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func SNIProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var host string
		var port int
		if b[0] == 0x16 {
			offset, length := GetSNI(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			port = 443
		} else {
			offset, length := GetHost(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			portstart := strings.Index(host, ":")
			if portstart == -1 {
				port = 80
			} else {
				port, err = strconv.Atoi(host[portstart+1:])
				if err != nil {
					return
				}
				host = host[:portstart]
			}
			if net.ParseIP(host) != nil {
				return
			}
		}

		conf, ok := ConfigLookup(host)

		if ok {
			logPrintln(1, "SNI:", host, port, conf)

			_, ips := NSLookup(host, conf.Option, conf.Server)
			if len(ips) == 0 {
				logPrintln(1, host, "no such host")
				return
			}

			if b[0] == 0x16 {
				conn, err = Dial(ips, port, b[:n], &conf)
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			} else {
				if conf.Option&OPT_HTTPS != 0 {
					HttpMove(client, "https", b[:n])
					return
				} else if conf.Option&OPT_MOVE != 0 {
					HttpMove(client, conf.Server, b[:n])
					return
				} else if conf.Option&OPT_STRIP != 0 {
					ip := ips[rand.Intn(len(ips))]
					conn, err = DialStrip(ip.String(), "")
					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(b[:n])
				} else {
					conn, err = HTTP(client, ips, port, b[:n], &conf)
					if err != nil {
						logPrintln(1, err)
						return
					}
					io.Copy(client, conn)
					return
				}
			}
		} else {
			host = net.JoinHostPort(host, strconv.Itoa(port))
			logPrintln(1, host)

			conn, err = net.Dial("tcp", host)
			if err != nil {
				logPrintln(1, err)
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				logPrintln(1, err)
				return
			}
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func RedirectProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var host string
		var port int
		var ips []net.IP = nil
		addr, err := GetOriginalDST(client.(*net.TCPConn))
		if err != nil {
			logPrintln(1, err)
			return
		}

		ip := []byte(addr.IP)
		iptype := binary.BigEndian.Uint16(ip[:2])
		switch iptype {
		case 0x2000:
			index := int(binary.BigEndian.Uint32(ip[12:16]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		case 0x0600:
			index := int(binary.BigEndian.Uint16(ip[2:4]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		default:
			if addr.String() == client.LocalAddr().String() {
				return
			}
			host = addr.IP.String()
			ips = []net.IP{addr.IP}
		}
		port = addr.Port

		config, ok := ConfigLookup(host)

		if ok {
			if config.Option&OPT_PROXY == 0 {
				if ips == nil {
					_, ips = NSLookup(host, config.Option, config.Server)
					if len(ips) == 0 {
						logPrintln(1, host, "no such host")
						return
					}
				}

				if config.Option == 0 {
					conn, err = Dial(ips, port, nil, &config)
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var b [1500]byte
					n, err := client.Read(b[:])
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

						logPrintln(1, "Redirect:", client.RemoteAddr(), "->", host, port, config)

						conn, err = Dial(ips, port, b[:n], conf)
						if err != nil {
							logPrintln(1, host, err)
							return
						}
					} else {
						logPrintln(1, "Redirect:", client.RemoteAddr(), "->", host, port, config)
						if config.Option&OPT_HTTPS != 0 {
							HttpMove(client, "https", b[:n])
							return
						} else if config.Option&OPT_MOVE != 0 {
							HttpMove(client, config.Server, b[:n])
							return
						} else if config.Option&OPT_STRIP != 0 {
							ip := ips[rand.Intn(len(ips))]
							conn, err = DialStrip(ip.String(), "")
							if err != nil {
								logPrintln(1, err)
								return
							}
							_, err = conn.Write(b[:n])
						} else {
							conn, err = HTTP(client, ips, port, b[:n], &config)
							if err != nil {
								logPrintln(1, err)
								return
							}
							io.Copy(client, conn)
							return
						}
					}
				}
			} else {
				logPrintln(1, "RedirectProxy:", client.RemoteAddr(), "->", host, port, config)

				if config.Option == OPT_PROXY {
					conn, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), config.Server, nil, nil)
				} else {
					var b [1500]byte
					n, err := client.Read(b[:])
					if err != nil {
						logPrintln(1, err)
						return
					}

					conn, err = DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), config.Server, b[:n], &config)
				}

				if err != nil {
					logPrintln(1, host, err)
					return
				}
			}
		} else if ips != nil {
			logPrintln(1, "RedirectProxy:", client.RemoteAddr(), "->", addr)
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				logPrintln(1, host, err)
				return
			}
		}
	}

	if conn == nil {
		return
	}

	defer conn.Close()

	//go io.Copy(client, conn)
	//io.Copy(conn, client)
	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logPrintln(1, "relay error:", err)
	}
}
