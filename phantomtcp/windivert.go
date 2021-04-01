// +build windows
//// +build !windows

package phantomtcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/macronut/godivert"
)

var winDivertLock sync.Mutex
var winDivert *godivert.WinDivertHandle

func DevicePrint() {
}

func connectionMonitor(layer uint8) {
	filter := "tcp.Syn"

	var err error
	winDivertLock.Lock()
	winDivert, err = godivert.WinDivertOpen(filter, layer, 1, 0)
	winDivertLock.Unlock()
	if err != nil {
		fmt.Printf("winDivert open failed: %v", err)
		return
	}
	defer winDivert.Close()

	for {
		divertpacket, err := winDivert.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		ipv6 := divertpacket.Raw[0]>>4 == 6
		var packet gopacket.Packet
		if ipv6 {
			packet = gopacket.NewPacket(divertpacket.Raw, layers.LayerTypeIPv6, gopacket.Default)
		} else {
			packet = gopacket.NewPacket(divertpacket.Raw, layers.LayerTypeIPv4, gopacket.Default)
		}

		ip := packet.NetworkLayer()
		tcp := packet.TransportLayer().(*layers.TCP)
		synack := tcp.SYN && tcp.ACK

		switch ip := ip.(type) {
		case *layers.IPv4:
			var srcPort layers.TCPPort
			var synAddr string
			var method uint32 = 0
			if synack {
				method = ConnWait4[tcp.DstPort]
				if method == 0 {
					winDivert.Send(divertpacket)
					continue
				}
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
				result, ok := ConnSyn.Load(synAddr)
				if ok {
					info := result.(SynInfo)
					method = info.Option
				}
			}

			if method != 0 {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.TTL = 128

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo4[srcPort]
				connInfo := &ConnectionInfo{nil, ip, *tcp}

				if method&(OPT_TFO|OPT_HTFO|OPT_SYNX2) != 0 {
					if synack {
						if method&(OPT_TFO|OPT_HTFO) != 0 {
							for _, op := range tcp.Options {
								if op.OptionType == 34 {
									TFOCookies.Store(ip.DstIP.String(), op.OptionData)
								}
							}
						}
						ConnWait4[srcPort] = 0
					} else if method&(OPT_TFO|OPT_HTFO) != 0 {
						if ip.TTL < 128 {
							count := 1
							if method&OPT_SYNX2 != 0 {
								count = 2
							}

							tfo_id := ip.TTL & 63
							ip.TTL = 128
							if tcp.SYN == true {
								payload := TFOPayload[tfo_id]
								if payload != nil {
									ip.TOS = 0
									ModifyAndSendPacket(connInfo, payload, OPT_TFO, 0, count)
									ConnWait4[srcPort] = method
								} else {
									connInfo = nil
								}
							} else {
								ip.TOS = 0
								ModifyAndSendPacket(connInfo, nil, OPT_TFO, 0, count)
								connInfo = nil
							}
						}
					} else if method&OPT_SYNX2 != 0 {
						winDivert.Send(divertpacket)
						SendPacket(packet)
					}
				} else {
					winDivert.Send(divertpacket)
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			} else {
				winDivert.Send(divertpacket)
			}
		case *layers.IPv6:
			var srcPort layers.TCPPort
			var synAddr string
			var method uint32 = 0
			if synack {
				method = ConnWait6[tcp.DstPort]
				if method == 0 {
					winDivert.Send(divertpacket)
					continue
				}
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
				result, ok := ConnSyn.Load(synAddr)
				if ok {
					info := result.(SynInfo)
					method = info.Option
				}
			}
			if method != 0 {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.HopLimit = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo6[srcPort]
				connInfo := &ConnectionInfo{nil, ip, *tcp}

				if method&(OPT_TFO|OPT_HTFO|OPT_SYNX2) != 0 {
					if synack {
						if method&(OPT_TFO|OPT_HTFO) != 0 {
							for _, op := range tcp.Options {
								if op.OptionType == 34 {
									TFOCookies.Store(ip.DstIP.String(), op.OptionData)
								}
							}
						}
						ConnWait6[srcPort] = 0
					} else if method&(OPT_TFO|OPT_HTFO) != 0 {
						if ip.HopLimit < 128 {
							count := 1
							if method&OPT_SYNX2 != 0 {
								count = 2
							}

							tfo_id := ip.HopLimit & 63
							ip.HopLimit = 128
							if tcp.SYN == true {
								payload := TFOPayload[tfo_id]
								if payload != nil {
									ip.TrafficClass = 0
									ModifyAndSendPacket(connInfo, payload, OPT_TFO, 0, count)
									ConnWait4[srcPort] = method
								} else {
									connInfo = nil
								}
							} else {
								ip.TrafficClass = 0
								ModifyAndSendPacket(connInfo, nil, OPT_TFO, 0, count)
								connInfo = nil
							}
						}
					} else if method&OPT_SYNX2 != 0 {
						winDivert.Send(divertpacket)
						SendPacket(packet)
					}
				} else {
					winDivert.Send(divertpacket)
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			} else {
				winDivert.Send(divertpacket)
			}
		default:
			winDivert.Send(divertpacket)
		}
	}
}

func ConnectionMonitor(devices []string) bool {
	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo, 1)
		ConnInfo6[i] = make(chan *ConnectionInfo, 1)
	}

	go connectionMonitor(0)

	return true
}

func SendPacket(packet gopacket.Packet) error {
	payload := packet.LinkLayer().LayerPayload()

	var divertAddr godivert.WinDivertAddress
	var divertpacket godivert.Packet
	divertpacket.Raw = payload
	divertpacket.PacketLen = uint(len(divertpacket.Raw))
	divertpacket.Addr = &divertAddr
	divertpacket.ParseHeaders()

	_, err := winDivert.Send(&divertpacket)
	return err
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, method uint32, ttl uint8, count int) error {
	ipLayer := connInfo.IP

	var tcpLayer *layers.TCP
	if method&OPT_TFO != 0 {
		tcpLayer = &connInfo.TCP

		tcpLayer.Seq -= uint32(len(payload))
		var cookie []byte = nil
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			result, ok := TFOCookies.Load(ip.DstIP.String())
			if ok {
				cookie = result.([]byte)
			} else {
				payload = nil
			}
		case *layers.IPv6:
			result, ok := TFOCookies.Load(ip.DstIP.String())
			if ok {
				cookie = result.([]byte)
			} else {
				payload = nil
			}
		}

		tcpLayer.Options = append(connInfo.TCP.Options,
			layers.TCPOption{34, uint8(len(cookie)), cookie},
		)
	} else {
		tcpLayer = &layers.TCP{
			SrcPort:    connInfo.TCP.SrcPort,
			DstPort:    connInfo.TCP.DstPort,
			Seq:        connInfo.TCP.Seq,
			Ack:        connInfo.TCP.Ack,
			DataOffset: 5,
			ACK:        true,
			PSH:        true,
			Window:     connInfo.TCP.Window,
		}

		if method&OPT_WMD5 != 0 {
			tcpLayer.Options = []layers.TCPOption{
				layers.TCPOption{19, 18, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			}
		} else if method&OPT_WTIME != 0 {
			tcpLayer.Options = []layers.TCPOption{
				layers.TCPOption{8, 8, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
			}
		}
	}

	if method&OPT_NACK != 0 {
		tcpLayer.ACK = false
		tcpLayer.Ack = 0
	} else if method&OPT_WACK != 0 {
		tcpLayer.Ack += uint32(tcpLayer.Window)
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true

	if method&OPT_WCSUM == 0 {
		options.ComputeChecksums = true
	}

	if method&OPT_WSEQ != 0 {
		tcpLayer.Seq--
		fakepayload := make([]byte, len(payload)+1)
		fakepayload[0] = 0xFF
		copy(fakepayload[1:], payload)
		payload = fakepayload
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		if method&OPT_TTL != 0 {
			ip.TTL = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	case *layers.IPv6:
		if method&OPT_TTL != 0 {
			ip.HopLimit = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	}

	var divertAddr godivert.WinDivertAddress
	var divertpacket godivert.Packet
	divertpacket.Raw = buffer.Bytes()
	divertpacket.PacketLen = uint(len(divertpacket.Raw))
	divertpacket.Addr = &divertAddr
	divertpacket.ParseHeaders()
	divertpacket.CalcNewChecksum(winDivert)

	for i := 0; i < count; i++ {
		_, err := winDivert.Send(&divertpacket)
		if err != nil {
			return err
		}
	}

	return nil
}

func Redirect(dst string, to_port int, forward bool) {
	if dst == "" {
		return
	}
	var filter string
	var layer uint8

	var dstfilter string
	iprange := strings.SplitN(dst, "-", 2)
	logPrintln(1, dst)
	if len(iprange) > 1 {
		dstfilter = fmt.Sprintf("ip.DstAddr>=%s and ip.DstAddr<=%s and tcp", iprange[0], iprange[1])
	} else {
		dstfilter = fmt.Sprintf("ip.DstAddr=%s and tcp", dst)
	}

	if forward {
		filter = fmt.Sprintf("(%s) or (ip.SrcAddr>127.255.0.0 and ip.SrcAddr<127.255.255.255 and tcp.SrcPort=%s)", dstfilter, strconv.Itoa(to_port))
		layer = 1
	} else {
		filter = fmt.Sprintf("(outbound and %s) or (ip.SrcAddr>127.255.0.0 and ip.SrcAddr<127.255.255.255 and tcp.SrcPort=%s)", dstfilter, strconv.Itoa(to_port))
		layer = 0
	}

	winDivertLock.Lock()
	winDivert, err := godivert.WinDivertOpen(filter, layer, 0, 0)
	winDivertLock.Unlock()
	if err != nil {
		fmt.Printf("winDivert open failed: %v with %s", err, filter)
		return
	}
	defer winDivert.Close()

	var localIP net.IP
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		srcIP := packet.SrcIP().To4()
		dstIP := packet.DstIP().To4()

		dstPort, _ := packet.DstPort()
		if srcIP[0] == 127 && srcIP[1] == 255 && dstIP[0] == 127 && dstIP[1] == 0 {
			packet.SetSrcIP(net.IPv4(6, 0, srcIP[2], srcIP[3]))
			packet.SetDstIP(localIP)
			packet.SetSrcPort(uint16(dstIP[2])<<8 | uint16(dstIP[3]))
		} else {
			localIP = srcIP.To16()
			packet.SetSrcIP(net.IPv4(127, 0, byte(dstPort>>8), byte(dstPort&0xFF)))
			packet.SetDstIP(net.IPv4(127, 255, dstIP[2], dstIP[3]))
			packet.SetDstPort(uint16(to_port))
		}

		packet.CalcNewChecksum(winDivert)
		winDivert.Send(packet)
	}
}

func RedirectDNS() {
	winDivertLock.Lock()
	winDivert, err := godivert.WinDivertOpen("outbound and udp.DstPort=53", 0, 0, 0)
	winDivertLock.Unlock()
	if err != nil {
		fmt.Printf("winDivert open failed: %v", err)
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}
		ipv6 := packet.Raw[0]>>4 == 6

		var ipheadlen int
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(packet.Raw[0]&0xF) * 4
		}
		udpheadlen := 8
		request := packet.Raw[ipheadlen+udpheadlen:]
		qname, qtype, _ := GetQName(request)
		if qname == "" {
			logPrintln(2, "DNS Segmentation fault")
			continue
		}

		conf, ok := ConfigLookup(qname)
		if ok {
			index, _ := NSLookup(qname, conf.Option, conf.Server)

			var response []byte
			if qtype == 28 {
				response = BuildResponse(request, qtype, 0, nil)
			} else {
				response = BuildLie(request, qtype, index)
			}
			udpsize := len(response) + 8

			var packetsize int
			if ipv6 {
				copy(rawbuf, []byte{96, 12, 19, 68, 0, 98, 17, 128})
				packetsize = 40 + udpsize
				binary.BigEndian.PutUint16(rawbuf[4:], uint16(udpsize))
				copy(rawbuf[8:], packet.Raw[24:40])
				copy(rawbuf[24:], packet.Raw[8:24])
				copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
			} else {
				copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
				packetsize = 20 + udpsize
				binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
				copy(rawbuf[12:], packet.Raw[16:20])
				copy(rawbuf[16:], packet.Raw[12:16])
				copy(rawbuf[20:], packet.Raw[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[22:], packet.Raw[ipheadlen:ipheadlen+2])
				ipheadlen = 20
			}

			binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
			copy(rawbuf[ipheadlen+8:], response)

			packet.PacketLen = uint(packetsize)
			packet.Raw = rawbuf[:packetsize]
			packet.Addr.Data |= 0x1
			packet.CalcNewChecksum(winDivert)
		}

		_, err = winDivert.Send(packet)
		if err != nil {
			logPrintln(1, err)
			return
		}
	}
}
