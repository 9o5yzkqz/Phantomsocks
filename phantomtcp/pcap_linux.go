// +build !mipsle

package phantomtcp

import (
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SendPacket(packet gopacket.Packet) error {
	switch link := packet.LinkLayer().(type) {
	case *layers.Ethernet:
		err := pcapHandle.WritePacketData(packet.Data())
		return err
	default:
		payload := link.LayerPayload()

		var sa syscall.Sockaddr
		var lsa syscall.Sockaddr
		var domain int

		switch ip := packet.NetworkLayer().(type) {
		case *layers.IPv4:
			var addr [4]byte
			copy(addr[:4], ip.DstIP.To4()[:4])
			sa = &syscall.SockaddrInet4{Addr: addr, Port: 0}
			var laddr [4]byte
			copy(laddr[:4], ip.SrcIP.To4()[:4])
			lsa = &syscall.SockaddrInet4{Addr: laddr, Port: 0}
			domain = syscall.AF_INET
			if payload[8] == 32 {
				return nil
			}
			payload[8] = 32
		case *layers.IPv6:
			var addr [16]byte
			copy(addr[:16], ip.DstIP[:16])
			sa = &syscall.SockaddrInet6{Addr: addr, Port: 0}
			var laddr [16]byte
			copy(laddr[:16], ip.SrcIP[:16])
			lsa = &syscall.SockaddrInet6{Addr: laddr, Port: 0}
			domain = syscall.AF_INET6
			if payload[7] == 32 {
				return nil
			}
			payload[7] = 32
		}

		raw_fd, err := syscall.Socket(domain, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
		err = syscall.Bind(raw_fd, lsa)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}

		err = syscall.Sendto(raw_fd, payload, 0, sa)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
		syscall.Close(raw_fd)
	}

	return nil
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, method uint32, ttl uint8, count int) error {
	linkLayer := connInfo.Link
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

	if linkLayer != nil {
		link := linkLayer.(*layers.Ethernet)
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if method&OPT_TTL != 0 {
				ip.TTL = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		case *layers.IPv6:
			if method&OPT_TTL != 0 {
				ip.HopLimit = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		}
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err := pcapHandle.WritePacketData(outgoingPacket)
			if err != nil {
				return err
			}
		}
	} else {
		var sa syscall.Sockaddr
		var lsa syscall.Sockaddr
		var domain int

		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if method&OPT_TTL != 0 {
				ip.TTL = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				ip, tcpLayer, gopacket.Payload(payload),
			)
			var addr [4]byte
			copy(addr[:4], ip.DstIP.To4()[:4])
			sa = &syscall.SockaddrInet4{Addr: addr, Port: 0}
			var laddr [4]byte
			copy(laddr[:4], ip.SrcIP.To4()[:4])
			lsa = &syscall.SockaddrInet4{Addr: laddr, Port: 0}
			domain = syscall.AF_INET
		case *layers.IPv6:
			if method&OPT_TTL != 0 {
				ip.HopLimit = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				ip, tcpLayer, gopacket.Payload(payload),
			)
			var addr [16]byte
			copy(addr[:16], ip.DstIP[:16])
			sa = &syscall.SockaddrInet6{Addr: addr, Port: 0}
			var laddr [16]byte
			copy(laddr[:16], ip.SrcIP[:16])
			lsa = &syscall.SockaddrInet6{Addr: laddr, Port: 0}
			domain = syscall.AF_INET6
		}

		raw_fd, err := syscall.Socket(domain, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
		err = syscall.Bind(raw_fd, lsa)
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err = syscall.Sendto(raw_fd, outgoingPacket, 0, sa)
			if err != nil {
				syscall.Close(raw_fd)
				return err
			}
		}
		syscall.Close(raw_fd)
	}

	return nil
}
