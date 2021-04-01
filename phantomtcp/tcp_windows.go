package phantomtcp

import (
	"net"
	"syscall"
	"time"
)

func DialConnInfo(laddr, raddr *net.TCPAddr, conf *Config, payload []byte) (net.Conn, *ConnectionInfo, error) {
	var conn net.Conn
	var err error

	addr := raddr.String()
	timeout := time.Millisecond * 1500

	tfo_id := 0
	if payload != nil {
		tfo_id = int(TFOSynID) % 64
		TFOSynID++
		TFOPayload[tfo_id] = payload
		defer func() {
			TFOPayload[tfo_id] = nil
		}()
	}

	AddConn(addr, conf.Option)

	if (conf.Option & (OPT_MSS | OPT_TFO | OPT_HTFO | OPT_KEEPALIVE)) != 0 {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr,
			Control: func(network, address string, c syscall.RawConn) error {
				err := c.Control(func(fd uintptr) {
					f := syscall.Handle(fd)
					if (conf.Option & OPT_MSS) != 0 {
					}
					if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
						syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_TTL, tfo_id|64)
					}
					if (conf.Option & OPT_KEEPALIVE) != 0 {
						syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
					}
				})
				return err
			}}
		conn, err = d.Dial("tcp", addr)
	} else {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
		conn, err = d.Dial("tcp", addr)
	}

	if err != nil {
		DelConn(raddr.String())
		return nil, nil, err
	}

	laddr = conn.LocalAddr().(*net.TCPAddr)
	ip4 := raddr.IP.To4()
	var connInfo *ConnectionInfo = nil
	if ip4 != nil {
		select {
		case connInfo = <-ConnInfo4[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	} else {
		select {
		case connInfo = <-ConnInfo6[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	}

	DelConn(raddr.String())

	if (payload != nil) || (conf.MAXTTL != 0) {
		if connInfo == nil {
			conn.Close()
			return nil, nil, nil
		}
		f, err := conn.(*net.TCPConn).File()
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		fd := syscall.Handle(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 0)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if conf.MAXTTL != 0 {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(conf.MAXTTL))
		} else {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		}
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		f.Close()
	}

	return conn, nil, nil
}

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	LocalAddr := conn.LocalAddr()
	LocalTCPAddr := LocalAddr.(*net.TCPAddr)

	if ip4 := LocalTCPAddr.IP.To4(); ip4 != nil {
		if ip4[0] == 127 && ip4[1] == 255 {
			ip4[0] = 6
			ip4[1] = 0
			LocalTCPAddr.IP = ip4
			RemoteTCPAddr := conn.RemoteAddr().(*net.TCPAddr).IP.To4()
			LocalTCPAddr.Port = int(RemoteTCPAddr[2])<<8 | int(RemoteTCPAddr[3])
		}
	}

	return LocalTCPAddr, nil
}
