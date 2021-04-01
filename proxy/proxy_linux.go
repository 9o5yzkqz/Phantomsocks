package proxy

import (
	"net"
	"syscall"
)

func SetProxy(dev, address string, state bool) error {
	return nil
}

func SetKeepAlive(conn net.Conn) error {
	f, err := conn.(*net.TCPConn).File()
	defer f.Close()
	if err == nil {
		fd := int(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5)
		if err != nil {
			return err
		}
	}
	return nil
}
