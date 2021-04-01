//+build !darwin
//+build !linux

package proxy

import (
	"net"
	"os/exec"
	"strings"

	ptcp "../phantomtcp"
)

func SetProxy(dev, address string, state bool) error {
	proxyAddr := strings.Split(address, "://")
	if len(proxyAddr) < 2 {
		return nil
	}

	proxyTCPAddr, err := net.ResolveTCPAddr("tcp", proxyAddr[1])
	if err != nil {
		return err
	}

	if state {
		switch proxyAddr[0] {
		case "redirect":
			if state {
				go ptcp.Redirect("6.0.0.1-6.0.255.254", proxyTCPAddr.Port, false)
				go ptcp.RedirectDNS()
			}

			arg := []string{"/flushdns"}
			cmd := exec.Command("ipconfig", arg...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				return err
			}
		default:
			return nil
		}
	}

	return nil
}

func SetKeepAlive(conn net.Conn) error {
	return nil
}
