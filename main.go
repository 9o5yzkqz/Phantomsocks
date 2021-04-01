package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"

	ptcp "github.com/macronut/phantomsocks/phantomtcp"
	proxy "github.com/macronut/phantomsocks/proxy"
)

var allowlist map[string]bool = nil

func ListenAndServe(listenAddr string, serve func(net.Conn)) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}

	if allowlist != nil {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			remoteAddr := client.RemoteAddr()
			remoteTCPAddr, _ := net.ResolveTCPAddr(remoteAddr.Network(), remoteAddr.String())
			_, ok := allowlist[remoteTCPAddr.IP.String()]
			if ok {
				go serve(client)
			} else {
				client.Close()
			}
		}
	} else {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			go serve(client)
		}
	}
}

func PACServer(listenAddr string, proxyAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	pac := ptcp.GetPAC(proxyAddr)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n%s", len(pac), pac))
	fmt.Println("PACServer:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go func() {
			defer client.Close()
			var b [1024]byte
			_, err := client.Read(b[:])
			if err != nil {
				return
			}
			_, err = client.Write(response)
			if err != nil {
				return
			}
		}()
	}
}

func DNSServer(listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Println("DNS:", listenAddr)
	data := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			continue
		}

		request := make([]byte, n)
		copy(request, data[:n])
		go func(clientAddr *net.UDPAddr, request []byte) {
			response := ptcp.NSRequest(request, true)
			conn.WriteToUDP(response, clientAddr)
		}(clientAddr, request)
	}
}

func main() {
	//log.SetFlags(log.LstdFlags | log.Lshortfile)

	var flags struct {
		ConfigFiles     string `json:"config,omitempty"`
		HostsFile       string `json:"hosts,omitempty"`
		SocksListenAddr string `json:"socks,omitempty"`
		HttpListenAddr  string `json:"http,omitempty"`
		PacListenAddr   string `json:"pac,omitempty"`
		SniListenAddr   string `json:"sni,omitempty"`
		RedirectAddr    string `json:"redir,omitempty"`
		SSListenAddr    string `json:"ss,omitempty"`
		SystemProxy     string `json:"proxy,omitempty"`
		DnsListenAddr   string `json:"dns,omitempty"`
		Device          string `json:"device,omitempty"`
		Clients         string `json:"clients,omitempty"`
		LogLevel        int    `json:"log,omitempty"`
		MaxProcs        int    `json:"maxprocs,omitempty"`
	}

	if len(os.Args) > 1 {
		flag.StringVar(&flags.ConfigFiles, "c", "default.conf", "Config")
		flag.StringVar(&flags.HostsFile, "hosts", "", "Hosts")
		flag.StringVar(&flags.SocksListenAddr, "socks", "", "Socks5")
		flag.StringVar(&flags.HttpListenAddr, "http", "", "HTTP")
		flag.StringVar(&flags.PacListenAddr, "pac", "", "PACServer")
		flag.StringVar(&flags.SniListenAddr, "sni", "", "SNIProxy")
		flag.StringVar(&flags.SSListenAddr, "ss", "", "Shadowsocks")
		flag.StringVar(&flags.RedirectAddr, "redir", "", "Redirect")
		flag.StringVar(&flags.SystemProxy, "proxy", "", "Proxy")
		flag.StringVar(&flags.DnsListenAddr, "dns", "", "DNS")
		flag.StringVar(&flags.Device, "device", "", "Device")
		flag.StringVar(&flags.Clients, "clients", "", "Clients")
		flag.IntVar(&flags.LogLevel, "log", 0, "LogLevel")
		flag.IntVar(&flags.MaxProcs, "maxprocs", 0, "LogLevel")
		flag.Parse()
	} else {
		conf, err := os.Open("phantomsocks.json")
		if err != nil {
			fmt.Println(err)
			return
		}

		bytes, err := ioutil.ReadAll(conf)
		if err != nil {
			log.Panic(err)
		}
		conf.Close()

		err = json.Unmarshal(bytes, &flags)
		if err != nil {
			log.Panic(err)
		}

		if flags.ConfigFiles == "" {
			flags.ConfigFiles = "default.conf"
		}
	}

	if flags.MaxProcs > 0 {
		runtime.GOMAXPROCS(flags.MaxProcs)
	}

	devices := strings.Split(flags.Device, ",")
	if !ptcp.ConnectionMonitor(devices) {
		return
	}

	ptcp.LogLevel = flags.LogLevel
	ptcp.Init()

	for _, filename := range strings.Split(flags.ConfigFiles, ",") {
		err := ptcp.LoadConfig(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}
	if flags.HostsFile != "" {
		err := ptcp.LoadHosts(flags.HostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if flags.Clients != "" {
		allowlist = make(map[string]bool)
		list := strings.Split(flags.Clients, ",")
		for _, c := range list {
			allowlist[c] = true
		}
	}

	if flags.SocksListenAddr != "" {
		fmt.Println("Socks:", flags.SocksListenAddr)
		go ListenAndServe(flags.SocksListenAddr, ptcp.SocksProxy)
		if flags.PacListenAddr != "" {
			go PACServer(flags.PacListenAddr, flags.SocksListenAddr)
		}
	}

	if flags.HttpListenAddr != "" {
		fmt.Println("HTTP:", flags.HttpListenAddr)
		go ListenAndServe(flags.HttpListenAddr, ptcp.HTTPProxy)
	}

	if flags.SniListenAddr != "" {
		fmt.Println("SNI:", flags.SniListenAddr)
		go ListenAndServe(flags.SniListenAddr, ptcp.SNIProxy)
	}

	if flags.SSListenAddr != "" {
		addr := flags.SSListenAddr
		if strings.HasPrefix(addr, "ss://") {
			accesskey := base64.StdEncoding.EncodeToString([]byte(addr[5:]))
			fmt.Println("ss://" + accesskey)
			ptcp.ShadowsocksServer(flags.SSListenAddr)
		}
	}

	if flags.RedirectAddr != "" {
		fmt.Println("Redirect:", flags.RedirectAddr)
		go ListenAndServe(flags.RedirectAddr, ptcp.RedirectProxy)
	}

	if flags.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, flags.SystemProxy, true)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if flags.DnsListenAddr != "" {
		go DNSServer(flags.DnsListenAddr)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	s := <-c
	fmt.Println(s)

	if flags.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, flags.SystemProxy, false)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}
