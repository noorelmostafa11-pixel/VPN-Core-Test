package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() { os.Exit(run()) }
func run() int {
	config := flag.String("config", "", "node.ini")
	check := flag.Bool("check-config", false, "validate configuration")
	inspect := flag.Bool("inspect-config", false, "inspect configuration")
	list := flag.String("inspect-list", "", "inspect original URI list")
	version := flag.Bool("version", false, "version")
	self := flag.Bool("self-test", false, "cryptographic self-test")
	components := flag.Bool("check-components", false, "check components")
	tunName := flag.String("tun", "", "create native TUN device")
	tunFD := flag.Int("tun-fd", -1, "duplicate an established TUN descriptor")
	tunMTU := flag.Int("tun-mtu", 1500, "native TUN MTU")
	tunOnly := flag.Bool("tun-only", false, "disable the SOCKS listener")
	noSOCKS := flag.Bool("no-socks", false, "disable SOCKS for server-only or HTTP/mixed configurations")
	dnsListen := flag.String("dns-listen", "", "local UDP/TCP DNS over HTTPS through the node, e.g. 127.0.0.1:53")
	bindInterface := flag.String("bind-interface", "", "Windows physical uplink for upstream sockets")
	httpListen := flag.String("http-listen", "", "optional loopback HTTP proxy")
	mixedListen := flag.String("mixed-listen", "", "optional loopback HTTP/SOCKS proxy")
	apiListen := flag.String("api-listen", "", "optional loopback management API")
	apiTokenFile := flag.String("api-token-file", "", "management bearer token file (32-256 characters)")
	flag.Parse()
	if *version {
		fmt.Println("vpn-core", core.Version, "Go; project-owned protocols; SOCKS5 TCP + UDP; native TUN")
		return 0
	}
	if *self || *components {
		if e := core.SelfTest(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		fmt.Println("PASS: Go components and cryptographic vectors")
		return 0
	}
	encoder := json.NewEncoder(os.Stdout)
	if *list != "" {
		f, e := os.Open(*list)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), 65537)
		line := 0
		for scan.Scan() {
			line++
			uri := strings.TrimSpace(scan.Text())
			if uri == "" || strings.HasPrefix(uri, "#") {
				continue
			}
			hash := sha256.Sum256([]byte(uri))
			c, e := core.ParseURI(uri)
			var row map[string]any
			if e == nil {
				row = c.Inspect()
				row["parsed"] = row["config_valid"]
			} else {
				row = map[string]any{"parsed": false, "uri_parsed": false, "config_valid": false, "connectable_by_this_build": false, "reason_code": "URI_PARSE_INVALID"}
			}
			row["line"] = line
			row["node_id"] = hex.EncodeToString(hash[:])[:20]
			encoder.Encode(row)
		}
		if e := scan.Err(); e != nil {
			return 1
		}
		return 0
	}
	if *config == "" {
		flag.Usage()
		return 2
	}
	c, e := core.ReadConfig(*config)
	if e == nil {
		e = c.Validate()
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	if *inspect {
		encoder.Encode(c.Inspect())
		return 0
	}
	if *check {
		fmt.Println("PASS: config supported")
		return 0
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtimeReady := c.ReadyFile
	if *tunName != "" || *tunFD >= 0 {
		c.ReadyFile = ""
	}
	hooks := core.Hooks{}
	if *bindInterface != "" {
		hooks.Protect, e = core.BindInterface(*bindInterface)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
	}
	var upstream4, upstream6 []string
	if *tunName != "" || *tunFD >= 0 {
		var ips []net.IPAddr
		hooks, ips, e = core.PinBootstrap(ctx, c, hooks)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				upstream4 = append(upstream4, ip.IP.String())
			} else {
				upstream6 = append(upstream6, ip.IP.String())
			}
		}
	}
	engine, e := core.NewEngine(ctx, c, hooks)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer engine.Close()
	if c.Routing != nil {
		for _, server := range c.Routing.Inbounds {
			address, err := engine.StartServer(server)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Fprintln(os.Stderr, "Server listening on", address)
		}
	}
	for _, listener := range []struct {
		address string
		start   func(string) (net.Addr, error)
	}{{*httpListen, engine.StartHTTP}, {*mixedListen, engine.StartMixed}} {
		if listener.address != "" {
			if _, err := listener.start(listener.address); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
	}
	if *apiListen != "" {
		file, err := os.Open(*apiTokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "API_TOKEN_FILE_FAILED")
			return 1
		}
		b, err := io.ReadAll(io.LimitReader(file, 257))
		file.Close()
		if err != nil || len(b) > 256 {
			fmt.Fprintln(os.Stderr, "API_TOKEN_FILE_FAILED")
			return 1
		}
		if _, err = engine.StartManagementAPI(*apiListen, strings.TrimSpace(string(b))); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	dns6 := false
	if *dnsListen != "" {
		if _, e = engine.StartDNS(*dnsListen); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		if host, port, err := net.SplitHostPort(*dnsListen); err == nil && host == "127.0.0.1" && port != "0" {
			if _, err = engine.StartDNS(net.JoinHostPort("::1", port)); err == nil {
				dns6 = true
			}
		}
	}
	var tunnel *core.Tunnel
	tunnelName := ""
	if *tunName != "" || *tunFD >= 0 {
		var device core.PacketDevice
		var name string
		if *tunFD >= 0 {
			device, e = core.OpenTUNFD(*tunFD, *tunMTU)
			name = "app-fd"
		} else {
			device, name, e = core.OpenTUN(*tunName, *tunMTU)
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		tunnel, e = engine.StartTUN(device, *tunMTU)
		if e != nil {
			device.Close()
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		fmt.Fprintln(os.Stderr, "Native TUN ready:", name)
		tunnelName = name
	}
	if *tunOnly && tunnel == nil {
		fmt.Fprintln(os.Stderr, "--tun-only requires --tun or --tun-fd")
		return 2
	}
	port := 0
	if !*tunOnly && !*noSOCKS {
		a, e := engine.StartSOCKS()
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		fmt.Fprintln(os.Stderr, "Listening on", a)
		port = a.(*net.TCPAddr).Port
	}
	if tunnel != nil && runtimeReady != "" {
		if e = core.PublishReady(runtimeReady, map[string]any{"pid": os.Getpid(), "port": port, "tun_name": tunnelName, "version": core.Version, "upstream_ipv4": upstream4, "upstream_ipv6": upstream6, "upstream_port": c.Port, "dns_ipv6": dns6}); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
	}
	go func() {
		for {
			select {
			case ev := <-engine.Events():
				b, _ := json.Marshal(ev)
				fmt.Fprintln(os.Stderr, string(b))
			case <-ctx.Done():
				return
			}
		}
	}()
	if tunnel == nil {
		<-ctx.Done()
	} else {
		select {
		case <-ctx.Done():
		case <-tunnel.Done():
			if e := tunnel.Err(); e != nil {
				fmt.Fprintln(os.Stderr, e)
				return 1
			}
		}
	}
	engine.Close()
	fmt.Fprintln(os.Stderr, "Stopped")
	return 0
}
