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
	engine, e := core.NewEngine(ctx, c, core.Hooks{})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer engine.Close()
	var tunnel *core.Tunnel
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
		if *tunOnly && c.ReadyFile != "" {
			if e = core.PublishReady(c.ReadyFile, map[string]any{"pid": os.Getpid(), "port": 0, "tun_name": name, "version": core.Version}); e != nil {
				fmt.Fprintln(os.Stderr, e)
				return 1
			}
		}
	}
	if *tunOnly && tunnel == nil {
		fmt.Fprintln(os.Stderr, "--tun-only requires --tun or --tun-fd")
		return 2
	}
	if !*tunOnly {
		a, e := engine.StartSOCKS()
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		fmt.Fprintln(os.Stderr, "Listening on", a)
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
