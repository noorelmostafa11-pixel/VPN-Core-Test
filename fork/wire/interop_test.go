// Package wire_test exercises independently built fork/main executables using
// synthetic loopback traffic. No node catalog or private configuration is read.
package wire_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

var (
	forkBinary = flag.String("fork-binary", "", "Explicit path to the fork CLI")
	mainBinary = flag.String("main-binary", "", "Explicit path to the comparison main CLI")
	mainCommit = flag.String("main-commit", "", "Comparison main source commit")
	outputDir  = flag.String("evidence", "", "Optional output directory outside the source checkout")
	forkSource = flag.String("fork-source", "", "Optional fork checkout for temporary test peers only")
	mainSource = flag.String("main-source", "", "Optional pinned main checkout for temporary test peers only")
)

const password = "synthetic-fork-wire-password"

const greeting = "server-first\n"

type object = map[string]any

type counts struct {
	CompletedPairs int `json:"completed_pairs"`
	TCPEchoes      int `json:"completed_tcp_echoes"`
	UDPEchoes      int `json:"completed_udp_echoes"`
	Greetings      int `json:"completed_server_first_greetings"`
}

func TestMainInteroperability(t *testing.T) {
	if *forkBinary == "" && *mainBinary == "" && *forkSource == "" && *mainSource == "" {
		t.Skip("requires independently built CLIs; see fork/wire/README.md")
	}
	if !validCommit(*mainCommit) {
		t.Fatal("the full lowercase comparison main commit is required")
	}
	binaries := []string{*forkBinary, *mainBinary}
	if *forkSource != "" || *mainSource != "" {
		if *forkSource == "" || *mainSource == "" || *forkBinary != "" || *mainBinary != "" {
			t.Fatal("supply either both source checkouts or both binaries, never a partial or mixed pair")
		}
		binaries = sourcePeers(t, *forkSource, *mainSource, *mainCommit)
	}
	if binaries[0] == "" || binaries[1] == "" {
		t.Fatal("both binary paths are required")
	}
	paths := make([]string, 2)
	fingerprints := make([]object, 2)
	for i, name := range binaries {
		path, err := filepath.Abs(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		paths[i] = path
		fingerprints[i] = object{"name": filepath.Base(path), "sha256": hex.EncodeToString(hash.Sum(nil))}
	}
	folder := *outputDir
	if folder == "" {
		folder = t.TempDir()
	}
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	methods := []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"}
	for _, mode := range []string{"cfb", "ctr", "ofb"} {
		for _, bits := range []int{128, 192, 256} {
			methods = append(methods, fmt.Sprintf("aes-%d-%s", bits, mode))
		}
	}
	methods = append(methods, "bf-cfb", "cast5-cfb", "des-cfb", "rc4", "rc4-md5", "salsa20", "chacha20", "chacha20-ietf", "table", "none", "plain")
	methods = append(methods, "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "chacha20-poly1305")
	var completed counts
	defer func() {
		report := object{
			"main_commit": *mainCommit, "binaries": fingerprints,
			"methods": methods, "roles": []string{"client", "server"},
			"expected_pairs": 2 * len(methods), "expected_tcp_echoes": 4 * len(methods), "expected_udp_echoes": 18 * len(methods),
			"expected_server_first_greetings": 4 * len(methods),
			"completed":                       completed, "passed": !t.Failed(),
			"tcp_bytes_each": 200001, "udp_sizes": []int{32, 1400, 3800},
			"platform":         runtime.GOOS + "/" + runtime.GOARCH,
			"scope":            "Synthetic loopback; not Internet, application ABI or all-platform acceptance",
			"plaintext_config": "Fork uses an empty password; pinned main requires an unused synthetic placeholder for none/plain. Neither endpoint encrypts or authenticates these methods.",
		}
		writeJSON(t, filepath.Join(folder, "summary.json"), report)
	}()
	for _, server := range []bool{false, true} {
		role := "fork-client-"
		if server {
			role = "fork-server-"
		}
		for _, method := range methods {
			t.Run(role+method, func(t *testing.T) {
				exchange(t, paths, server, method, filepath.Join(folder, role+method), &completed)
			})
		}
	}
	want := counts{CompletedPairs: 2 * len(methods), TCPEchoes: 4 * len(methods), UDPEchoes: 18 * len(methods), Greetings: 4 * len(methods)}
	if completed != want {
		t.Errorf("incomplete wire coverage: completed %+v, expected %+v", completed, want)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Reserve UDP first, then TCP on the same OS-selected loopback port. Only
// fixture allocation is retried; a started protocol exchange is never retried.
func reserve(t *testing.T) (int, func()) {
	t.Helper()
	var last error
	for range 8 {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			last = err
			continue
		}
		tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
		if err != nil {
			last = err
			udp.Close()
			continue
		}
		release := sync.OnceFunc(func() { tcp.Close(); udp.Close() })
		t.Cleanup(release)
		return tcp.Addr().(*net.TCPAddr).Port, release
	}
	t.Fatal("unable to reserve fixture port:", last)
	return 0, nil
}

func echoes(t *testing.T) (net.Addr, net.Addr) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var workers, handlers sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	workers.Go(func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[c] = true
			mu.Unlock()
			handlers.Go(func() {
				defer c.Close()
				defer func() { mu.Lock(); delete(connections, c); mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				if _, err := io.WriteString(c, greeting); err != nil {
					return
				}
				_, _ = io.Copy(c, c) // Client deadlines and byte equality are authoritative.
			})
		}
	})
	workers.Go(func() {
		packet := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(packet)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(packet[:n], peer)
		}
	})
	t.Cleanup(func() {
		tcp.Close()
		udp.Close()
		workers.Wait()
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		handlers.Wait()
	})
	return tcp.Addr(), udp.LocalAddr()
}

func start(t *testing.T, binary string, args []string, logPath string, release func()) <-chan struct{} {
	t.Helper()
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = log, log
	release()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("fixture process did not exit")
		}
	})
	return done
}

func exact(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatal("short response:", err)
	}
	return data
}

func ipv4Address(t *testing.T, address string) []byte {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil || addr.IP.To4() == nil {
		t.Fatal("invalid IPv4 fixture target:", address, err)
	}
	wire := append([]byte{1}, addr.IP.To4()...)
	return binary.BigEndian.AppendUint16(wire, uint16(addr.Port))
}

func socks(t *testing.T, port int, command byte, target string) (net.Conn, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exact(t, c, 2), []byte{5, 0}) {
		t.Fatal("SOCKS authentication rejected")
	}
	if _, err := c.Write(append([]byte{5, command, 0}, ipv4Address(t, target)...)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exact(t, c, 3), []byte{5, 0, 0}) {
		t.Fatal("SOCKS request rejected")
	}
	var host string
	switch exact(t, c, 1)[0] {
	case 1:
		host = net.IP(exact(t, c, 4)).String()
	case 4:
		host = net.IP(exact(t, c, 16)).String()
	case 3:
		host = string(exact(t, c, int(exact(t, c, 1)[0])))
	default:
		t.Fatal("invalid SOCKS response address")
	}
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return c, net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(exact(t, c, 2))))
}

func exchange(t *testing.T, binaries []string, forkServer bool, method, folder string, completed *counts) {
	t.Helper()
	secret := password
	if method == "none" || method == "plain" {
		secret = ""
	}
	// Pinned main rejects empty passwords even for plaintext. Use its required
	// unused placeholder only on that peer; the fork's empty-password case stays.
	referenceSecret := password
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	tcpTarget, udpTarget := echoes(t)
	serverPort, releaseServer := reserve(t)
	socksPort, releaseSocks := reserve(t)
	config := object{"log": object{"loglevel": "debug"}}
	var mainConfig object
	forkRelease, mainRelease := releaseSocks, releaseServer
	mainArgs := []string{"--no-socks"}
	if forkServer {
		config["inbounds"] = []object{{"listen": "127.0.0.1", "port": serverPort, "protocol": "shadowsocks", "settings": object{"method": method, "password": secret, "network": "tcp,udp"}}}
		// Upstream blocks private destinations for proxy inbounds by default.
		// Allow only this fixture's loopback echo ports, never change production defaults.
		config["outbounds"] = []object{{"protocol": "freedom", "settings": object{"finalRules": []object{{"action": "allow", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprintf("%d,%d", tcpTarget.(*net.TCPAddr).Port, udpTarget.(*net.UDPAddr).Port)}}}}}
		mainConfig = object{"listen_port": socksPort, "outbounds": []object{{"tag": "peer", "uri": fmt.Sprintf("ss://%s:%s@127.0.0.1:%d", method, referenceSecret, serverPort)}}, "final": "peer"}
		forkRelease, mainRelease = releaseServer, releaseSocks
		mainArgs = nil
	} else {
		config["inbounds"] = []object{{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": object{"udp": true}}}
		config["outbounds"] = []object{{"protocol": "shadowsocks", "settings": object{"servers": []object{{"address": "127.0.0.1", "port": serverPort, "method": method, "password": secret}}}}}
		mainConfig = object{"outbounds": []object{{"tag": "direct", "uri": "direct://"}}, "final": "direct", "inbounds": []object{{"protocol": "ss", "listen": fmt.Sprintf("127.0.0.1:%d", serverPort), "cipher": method, "password": referenceSecret}}}
	}
	temp := t.TempDir()
	forkFile, mainFile := filepath.Join(temp, "fork.json"), filepath.Join(temp, "main.json")
	writeJSON(t, forkFile, config)
	writeJSON(t, mainFile, mainConfig)
	forkDone := start(t, binaries[0], []string{"run", "-config", forkFile}, filepath.Join(folder, "fork.log"), forkRelease)
	mainDone := start(t, binaries[1], append([]string{"--config", mainFile}, mainArgs...), filepath.Join(folder, "main.log"), mainRelease)
	deadline := time.Now().Add(8 * time.Second)
	for _, port := range []int{serverPort, socksPort} {
		for {
			select {
			case <-forkDone:
				t.Fatal("fork stopped before readiness; inspect fork.log")
			case <-mainDone:
				t.Fatal("main stopped before readiness; inspect main.log")
			default:
			}
			c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("fixture listener readiness:", err)
			}
			time.Sleep(30 * time.Millisecond)
		}
	}
	for cycle := range 2 {
		c, _ := socks(t, socksPort, 1, tcpTarget.String())
		if string(exact(t, c, len(greeting))) != greeting {
			t.Fatal("server-first greeting changed")
		}
		completed.Greetings++
		body := bytes.Repeat([]byte{byte(91 + cycle)}, 200001)
		if _, err := io.Copy(c, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(exact(t, c, len(body)), body) {
			t.Fatal("TCP payload mismatch")
		}
		c.Close()
		completed.TCPEchoes++
	}
	control, relay := socks(t, socksPort, 3, "0.0.0.0:0")
	defer control.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	peer, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte{0, 0, 0}, ipv4Address(t, udpTarget.String())...)
	response := make([]byte, 65535)
	for _, size := range []int{32, 1400, 3800} {
		for cycle := range 3 {
			body := bytes.Repeat([]byte{byte(cycle + 1)}, size)
			packet := append(append([]byte(nil), header...), body...)
			_ = udp.SetDeadline(time.Now().Add(8 * time.Second))
			if _, err := udp.WriteTo(packet, peer); err != nil {
				t.Fatal(err)
			}
			n, from, err := udp.ReadFrom(response)
			if err != nil {
				t.Fatal(err)
			}
			if from.String() != peer.String() || !bytes.Equal(response[:n], packet) {
				t.Fatal("UDP peer, address or payload mismatch")
			}
			completed.UDPEchoes++
		}
	}
	completed.CompletedPairs++
}
