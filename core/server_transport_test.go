package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func carrierServerFixture(t *testing.T, protocol, transport string, secure bool, early int, modes ...string) (Config, *Engine) {
	return carrierServerFixtureWithXHTTPExtra(t, protocol, transport, secure, early, nil, modes...)
}

func carrierServerFixtureWithXHTTPExtra(t *testing.T, protocol, transport string, secure bool, early int, extra *XHTTPServerOptions, modes ...string) (Config, *Engine) {
	t.Helper()
	server := testServerEngine(t)
	spec := ServerConfig{Protocol: protocol, Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Password: "carrier secret", Cipher: "aes-256-gcm",
		Transport: &ServerTransportConfig{Type: transport, Path: "/native%20path", Host: "localhost", EarlyData: early, Extra: extra}}
	if len(modes) > 0 {
		spec.Transport.Mode = modes[0]
	}
	if len(modes) > 1 {
		spec.Transport.HTTPVersion = modes[1]
	}
	if len(modes) > 2 {
		spec.Transport.Method = modes[2]
	}
	if protocol == "ss" {
		spec.Options = map[string]string{"udp": "false"}
	} else {
		spec.Cipher = ""
		if protocol != "trojan" {
			spec.Password = ""
		}
	}
	if secure || protocol == "trojan" {
		spec.CertFile, spec.KeyFile = testServerCertificate(t)
	}
	addr, err := server.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaults()
	cfg.Protocol, cfg.Transport, cfg.Security = protocol, transport, "none"
	if transport == "http2" {
		cfg.Transport = "http"
	}
	if transport == "xhttp" {
		cfg.Mode = "stream-one"
		if extra != nil {
			cfg.Extra, err = json.Marshal(extra)
			if err != nil {
				t.Fatal(err)
			}
		}
		if len(modes) > 0 {
			cfg.Mode = modes[0]
		}
	}
	cfg.Server, cfg.Port, _ = splitProtocolTarget(addr.String())
	cfg.UUID, _ = uuidBytes(visionServerTestUUID)
	cfg.Password, cfg.Cipher = spec.Password, spec.Cipher
	cfg.Path, cfg.Host = "/native path", "localhost"
	cfg.EarlyData = early
	cfg.EarlyHeader = "Sec-WebSocket-Protocol"
	if protocol == "vmess" {
		cfg.Cipher = "aes-128-gcm"
	}
	if protocol == "trojan" {
		hash := sha256.Sum224([]byte(cfg.Password))
		cfg.PasswordHash = hex.EncodeToString(hash[:])
	}
	if spec.CertFile != "" {
		cfg.Security = "tls"
		cfg.CAFile = spec.CertFile
		cfg.ServerName = cfg.Server
		cfg.Fingerprint = "native"
	}
	if spec.Transport.HTTPVersion == "h3" {
		cfg.ALPN = []string{"h3"}
	} else if spec.Transport.HTTPVersion == "h2" && spec.CertFile != "" {
		cfg.ALPN = []string{"h2"}
	}
	if err = cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg, server
}

func TestServerCarriersProtocolsTCPUDPAndOwnerClose(t *testing.T) {
	for _, transport := range []string{"websocket", "httpupgrade", "http2", "xhttp"} {
		for _, protocol := range []string{"vless", "vmess", "trojan", "ss"} {
			for _, secure := range []bool{false, true} {
				t.Run(transport+"/"+protocol+"/TLS="+boolText(secure), func(t *testing.T) {
					early := 0
					if transport == "websocket" {
						early = 64
					}
					cfg, server := carrierServerFixture(t, protocol, transport, secure, early)
					client, err := NewEngine(context.Background(), cfg, Hooks{})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					target := echoPeer(t)
					for cycle := 0; cycle < 8; cycle++ {
						c, err := client.DialContext(client.ctx, "tcp", target)
						if err != nil {
							t.Fatal(err)
						}
						payloadCheck(t, c)
					}
					if protocol != "ss" {
						h, port, _ := splitProtocolTarget(udpEchoPeer(t))
						for cycle := 0; cycle < 4; cycle++ {
							p, err := client.dialPacket(client.ctx, h, port)
							if err != nil {
								t.Fatal(err)
							}
							checkHysteriaUDP(t, p)
							p.Close()
						}
					}
					server.Close()
					client.Close()
					if server.Stats().Active != 0 || client.Stats().Active != 0 {
						t.Fatal("carrier owner retained admission")
					}
				})
			}
		}
	}
}

func upgradeWire(path, extra string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16)) + "\r\nSec-WebSocket-Version: 13\r\n" + extra + "\r\n"
}

func TestServerUpgradePreservesCoalescedAndEarlyData(t *testing.T) {
	for _, transport := range []string{"websocket", "httpupgrade"} {
		a, b := net.Pipe()
		deadline := time.Now().Add(3 * time.Second)
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
		payload := []byte("prefetched protocol data retained")
		extra := ""
		tail := payload
		config := &ServerTransportConfig{Type: transport, Path: "/native", Host: "localhost"}
		if transport == "websocket" {
			config.EarlyData = 16
			config.EarlyHeader = "Sec-WebSocket-Protocol"
			extra = "Sec-WebSocket-Protocol: " + base64.RawURLEncoding.EncodeToString(payload[:7]) + "\r\n"
			tail = wsFrame(2, payload[7:])
		}
		done := make(chan error, 1)
		go func() {
			defer b.Close()
			c, err := acceptServerUpgrade(b, config)
			if err == nil {
				got := make([]byte, len(payload))
				_, err = io.ReadFull(c, got)
				if err == nil && !bytes.Equal(payload, got) {
					err = io.ErrUnexpectedEOF
				}
			}
			done <- err
		}()
		written := make(chan error, 1)
		go func() { written <- writeAll(a, join([]byte(upgradeWire("/native", extra)), tail)) }()
		reader := bufio.NewReader(a)
		resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil || resp.StatusCode != 101 {
			t.Fatal("upgrade response", err)
		}
		if err = <-written; err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal("coalesced/early bytes", err)
		}
		a.Close()
		b.Close()
	}
}

func TestServerUpgradeRejectsUnmatchedMalformedAndOversizedHeaders(t *testing.T) {
	for _, wire := range []string{upgradeWire("/wrong", ""), upgradeWire("/native", "Content-Length: 1\r\n"), upgradeWire("/native", "Sec-WebSocket-Version: 13\r\n"), upgradeWire("/native", "Sec-WebSocket-Protocol: !!!!\r\n"), upgradeWire("/native", "Sec-WebSocket-Extensions: permessage-deflate\r\n"), upgradeWire("/native", "X-Large: "+strings.Repeat("x", 8193)+"\r\n")} {
		a, b := net.Pipe()
		deadline := time.Now().Add(time.Second)
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
		done := make(chan error, 1)
		go func() {
			defer b.Close()
			_, err := acceptServerUpgrade(b, &ServerTransportConfig{Type: "websocket", Path: "/native", Host: "localhost", EarlyData: 16, EarlyHeader: "Sec-WebSocket-Protocol"})
			done <- err
		}()
		written := make(chan struct{})
		go func() { defer close(written); writeAll(a, []byte(wire)) }()
		resp, err := http.ReadResponse(bufio.NewReader(a), &http.Request{Method: "GET"})
		if err != nil || resp.StatusCode == 101 {
			t.Fatal("malformed upgrade admitted", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err = <-done; err == nil {
			t.Fatal("bad header accepted")
		}
		a.Close()
		b.Close()
		<-written
	}
	for _, config := range []ServerTransportConfig{{Type: "http3"}, {Type: "raw", Path: "/ignored"}, {Type: "websocket", Path: "relative"}, {Type: "websocket", Host: "injected\r\n"}, {Type: "websocket", EarlyData: 4097}, {Type: "httpupgrade", EarlyData: 10}, {Type: "websocket", EarlyData: 10, EarlyHeader: "Connection"}} {
		if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &config}); err == nil {
			t.Fatal("bad carrier settings accepted")
		}
	}
}

func TestWebSocketServerMaskFragmentsControlsAndFrameLimits(t *testing.T) {
	payload := []byte("fragmented payload")
	first := wsFrame(2, payload[:4])
	first[0] &= 0x7f
	second := wsFrame(0, payload[4:])
	wire := join(first, wsFrame(9, []byte("ping")), second)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	deadline := time.Now().Add(3 * time.Second)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	server := &wsConn{Conn: b, r: bufio.NewReader(b), server: true}
	written := make(chan error, 1)
	go func() { written <- writeAll(a, wire) }()
	pong := make(chan error, 1)
	go func() {
		got := make([]byte, 6)
		_, err := io.ReadFull(a, got)
		if err == nil && !bytes.Equal(got, []byte{138, 4, 'p', 'i', 'n', 'g'}) {
			err = io.ErrUnexpectedEOF
		}
		pong <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("fragmented masked data", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := <-pong; err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{{130, 1, 7}, {194, 128, 0, 0, 0, 0}, {128, 128, 0, 0, 0, 0}, {130, 254, 0, 1, 0, 0, 0, 0, 7}, {130, 255, 0, 0, 0, 0, 0, 8, 0, 1}} {
		c := &wsConn{Conn: b, r: bufio.NewReader(bytes.NewReader(bad)), server: true}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("bad server frame accepted")
		}
	}
}

func TestServerCarrierEncryptedVisionNativeClientInnerTLSAndMetadata(t *testing.T) {
	cert, key := testServerCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	root := x509.NewCertPool()
	pem, _ := os.ReadFile(cert)
	root.AppendCertsFromPEM(pem)
	for _, carrier := range []string{"websocket", "httpupgrade", "http2", "grpc", "xhttp"} {
		for _, mode := range []string{"native", "random"} {
			t.Run(carrier+"/"+mode, func(t *testing.T) {
				private, public := encryptionTestKeys(t, false, 1)
				server := testServerEngine(t)
				spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, CertFile: cert, KeyFile: key,
					Transport: &ServerTransportConfig{Type: carrier, Path: "/carrier-test", Host: "localhost"},
					Options:   map[string]string{"flow": vlessVisionFlow, "decryption": "mlkem768x25519plus." + mode + ".60-60s.100-75-75." + private[0]}}
				if carrier == "grpc" {
					spec.Transport.Path = ""
					spec.Transport.Service = "carrier-test"
				}
				addr, err := server.StartServer(spec)
				if err != nil {
					t.Fatal(err)
				}
				encryption := "mlkem768x25519plus." + mode + ".0rtt.100-75-75." + public[0]
				cfg, err := ParseURI("vless://" + visionServerTestUUID + "@" + addr.String() + "?security=tls&fp=native&sni=127.0.0.1&flow=" + vlessVisionFlow + "&type=" + carrier + "&path=/carrier-test&host=localhost&encryption=" + url.QueryEscape(encryption))
				if err != nil {
					t.Fatal(err)
				}
				cfg.CAFile = cert
				if carrier == "xhttp" {
					cfg.Mode = "stream-one"
				}
				if carrier == "grpc" {
					cfg.Authority = "localhost"
				}
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					for cycle := 0; cycle < 4; cycle++ {
						c, err := listener.Accept()
						if err != nil {
							return
						}
						c.SetDeadline(time.Now().Add(5 * time.Second))
						io.Copy(c, c)
						c.Close()
					}
				}()
				defer func() { listener.Close(); <-done }()
				for cycle := 0; cycle < 4; cycle++ {
					c, err := client.DialContext(client.ctx, "tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					version, _ := connectionMeta(c)
					if version != "TLS1.3" {
						c.Close()
						t.Fatal("wrapped TLS metadata lost", version)
					}
					inner := tls.Client(c, &tls.Config{RootCAs: root, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
					inner.SetDeadline(time.Now().Add(5 * time.Second))
					body := bytes.Repeat([]byte{byte(cycle + 11)}, 200001)
					if err = writeAll(inner, body); err != nil {
						inner.Close()
						t.Fatal(err)
					}
					got := make([]byte, len(body))
					_, err = io.ReadFull(inner, got)
					inner.Close()
					if err != nil || !bytes.Equal(body, got) {
						t.Fatal("native encrypted carrier payload", err)
					}
				}
				h, port, _ := splitProtocolTarget(udpEchoPeer(t))
				p, err := client.dialPacket(client.ctx, h, port)
				if err != nil {
					t.Fatal(err)
				}
				checkHysteriaUDP(t, p)
				p.Close()
				server.Close()
				client.Close()
				if server.Stats().Active != 0 {
					t.Fatal("encrypted carrier retained budget")
				}
			})
		}
	}
}

func TestServerCarrierPendingHeaderOwnerCloseAndEmptyFrames(t *testing.T) {
	_, server := carrierServerFixture(t, "vless", "websocket", false, 0)
	// Independent listener solely to keep the HTTP header incomplete.
	spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "httpupgrade"}}
	addr, err := server.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	writeAll(c, []byte("GET /"))
	deadline := time.Now().Add(time.Second)
	for server.Stats().Active == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { server.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending HTTP header retained owner")
	}
	if server.Stats().Active != 0 {
		t.Fatal("pending upgrade retained budget")
	}
	empty := bytes.Repeat(wsFrame(2, nil), 65)
	w := &wsConn{Conn: c, r: bufio.NewReader(bytes.NewReader(empty)), server: true}
	if _, err = w.Read(make([]byte, 1)); err == nil || err.Error() != "WEBSOCKET_EMPTY_FRAME_LIMIT" {
		t.Fatal("empty frame loop unbounded", err)
	}
}
