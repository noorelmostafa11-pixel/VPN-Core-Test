package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func grpcServerFixture(t *testing.T, protocol, mode string, secure bool, hooks ...Hooks) (Config, *Engine) {
	t.Helper()
	base, _ := ParseURI("direct://")
	h := Hooks{}
	if len(hooks) > 0 {
		h = hooks[0]
	}
	e, err := NewEngine(context.Background(), base, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	spec := ServerConfig{Protocol: protocol, Listen: "127.0.0.1:0", Transport: &ServerTransportConfig{Type: "grpc", Service: "vpn.service", Host: "localhost"}}
	cfg := defaults()
	cfg.Protocol, cfg.Transport, cfg.Security, cfg.Service, cfg.Authority, cfg.Mode = protocol, "grpc", "none", "vpn.service", "localhost", mode
	switch protocol {
	case "vless", "vmess":
		spec.UUIDs = []string{visionServerTestUUID}
		cfg.UUID, _ = uuidBytes(visionServerTestUUID)
		if protocol == "vmess" {
			cfg.Cipher = "aes-128-gcm"
		}
	case "trojan":
		spec.Password = "gRPC synthetic secret"
		cfg.Password = spec.Password
		hash := sha256.Sum224([]byte(cfg.Password))
		cfg.PasswordHash = hex.EncodeToString(hash[:])
	case "ss":
		spec.Password = "gRPC synthetic secret"
		spec.Cipher = "aes-256-gcm"
		spec.Options = map[string]string{"udp": "false"}
		cfg.Password, cfg.Cipher = spec.Password, spec.Cipher
	}
	if secure || protocol == "trojan" {
		spec.CertFile, spec.KeyFile = testServerCertificate(t)
		cfg.Security = "tls"
		cfg.CAFile = spec.CertFile
		cfg.Fingerprint = "native"
		cfg.ALPN = []string{"h2"}
	}
	addr, err := e.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server, cfg.Port, _ = splitProtocolTarget(addr.String())
	cfg.ServerName = cfg.Server
	if err = cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg, e
}

func TestGRPCServerProtocolsTunMultiTCPUDPAndClose(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan", "ss"} {
		for _, mode := range []string{"gun", "multi"} {
			for _, secure := range []bool{false, true} {
				t.Run(protocol+"/"+mode+"/TLS="+boolText(secure), func(t *testing.T) {
					cfg, server := grpcServerFixture(t, protocol, mode, secure)
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
						h, p, _ := splitProtocolTarget(udpEchoPeer(t))
						for cycle := 0; cycle < 4; cycle++ {
							s, err := client.dialPacket(client.ctx, h, p)
							if err != nil {
								t.Fatal(err)
							}
							checkHysteriaUDP(t, s)
							s.Close()
						}
					}
					server.Close()
					client.Close()
					if server.Stats().Active != 0 || client.Stats().Active != 0 {
						t.Fatal("gRPC owner retained budget")
					}
				})
			}
		}
	}
}

func TestGRPCServerConcurrentStreamsOneParentAndHalfClose(t *testing.T) {
	cfg, server := grpcServerFixture(t, "vless", "gun", false)
	raw, err := net.Dial("tcp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	transport := &http2.Transport{AllowHTTP: true}
	parent, err := transport.NewClientConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	target := echoPeer(t)
	host, port, _ := splitProtocolTarget(target)
	address, _ := Address(host, port)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			request, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/vpn.service/Tun", reader)
			request.Header.Set("Content-Type", "application/grpc")
			request.Header.Set("TE", "trailers")
			written := make(chan error, 1)
			body := bytes.Repeat([]byte{byte(worker + 1)}, 200001)
			go func() {
				p := newProtocol(cfg, false)
				header, err := p.open(address)
				if err == nil {
					wire, _ := (&grpcCodec{}).encode(join(header, body))
					err = writeAll(writer, wire)
				}
				writer.CloseWithError(err)
				written <- err
			}()
			resp, err := parent.RoundTrip(request)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			codec := grpcCodec{}
			var got []byte
			buffer := make([]byte, 32768)
			for {
				n, readErr := resp.Body.Read(buffer)
				data, decodeErr := codec.decode(buffer[:n])
				if decodeErr != nil {
					t.Error(decodeErr)
					return
				}
				got = append(got, data...)
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					t.Error(readErr)
					return
				}
			}
			if err = <-written; err != nil {
				t.Error(err)
			}
			if !bytes.Equal(got, join([]byte{0, 0}, body)) || resp.Trailer.Get("Grpc-Status") != "0" {
				t.Error("reused stream/half-close response or status lost", len(got), resp.Trailer)
			}
		}(worker)
	}
	wg.Wait()
	parent.Close()
	raw.Close()
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("shared HTTP2 owner retained budget")
	}
}

func TestGRPCServerServicePathsAndRejectedSettings(t *testing.T) {
	for _, service := range []string{"/svc/", "/svc/Tun|", "/svc/Tun|Tun", "/svc/Tun|Multi|Third"} {
		if _, _, err := grpcServerPaths(service); err == nil {
			t.Fatal("bad service accepted", service)
		}
	}
	for _, service := range []string{"", "named.service", "/nested/service/Custom|CustomMulti"} {
		single, multi, err := grpcServerPaths(service)
		if err != nil || single == multi || !strings.HasPrefix(single, "/") {
			t.Fatal("service names", service, err)
		}
	}
	for _, config := range []ServerTransportConfig{{Type: "grpc", Path: "/ignored"}, {Type: "grpc", EarlyData: 1}, {Type: "grpc", Service: "bad\r\n"}, {Type: "websocket", Service: "ignored"}} {
		if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &config}); err == nil {
			t.Fatal("ignored carrier options accepted")
		}
	}
}

func TestGRPCServerMalformedRequestStreamIsolationAndOwnerClose(t *testing.T) {
	cfg, server := grpcServerFixture(t, "vless", "gun", false)
	raw, err := net.Dial("tcp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	parent, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, test := range []struct{ method, path, content, encoding string }{{"GET", "/vpn.service/Tun", "application/grpc", ""}, {"POST", "/wrong/Tun", "application/grpc", ""}, {"POST", "/vpn.service/Tun", "application/grpcfoo", ""}, {"POST", "/vpn.service/Tun", "application/grpc", "gzip"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, _ := http.NewRequestWithContext(ctx, test.method, "http://localhost"+test.path, bytes.NewReader(nil))
		r.Header.Set("Content-Type", test.content)
		if test.encoding != "" {
			r.Header.Set("Grpc-Encoding", test.encoding)
		}
		response, err := parent.RoundTrip(r)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		cancel()
		if response.StatusCode != 404 {
			t.Fatal("invalid gRPC request admitted", response.StatusCode)
		}
	}
	// A compressed message must reject this stream without closing its parent.
	request, _ := http.NewRequest("POST", "http://localhost/vpn.service/Tun", bytes.NewReader([]byte{1, 0, 0, 0, 1, 0}))
	request.Header.Set("Content-Type", "application/grpc")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := parent.RoundTrip(request.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	// Leave a second stream incomplete and require joined owner cancellation.
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, _ = http.NewRequest("POST", "http://localhost/vpn.service/Tun", reader)
	request.Header.Set("Content-Type", "application/grpc")
	response, err = parent.RoundTrip(request)
	if err != nil {
		t.Fatal("parent not reusable after malformed stream", err)
	}
	defer response.Body.Close()
	done := make(chan struct{})
	go func() { server.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("incomplete gRPC stream retained owner")
	}
	if server.Stats().Active != 0 {
		t.Fatal("gRPC owner retained admission")
	}
}

func TestGRPCServerProtectedRouteCannotFallBack(t *testing.T) {
	var protects atomic.Int32
	cfg, server := grpcServerFixture(t, "vless", "gun", false, Hooks{Protect: func(context.Context, int64) error { protects.Add(1); return errors.New("denied") }})
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c, err := client.DialContext(client.ctx, "tcp", echoPeer(t))
	if err == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("protected"))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("gRPC bypassed protected route")
	}
	server.Close()
	client.Close()
	if protects.Load() != 1 || server.Stats().Active != 0 {
		t.Fatal("protection/lifetime", protects.Load(), server.Stats())
	}
}

func TestGRPCServerParentAndStreamShareAdmission(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.MaxConnections = 1
	server, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "grpc", Service: "vpn.service"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	parent, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/vpn.service/Tun", bytes.NewReader(nil))
	r.Header.Set("Content-Type", "application/grpc")
	response, err := parent.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 || response.Header.Get("Grpc-Status") != "8" || server.Stats().Active != 1 || server.Stats().Rejected != 1 {
		t.Fatal("gRPC parent bypassed stream budget", response.StatusCode, response.Header, server.Stats())
	}
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("admission failure retained parent")
	}
}

func TestGRPCServerParentSurvivesSetupDeadline(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.ConnectTimeout, cfg.IdleTimeout = 500*time.Millisecond, 3*time.Second
	server, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "grpc", Service: "vpn.service"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	parent, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	client := defaults()
	client.Protocol = "vless"
	client.UUID, _ = uuidBytes(visionServerTestUUID)
	for cycle := 0; cycle < 2; cycle++ {
		if cycle == 1 {
			time.Sleep(750 * time.Millisecond)
		}
		header, _ := newProtocol(client, false).open(address)
		body := bytes.Repeat([]byte{42}, 65537)
		wire, _ := (&grpcCodec{}).encode(join(header, body))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		request, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/vpn.service/Tun", bytes.NewReader(wire))
		request.Header.Set("Content-Type", "application/grpc")
		response, err := parent.RoundTrip(request)
		if err != nil {
			cancel()
			t.Fatal("parent expired after setup", err)
		}
		encoded, err := io.ReadAll(response.Body)
		response.Body.Close()
		cancel()
		plain, decodeErr := (&grpcCodec{}).decode(encoded)
		if err != nil || decodeErr != nil || !bytes.Equal(plain, join([]byte{0, 0}, body)) || response.Trailer.Get("Grpc-Status") != "0" {
			t.Fatal("response after setup deadline", err, decodeErr, response.Trailer)
		}
	}
}
