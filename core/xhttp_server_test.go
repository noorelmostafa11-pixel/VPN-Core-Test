package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestXHTTPServerHTTP1HalfCloseReuseAndMalformedRequests(t *testing.T) {
	cfg, server := carrierServerFixture(t, "vless", "xhttp", false, 0)
	transport := &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	base := "http://" + net.JoinHostPort(cfg.Server, itoa(cfg.Port))
	for cycle := 0; cycle < 4; cycle++ {
		header, _ := newProtocol(cfg, false).open(address)
		body := bytes.Repeat([]byte{byte(cycle + 51)}, 200001)
		r, _ := http.NewRequest("POST", base+"/native%20path/?padding=ignored", bytes.NewReader(join(header, body)))
		r.Host = "localhost"
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("native HTTP1 full duplex response", err)
		}
		got, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.ProtoMajor != 1 || !bytes.Equal(got, join([]byte{0, 0}, body)) {
			t.Fatal("HTTP1 half-close/drain", len(got), err)
		}
	}
	for _, test := range []struct{ method, path, host, encoding, session string }{{"GET", "/native%20path/", "localhost", "", ""}, {"POST", "/native%20path/not-stream-one", "localhost", "", ""}, {"POST", "/native%20path/", "wrong", "", ""}, {"POST", "/native%20path/", "localhost", "gzip", ""}, {"POST", "/native%20path/", "localhost", "", "session"}} {
		r, _ := http.NewRequest(test.method, base+test.path, bytes.NewReader(nil))
		r.Host = test.host
		if test.encoding != "" {
			r.Header.Set("Content-Encoding", test.encoding)
		}
		if test.session != "" {
			r.Header.Set("X-Session", test.session)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("invalid XHTTP stream-one request admitted", response.StatusCode)
		}
	}
	transport.CloseIdleConnections()
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("XHTTP parent retained admission")
	}
}

func TestXHTTPServerProtectionCancellationAndIncompleteOwnerLoss(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.MaxConnections = 2
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	server, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(ctx context.Context, _ int64) error {
		calls.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "xhttp", Path: "/test"}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	headCfg := defaults()
	headCfg.Protocol = "vless"
	headCfg.UUID, _ = uuidBytes(visionServerTestUUID)
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(headCfg, false).open(address)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://"+addr.String()+"/test/", bytes.NewReader(header))
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("protected XHTTP dial not entered")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for server.Stats().Active > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.Stats().Active != 0 || calls.Load() != 1 {
		t.Fatal("canceled XHTTP dial retained/bypassed protection", server.Stats(), calls.Load())
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	r, _ = http.NewRequest("POST", "http://"+addr.String()+"/test/", reader)
	pending, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Body.Close()
	done := make(chan struct{})
	go func() { server.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("incomplete native HTTP body retained owner")
	}
	if server.Stats().Active != 0 || calls.Load() != 1 {
		t.Fatal("XHTTP owner resources", server.Stats(), calls.Load())
	}
	for _, spec := range []ServerTransportConfig{{Type: "xhttp", Mode: "unknown"}, {Type: "xhttp", Method: "GET"}, {Type: "xhttp", EarlyData: 1}, {Type: "http2", Mode: "stream-one"}} {
		if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &spec}); err == nil {
			t.Fatal("unsupported XHTTP mode/options silently accepted", spec)
		}
	}
}

func TestXHTTPServerH2cPayloadAndNativeSSUDP(t *testing.T) {
	cfg, server := carrierServerFixture(t, "vless", "xhttp", false, 0)
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
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(cfg, false).open(address)
	body := bytes.Repeat([]byte("independent h2c body"), 16384)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/native%20path/", bytes.NewReader(join(header, body)))
	response, err := parent.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.ProtoMajor != 2 || !bytes.Equal(got, join([]byte{0, 0}, body)) {
		t.Fatal("native cleartext HTTP2 XHTTP body", len(got), err)
	}
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("h2c retained parent/stream")
	}
	// XHTTP TCP hosting must retain separately configured SS native UDP.
	server = testServerEngine(t)
	addr, err := server.StartServer(ServerConfig{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: "aes-256-gcm", Password: "synthetic SS UDP secret", Transport: &ServerTransportConfig{Type: "xhttp"}})
	if err != nil {
		t.Fatal(err)
	}
	clientCfg := defaults()
	clientCfg.Protocol, clientCfg.Cipher, clientCfg.Password = "ss", "aes-256-gcm", "synthetic SS UDP secret"
	clientCfg.Transport = "raw"
	clientCfg.Security = "none"
	clientCfg.Server, clientCfg.Port, _ = splitProtocolTarget(addr.String())
	client, err := NewEngine(context.Background(), clientCfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	host, port, _ = splitProtocolTarget(udpEchoPeer(t))
	packets, err := client.dialPacket(client.ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	checkHysteriaUDP(t, packets)
	packets.Close()
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("native SS UDP retained owner")
	}
}
