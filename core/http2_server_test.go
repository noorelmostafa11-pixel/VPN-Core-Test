package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestHTTP2ServerConcurrentStreamsHalfCloseAndParentReuse(t *testing.T) {
	cfg, server := carrierServerFixture(t, "vless", "http2", false, 0)
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
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			header, _ := newProtocol(cfg, false).open(address)
			body := bytes.Repeat([]byte{byte(i + 1)}, 200001)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, "PUT", "http://localhost/native%20path?ignored=value", bytes.NewReader(join(header, body)))
			r.Header.Set("X-Forwarded-For", "192.0.2.1")
			response, err := parent.RoundTrip(r)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || !bytes.Equal(got, join([]byte{0, 0}, body)) || response.Header.Get("Content-Encoding") != "identity" {
				t.Error("independent raw HTTP2 half-close payload", len(got), err)
			}
		}(i)
	}
	wg.Wait()
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("HTTP2 parent retained admission")
	}
}

func TestHTTP2ServerCustomMethodAndMalformedIsolation(t *testing.T) {
	server := testServerEngine(t)
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "http2", Path: "/custom", Host: "localhost", Method: "PATCH"}})
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
	for _, test := range []struct{ method, host, path, encoding string }{{"PUT", "localhost", "/custom", ""}, {"PATCH", "wrong", "/custom", ""}, {"PATCH", "localhost", "/custom/extra", ""}, {"PATCH", "localhost", "/custom", "gzip"}} {
		r, _ := http.NewRequest("POST", "http://"+test.host+test.path, bytes.NewReader(nil))
		r.Method = test.method
		if test.encoding != "" {
			r.Header.Set("Content-Encoding", test.encoding)
		}
		response, err := parent.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("invalid HTTP2 request admitted", response.StatusCode)
		}
	}
	cfg := defaults()
	cfg.Protocol = "vless"
	cfg.UUID, _ = uuidBytes(visionServerTestUUID)
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(cfg, false).open(address)
	body := bytes.Repeat([]byte("custom method actual payload"), 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "PATCH", "http://localhost/custom", bytes.NewReader(join(header, body)))
	response, err := parent.RoundTrip(r)
	if err != nil {
		t.Fatal("parent lost after rejected requests", err)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(got, join([]byte{0, 0}, body)) {
		t.Fatal("custom method payload", err)
	}
	for _, spec := range []ServerTransportConfig{{Type: "http2", EarlyData: 1}, {Type: "http2", Service: "ignored"}, {Type: "http2", Method: "GET"}, {Type: "http2", Method: "bad\r\n"}, {Type: "grpc", Method: "PUT"}, {Type: "websocket", Method: "POST"}} {
		if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &spec}); err == nil {
			t.Fatal("invalid HTTP carrier options accepted", spec)
		}
	}
}

func TestHTTP2ServerCancellationBudgetAndOwnerClose(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.MaxConnections = 2
	var protects atomic.Int32
	entered := make(chan struct{}, 1)
	server, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(ctx context.Context, _ int64) error {
		protects.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "http2"}})
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
	client := defaults()
	client.Protocol = "vless"
	client.UUID, _ = uuidBytes(visionServerTestUUID)
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(client, false).open(address)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "PUT", "http://localhost/", bytes.NewReader(header))
	response, err := parent.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("protected dial not entered")
	}
	// The admitted parent + stream exhaust the same budget; a sibling cannot dial.
	request, _ = http.NewRequest("PUT", "http://localhost/", bytes.NewReader(header))
	sibling, err := parent.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	sibling.Body.Close()
	if sibling.StatusCode != 503 || protects.Load() != 1 {
		t.Fatal("HTTP2 budget bypass", sibling.StatusCode, protects.Load())
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for server.Stats().Active > 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.Stats().Active != 1 {
		t.Fatal("stream cancellation retained protected dial")
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, _ = http.NewRequest("PUT", "http://localhost/", reader)
	pending, err := parent.RoundTrip(request)
	if err != nil {
		t.Fatal("parent lost after stream cancellation", err)
	}
	defer pending.Body.Close()
	done := make(chan struct{})
	go func() { server.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("incomplete HTTP2 stream retained owner")
	}
	if server.Stats().Active != 0 || protects.Load() != 1 {
		t.Fatal("HTTP2 owner cleanup/fallback", server.Stats(), protects.Load())
	}
}
