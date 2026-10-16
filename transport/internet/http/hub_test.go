package http

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	gonet "net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	httpheader "github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

func forkListener(t *testing.T, secure bool, config *Config, handler internet.ConnHandler) (*Listener, *internet.MemoryStreamConfig) {
	t.Helper()
	settings := &internet.MemoryStreamConfig{ProtocolName: "http", ProtocolSettings: config}
	if secure {
		certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
		settings.SecurityType = "tls"
		settings.SecuritySettings = &tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)}, ServerName: "localhost", PinnedPeerCertSha256: [][]byte{hash[:]}}
	}
	port := tcp.PickPort()
	listener, err := Listen(context.Background(), net.LocalHostIP, port, settings, handler)
	if err != nil {
		t.Fatal(err)
	}
	l := listener.(*Listener)
	t.Cleanup(func() { l.Close() })
	return l, settings
}

func independentClient(t *testing.T, l *Listener, settings *internet.MemoryStreamConfig) *http2.ClientConn {
	t.Helper()
	raw, err := gonet.DialTimeout("tcp", l.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	if security := tls.ConfigFromStreamSettings(settings); security != nil {
		secure := gotls.Client(raw, security.GetTLSConfig(tls.WithNextProto("h2")))
		if err := secure.Handshake(); err != nil {
			raw.Close()
			t.Fatal(err)
		}
		raw = secure
	}
	client, err := (&http2.Transport{AllowHTTP: true, DisableCompression: true}).NewClientConn(raw)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); raw.Close() })
	return client
}

func TestForkLegacyHTTP2ServerIndependentPeer(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "h2c", true: "TLS"}[secure], func(t *testing.T) {
			payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
			greeting := []byte("server-first\n")
			finished := make(chan error, 1)
			l, settings := forkListener(t, secure, &Config{Host: []string{"tunnel.example:8443"}, Path: "/legacy%20path?key=value", Method: "PATCH"}, func(conn stat.Connection) {
				go func() {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(8 * time.Second))
					if _, err := conn.Write(greeting); err != nil {
						finished <- err
						return
					}
					got, err := io.ReadAll(conn)
					if err == nil && !bytes.Equal(got, payload) {
						err = io.ErrUnexpectedEOF
					}
					if err == nil {
						_, err = conn.Write(got)
					}
					finished <- err
				}()
			})
			client := independentClient(t, l, settings)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			body, upload := io.Pipe()
			defer body.Close()
			defer upload.Close()
			req, _ := http.NewRequestWithContext(ctx, "PATCH", "http://tunnel.example:8443/legacy%20path?key=value", body)
			response, err := client.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 200 || response.ProtoMajor != 2 || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("unexpected server response")
			}
			got := make([]byte, len(greeting))
			if _, err := io.ReadFull(response.Body, got); err != nil || !bytes.Equal(got, greeting) {
				t.Fatal("server-first failed", err)
			}
			for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
				if _, err := upload.Write(piece); err != nil {
					t.Fatal(err)
				}
			}
			upload.Close()
			got, err = io.ReadAll(response.Body)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("independent peer echo mismatch", len(got), err)
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("server worker did not join")
			}
		})
	}
}

func TestForkLegacyHTTP2ServerRejectsMetadata(t *testing.T) {
	var accepted atomic.Int32
	l, settings := forkListener(t, false, &Config{Host: []string{"tunnel.example"}, Path: "/exact", Method: "PATCH"}, func(conn stat.Connection) { accepted.Add(1); conn.Close() })
	client := independentClient(t, l, settings)
	for _, test := range []struct{ host, path, method, encoding string }{
		{"wrong.example", "/exact", "PATCH", ""}, {"tunnel.example", "/exact/suffix", "PATCH", ""}, {"tunnel.example", "/exact", "PUT", ""}, {"tunnel.example", "/exact", "GET", ""}, {"tunnel.example", "/exact?other=1", "PATCH", ""}, {"tunnel.example", "/exact", "PATCH", "gzip"},
	} {
		req, _ := http.NewRequest(test.method, "http://"+test.host+test.path, nil)
		if test.encoding != "" {
			req.Header.Set("Content-Encoding", test.encoding)
		}
		response, err := client.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("invalid metadata reached tunnel", test, response.StatusCode)
		}
	}
	if accepted.Load() != 0 {
		t.Fatal("rejected metadata invoked core handler")
	}
	// A raw HTTP/1.1 request must not be accepted as h2c or passed to the core.
	raw, err := gonet.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	raw.Write([]byte("PATCH /exact HTTP/1.1\r\nHost: tunnel.example\r\n\r\n"))
	io.Copy(io.Discard, raw)
	if accepted.Load() != 0 {
		t.Fatal("HTTP/1.1 reached H2 tunnel handler")
	}
}

func TestForkLegacyHTTP2ServerMultiplexAndClose(t *testing.T) {
	accepted := make(chan *serverConn, 8)
	l, settings := forkListener(t, false, &Config{}, func(conn stat.Connection) { accepted <- conn.(*serverConn) })
	client := independentClient(t, l, settings)
	var workers sync.WaitGroup
	beginRead := make(chan struct{})
	for range 8 {
		workers.Go(func() {
			body, upload := io.Pipe()
			defer upload.Close()
			defer body.Close()
			req, _ := http.NewRequest("PUT", "http://tunnel.example/", body)
			response, err := client.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			<-beginRead
			_, err = io.Copy(io.Discard, response.Body)
			if err == nil {
				t.Error("listener shutdown reported a clean payload EOF")
			}
		})
	}
	streams := make([]*serverConn, 0, 8)
	for range 8 {
		select {
		case stream := <-accepted:
			streams = append(streams, stream)
		case <-time.After(5 * time.Second):
			t.Fatal("stream not admitted")
		}
	}
	closed := make(chan struct{})
	go func() { l.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("listener close did not join active streams")
	}
	close(beginRead)
	workers.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.streams) != 0 || len(l.connections) != 0 {
		t.Fatal("listener retained streams or parents")
	}
}

func TestForkLegacyHTTP2RuntimeValidation(t *testing.T) {
	for _, config := range []*Config{{Method: "GET"}, {IdleTimeout: -1}, {Header: []*httpheader.Header{{Name: "Content-Length", Value: []string{"1"}}}}, {Path: "/%zz"}, {Host: []string{strings.Repeat("x", 513)}}} {
		settings := &internet.MemoryStreamConfig{ProtocolSettings: config}
		if c, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, 1), settings); err == nil {
			c.Close()
			t.Fatal("protobuf bypassed outbound guard")
		}
		if l, err := Listen(context.Background(), net.LocalHostIP, 1, settings, nil); err == nil {
			l.Close()
			t.Fatal("protobuf bypassed inbound guard")
		}
	}
	for _, host := range []string{"example.com", "example.com:8443", "[::1]", "[::1]:8443"} {
		c := &Config{Host: []string{host}}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if !c.validHost(host) || c.validHost("attacker.example") {
			t.Fatal("host validation mismatch", host)
		}
	}
}

func TestForkLegacyHTTP2ServerCloseBlockedWrite(t *testing.T) {
	accepted := make(chan *serverConn, 1)
	l, settings := forkListener(t, false, &Config{}, func(conn stat.Connection) { accepted <- conn.(*serverConn) })
	client := independentClient(t, l, settings)
	body, upload := io.Pipe()
	defer upload.Close()
	defer body.Close()
	req, _ := http.NewRequest("PUT", "http://tunnel.example/", body)
	response, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	stream := <-accepted
	blocked := make(chan error, 1)
	go func() { _, err := stream.Write(make([]byte, 8<<20)); blocked <- err }()
	// Reading the first byte proves the large response Write really started.
	if _, err := io.ReadFull(response.Body, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("flow-control blocked write unexpectedly completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream close did not unblock response write")
	}
	if _, err := stream.Write([]byte("late")); err == nil {
		t.Fatal("write after response handler close accepted")
	}
	l.Close()
}

func TestForkLegacyHTTP2ListenerContextAndStalledPreface(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}}
	listener, err := Listen(ctx, net.LocalHostIP, tcp.PickPort(), settings, func(conn stat.Connection) { t.Error("missing preface reached tunnel handler"); conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	l := listener.(*Listener)
	t.Cleanup(func() { cancel(); l.Close() })
	raw, err := gonet.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.Write([]byte(http2.ClientPreface[:1]))
	cancel()
	select {
	case <-l.done:
	case <-time.After(5 * time.Second):
		t.Fatal("listener cancellation retained stalled connection")
	}
	if _, err := Listen(ctx, net.LocalHostIP, 1, settings, nil); err == nil {
		t.Fatal("already-canceled listener created")
	}
}
