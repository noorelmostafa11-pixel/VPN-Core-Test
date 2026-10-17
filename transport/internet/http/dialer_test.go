package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	httpheader "github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func referencePeer(t *testing.T, secure bool, handler http.Handler) (*httptest.Server, *internet.MemoryStreamConfig) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	settings := &internet.MemoryStreamConfig{ProtocolName: "http", ProtocolSettings: &Config{Host: []string{"tunnel.example"}, Path: "/legacy%20path?key=value", Method: "PATCH", Header: []*httpheader.Header{{Name: "X-Test", Value: []string{"one", "two"}}}}}
	if secure {
		server.EnableHTTP2 = true
		server.StartTLS()
		hash := sha256.Sum256(server.Certificate().Raw)
		settings.SecuritySettings = &tls.Config{ServerName: "example.com", PinnedPeerCertSha256: [][]byte{hash[:]}}
		settings.SecurityType = "tls"
	} else {
		server.Config.Handler = h2c.NewHandler(handler, &http2.Server{})
		server.Start()
	}
	t.Cleanup(server.Close)
	return server, settings
}

func dialPeer(t *testing.T, server *httptest.Server, settings *internet.MemoryStreamConfig, ctx context.Context) *clientConn {
	t.Helper()
	c := dialPeerWithoutDeadline(t, server, settings, ctx)
	if err := c.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func dialPeerWithoutDeadline(t *testing.T, server *httptest.Server, settings *internet.MemoryStreamConfig, ctx context.Context) *clientConn {
	t.Helper()
	port := server.Listener.Addr().(*gonet.TCPAddr).Port
	conn, err := Dial(ctx, net.TCPDestination(net.LocalHostIP, net.Port(port)), settings)
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*clientConn)
	t.Cleanup(func() {
		c.Close()
		select {
		case <-c.workerDone:
		case <-time.After(5 * time.Second):
			t.Error("HTTP/2 response worker did not join")
		}
	})
	return c
}

func TestForkLegacyHTTP2ClientIndependentPeer(t *testing.T) {
	for _, variant := range []string{"h2c", "TLS", "uTLS"} {
		t.Run(variant, func(t *testing.T) {
			secure := variant != "h2c"
			done := make(chan error, 1)
			greeting := []byte("server-first\n")
			payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
			server, settings := referencePeer(t, secure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.Method != "PATCH" || r.Host != "tunnel.example" || r.URL.EscapedPath() != "/legacy%20path" || r.URL.RawQuery != "key=value" || strings.Join(r.Header.Values("X-Test"), ",") != "one,two" || r.Header.Get("Accept-Encoding") != "identity" {
					done <- errors.New("HTTP/2 wire metadata mismatch")
					w.WriteHeader(404)
					return
				}
				w.WriteHeader(200)
				w.Write(greeting)
				w.(http.Flusher).Flush()
				got, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(got, payload) {
					done <- errors.New("upload/half-close mismatch")
					return
				}
				_, err = w.Write(got)
				done <- err
			}))
			if variant == "TLS" {
				settings.SecuritySettings.(*tls.Config).Fingerprint = "unsafe"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c := dialPeer(t, server, settings, ctx)
			got := make([]byte, len(greeting))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, greeting) {
				t.Fatal("server-first failed", err)
			}
			for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
				if n, err := c.Write(piece); err != nil || n != len(piece) {
					t.Fatal("upload failed", n, err)
				}
			}
			if err := c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("download after upload EOF failed", len(got), err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("independent handler did not finish")
			}
		})
	}
}

func TestForkLegacyHTTP2ClientRejectsResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		encodings []string
	}{
		{"redirect", 307, nil}, {"missing", 404, nil}, {"compression", 200, []string{"gzip"}}, {"duplicate-encoding", 200, []string{"identity", "identity"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			requests := 0
			server, settings := referencePeer(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests++
				mu.Unlock()
				w.Header().Set("Location", "/redirect")
				for _, value := range test.encodings {
					w.Header().Add("Content-Encoding", value)
				}
				w.WriteHeader(test.status)
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c := dialPeerWithoutDeadline(t, server, settings, ctx)
			want := "invalid legacy HTTP/2 response: status " + strconv.Itoa(test.status)
			if _, err := c.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("invalid HTTP/2 response rejection: got %v, want %q", err, want)
			}
			select {
			case <-c.workerDone:
			case <-ctx.Done():
				t.Fatal("HTTP/2 response worker did not finish after rejection")
			}
			mu.Lock()
			defer mu.Unlock()
			if requests != 1 {
				t.Fatal("HTTP request retried or redirected", requests)
			}
		})
	}
}

func TestForkLegacyHTTP2ClientDeadlineAndCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server, settings := referencePeer(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-release:
			w.Write([]byte("ok"))
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := dialPeer(t, server, settings, ctx)
	<-started
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline ignored", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	close(release)
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ok" {
		t.Fatal("read deadline was not renewable", err)
	}
	// No server consumes the request body. Exceed HTTP/2's finite upload window
	// to force a real blocked write, then cancel the owning context.
	writing := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 8<<20)); writing <- err }()
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-writing:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("write deadline ignored", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write stayed blocked")
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); blocked <- err }()
	cancel()
	select {
	case err := <-blocked:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation not propagated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled read stayed blocked")
	}
	select {
	case <-c.workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled response worker remained alive")
	}
}

func TestForkLegacyHTTP2ClientCancelBeforeHeaders(t *testing.T) {
	started := make(chan struct{})
	server, settings := referencePeer(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	ctx, cancel := context.WithCancel(context.Background())
	c := dialPeer(t, server, settings, ctx)
	<-started
	cancel()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-header cancellation lost", err)
	}
}

func TestForkLegacyHTTP2ClientTLSSafety(t *testing.T) {
	server, settings := referencePeer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	security := settings.SecuritySettings.(*tls.Config)
	port := net.Port(server.Listener.Addr().(*gonet.TCPAddr).Port)
	dest := net.TCPDestination(net.LocalHostIP, port)
	security.NextProtocol = []string{"http/1.1"}
	if c, err := Dial(context.Background(), dest, settings); err == nil {
		c.Close()
		t.Fatal("explicit incompatible ALPN ignored")
	}
	security.NextProtocol = nil
	security.PinnedPeerCertSha256 = [][]byte{bytes.Repeat([]byte{0xff}, 32)}
	if c, err := Dial(context.Background(), dest, settings); err == nil {
		c.Close()
		t.Fatal("bad certificate pin accepted")
	}
	settings.SecuritySettings = nil
	if c, err := Dial(context.Background(), dest, settings); err == nil {
		c.Close()
		t.Fatal("missing TLS settings downgraded to h2c")
	}
	plainTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP/1.1 fallback reached handler") }))
	defer plainTLS.Close()
	hash := sha256.Sum256(plainTLS.Certificate().Raw)
	settings.SecuritySettings = &tls.Config{ServerName: "example.com", PinnedPeerCertSha256: [][]byte{hash[:]}, Fingerprint: "unsafe", NextProtocol: []string{"h2", "http/1.1"}}
	if c, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(plainTLS.Listener.Addr().(*gonet.TCPAddr).Port)), settings); err == nil {
		c.Close()
		t.Fatal("TLS peer negotiated HTTP/1.1 without rejection")
	}
}
