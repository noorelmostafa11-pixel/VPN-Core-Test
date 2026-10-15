package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func xPolicyOptions() *XHTTPServerOptions {
	return &XHTTPServerOptions{XPaddingBytes: &XHTTPPaddingRange{32, 32}, XPaddingObfsMode: true, XPaddingPlacement: "header", NoSSEHeader: true,
		ResponseHeaders: map[string]string{"Content-Type": "application/octet-stream", "X-Core": "${version}/${method}/${httpVersion}"},
		CORS:            &XHTTPCORSOptions{Origins: []string{"http://front.example"}, AllowCredentials: true, AllowHeaders: []string{"X-Custom"}, ExposeHeaders: []string{"X-Core"}, MaxAgeSeconds: 60}}
}

func TestXHTTPResponseCombinedProtocolsModes(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		for _, mode := range []string{"stream-one", "stream-up", "packet-up", "auto"} {
			for _, protocol := range []string{"vless", "vmess", "trojan", "ss"} {
				t.Run(version+"/"+mode+"/"+protocol, func(t *testing.T) {
					x := xPolicyOptions()
					if mode == "stream-up" || mode == "auto" {
						x.ScStreamUpServerSecs = &XHTTPPaddingRange{1, 1}
					}
					cfg, server := carrierServerFixtureWithXHTTPExtra(t, protocol, "xhttp", version != "h1", 0, x, mode, version)
					var extra map[string]any
					json.Unmarshal(cfg.Extra, &extra)
					extra["headers"] = map[string]string{"Origin": "http://front.example"}
					extra["scMinPostsIntervalMs"] = 1
					cfg.Extra, _ = json.Marshal(extra)
					client, err := NewEngine(context.Background(), cfg, Hooks{})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					conn, err := client.DialContext(client.ctx, "tcp", echoPeer(t))
					if err != nil {
						t.Fatal(err)
					}
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					body := bytes.Repeat([]byte("combined policy\x00\xff"), 6000)
					if _, err = conn.Write(body); err != nil {
						conn.Close()
						t.Fatal(err)
					}
					got := make([]byte, len(body))
					_, err = io.ReadFull(conn, got)
					conn.Close()
					if err != nil || !bytes.Equal(body, got) {
						t.Fatal("combined policy changed protocol bytes", err)
					}
					if protocol != "ss" {
						host, port, _ := splitProtocolTarget(udpEchoPeer(t))
						packets, err := client.dialPacket(client.ctx, host, port)
						if err != nil {
							t.Fatal(err)
						}
						checkHysteriaUDP(t, packets)
						packets.Close()
					}
					client.Close()
					server.Close()
					if client.Stats().Active != 0 || server.Stats().Active != 0 {
						t.Fatal("response policy retained admission")
					}
				})
			}
		}
	}
}

func xPolicyHTTPClient(t *testing.T, cfg Config, version string) (*http.Client, string) {
	t.Helper()
	scheme := "http"
	tlsConfig := &tls.Config{}
	if cfg.Security == "tls" {
		scheme = "https"
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
			t.Fatal("test CA")
		}
		tlsConfig.ServerName = cfg.Server
	}
	var transport http.RoundTripper
	if version == "h3" {
		rt := &http3.Transport{TLSClientConfig: tlsConfig}
		t.Cleanup(func() { rt.Close() })
		transport = rt
	} else {
		rt := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: version == "h2", DisableCompression: true}
		t.Cleanup(rt.CloseIdleConnections)
		transport = rt
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, scheme + "://" + net.JoinHostPort(cfg.Server, itoa(cfg.Port)) + "/native%20path"
}

func TestXHTTPCORSPreflightWireAndEmptyFIN(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		t.Run(version, func(t *testing.T) {
			x := xPolicyOptions()
			cfg, server := carrierServerFixtureWithXHTTPExtra(t, "vless", "xhttp", version != "h1", 0, x, "packet-up", version)
			client, base := xPolicyHTTPClient(t, cfg, version)
			cases := []struct {
				origin, method, fields, path, body string
				want                               int
			}{
				{"http://front.example", "POST", "Content-Type, X-Custom", "/session/0", "", 200},
				{"http://front.example", "GET", "", "", "", 200},
				{"http://other.example", "POST", "Content-Type", "", "", 403},
				{"null", "POST", "", "", "", 400},
				{"http://front.example", "DELETE", "", "", "", 403},
				{"http://front.example", "POST", "Content-Length", "", "", 403},
				{"http://front.example", "POST", "X-Custom,x-custom", "", "", 400},
				{"http://front.example", "POST", "X-Unknown", "", "", 403},
				{"http://front.example", "POST", "", "/session/0/extra", "", 404},
				{"http://front.example", "POST", "", "/session/not-sequence", "", 404},
				{"http://front.example", "POST", "", "", "bad-body", 400},
			}
			for _, tc := range cases {
				r, _ := http.NewRequest("OPTIONS", base+"/"+strings.TrimPrefix(tc.path, "/"), strings.NewReader(tc.body))
				r.Host = "localhost"
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Access-Control-Request-Method", tc.method)
				if tc.fields != "" {
					r.Header.Set("Access-Control-Request-Headers", tc.fields)
				}
				res, err := client.Do(r)
				if err != nil {
					t.Fatal(tc, err)
				}
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil || res.StatusCode != tc.want || len(body) != 0 {
					t.Fatal("preflight wire result", tc, res.StatusCode, err)
				}
				if tc.want == 200 && (res.Header.Get("Access-Control-Allow-Origin") != tc.origin || res.Header.Get("Access-Control-Allow-Credentials") != "true" || !strings.Contains(res.Header.Get("X-Core"), "/OPTIONS/")) {
					t.Fatal("preflight reflection/template policy", res.Header)
				}
			}
			// A positive declared length is rejected above. Verify unknown-length
			// HTTP3 actual FIN too, without allocating a split protocol session.
			if version == "h3" {
				r, _ := http.NewRequest("OPTIONS", base+"/", io.NopCloser(strings.NewReader("x")))
				r.Host = "localhost"
				r.Header.Set("Origin", "http://front.example")
				r.Header.Set("Access-Control-Request-Method", "POST")
				res, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != 400 {
					t.Fatal("nonempty unknown preflight body accepted", res.StatusCode)
				}
			}
			server.Close()
			if server.Stats().Active != 0 {
				t.Fatal("preflight retained owner admission")
			}
		})
	}
}

func TestXHTTPResponseConfigurationIsolationAndBudget(t *testing.T) {
	for _, x := range []XHTTPServerOptions{
		{ResponseHeaders: map[string]string{"Content-Encoding": "gzip"}}, {ResponseHeaders: map[string]string{"Cache-Control": "public"}},
		{ResponseHeaders: map[string]string{"X-Test": "bad\r\nheader"}}, {ResponseHeaders: map[string]string{"X-Test": "${cookie}"}},
		{ResponseHeaders: map[string]string{"X-Test": "${unfinished"}}, {ResponseHeaders: map[string]string{"X-Test": strings.Repeat("x", 513)}},
		{ResponseHeaders: map[string]string{"X-Test": "a", "x-test": "b"}},
		{CORS: &XHTTPCORSOptions{}}, {CORS: &XHTTPCORSOptions{Origins: []string{"*"}, AllowCredentials: true}},
		{CORS: &XHTTPCORSOptions{Origins: []string{"https://front.example/path"}}}, {CORS: &XHTTPCORSOptions{Origins: []string{"null"}}},
		{CORS: &XHTTPCORSOptions{Origins: []string{"http://host:"}}}, {CORS: &XHTTPCORSOptions{Origins: []string{"http://host:70000"}}},
		{CORS: &XHTTPCORSOptions{Origins: []string{"http://front.example"}, AllowHeaders: []string{"Cookie"}}},
		{CORS: &XHTTPCORSOptions{Origins: []string{"http://front.example"}, MaxAgeSeconds: 601}},
		{XPaddingBytes: &XHTTPPaddingRange{4096, 4096}, XPaddingObfsMode: true, XPaddingPlacement: "header", XPaddingMethod: "tokenish", CORS: &XHTTPCORSOptions{Origins: []string{"http://front.example"}}},
		{ScStreamUpServerSecs: &XHTTPPaddingRange{0, 1}}, {ScStreamUpServerSecs: &XHTTPPaddingRange{1, 301}},
	} {
		if _, err := compileXHTTPMetadata(x); err == nil {
			t.Fatal("unsafe response configuration accepted", x)
		}
	}
	x := xPolicyOptions()
	x.ScStreamUpServerSecs = &XHTTPPaddingRange{1, 2}
	compiled, err := compileXHTTPMetadata(*x)
	if err != nil {
		t.Fatal(err)
	}
	x.ResponseHeaders["X-Core"] = "changed"
	x.CORS.Origins[0], x.CORS.AllowHeaders[0] = "http://other.example", "Other"
	x.ScStreamUpServerSecs.From = 2
	if compiled.ResponseHeaders["X-Core"] == "changed" || compiled.CORS.Origins[0] != "http://front.example" || compiled.CORS.AllowHeaders[0] != "X-Custom" || compiled.ScStreamUpServerSecs.From != 1 {
		t.Fatal("compiled response settings alias caller state")
	}
	if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Mode: "packet-up", Extra: &compiled}}); err == nil {
		t.Fatal("periodic upload padding accepted in packet-only mode")
	}
}

func TestXHTTPCORSRejectionBeforeSessionAllocation(t *testing.T) {
	e := testServerEngine(t)
	defer e.Close()
	m := &xServerSessions{e: e}
	e.track(m)
	tpt, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Path: "/vpn", Mode: "packet-up", Extra: xPolicyOptions()}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		r := httptest.NewRequest("POST", "http://localhost/vpn/session/0", strings.NewReader("unforwarded bytes"))
		r.Header.Set("Origin", "http://denied.example")
		w := &xPaddingRecorder{httptest.NewRecorder()}
		e.serveXHTTP(w, r, serverSpec{transport: tpt}, m)
		if w.Code != 403 || len(m.items) != 0 || e.Stats().Active != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("denied origin retained state or was reflected", w.Code, len(m.items))
		}
		r = httptest.NewRequest("OPTIONS", "http://localhost/vpn/", nil)
		r.Header.Set("Origin", "http://front.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
		w = &xPaddingRecorder{httptest.NewRecorder()}
		e.serveXHTTP(w, r, serverSpec{transport: tpt}, m)
		if w.Code != 200 || len(m.items) != 0 || m.buffered.Load() != 0 || e.Stats().Active != 0 {
			t.Fatal("preflight allocated protocol state", w.Code, len(m.items))
		}
		r = httptest.NewRequest("OPTIONS", "http://localhost/vpn/", strings.NewReader("body"))
		r.Header.Set("Origin", "http://front.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
		w = &xPaddingRecorder{httptest.NewRecorder()}
		e.serveXHTTP(w, r, serverSpec{transport: tpt}, m)
		if w.Code != 400 || len(m.items) != 0 || m.buffered.Load() != 0 || e.Stats().Active != 0 {
			t.Fatal("nonempty preflight allocated protocol state", w.Code, len(m.items))
		}
	}
}

func TestXHTTPCORSDuplicateWildcardAndActualResponses(t *testing.T) {
	options := xPolicyOptions()
	compiled, err := compileXHTTPMetadata(*options)
	if err != nil {
		t.Fatal(err)
	}
	tpt := &ServerTransportConfig{Extra: &compiled, Method: "POST"}
	for _, tc := range []struct {
		origins []string
		want    int
	}{
		{nil, 0}, {[]string{"http://front.example"}, 0},
		{[]string{"http://front.example", "http://front.example"}, 400},
		{[]string{"http://front.example,http://other.example"}, 400},
		{[]string{"https://other.example"}, 403},
	} {
		r := httptest.NewRequest("POST", "http://localhost/", nil)
		for _, origin := range tc.origins {
			r.Header.Add("Origin", origin)
		}
		w := httptest.NewRecorder()
		if status := xServerCORS(w, r, tpt, false); status != tc.want {
			t.Fatal("actual CORS policy", tc, status)
		}
		if tc.want == 0 && len(tc.origins) == 1 && (w.Header().Get("Access-Control-Expose-Headers") != "X-Core" || w.Header().Get("Access-Control-Allow-Credentials") != "true") {
			t.Fatal("actual CORS exposure", w.Header())
		}
	}
	compiled, err = compileXHTTPMetadata(XHTTPServerOptions{CORS: &XHTTPCORSOptions{Origins: []string{"*"}}})
	if err != nil {
		t.Fatal(err)
	}
	tpt.Extra = &compiled
	r := httptest.NewRequest("GET", "http://localhost/", nil)
	r.Header.Set("Origin", "http://any.example")
	w := httptest.NewRecorder()
	if status := xServerCORS(w, r, tpt, false); status != 0 || w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("noncredential wildcard policy", status, w.Header())
	}
}

func TestXHTTPUploadPaddingWireLifetime(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		t.Run(version, func(t *testing.T) {
			x := xPolicyOptions()
			x.ScStreamUpServerSecs = &XHTTPPaddingRange{1, 1}
			serverConfig, _ := ParseURI("direct://")
			serverConfig.ConnectTimeout = 350 * time.Millisecond
			serverConfig.IdleTimeout = 4 * time.Second
			server, err := NewEngine(context.Background(), serverConfig, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "xhttp", Path: "/native%20path", Host: "localhost", Mode: "stream-up", HTTPVersion: version, Extra: x}}
			if version != "h1" {
				spec.CertFile, spec.KeyFile = testServerCertificate(t)
			}
			addr, err := server.StartServer(spec)
			if err != nil {
				t.Fatal(err)
			}
			cfg := defaults()
			cfg.Protocol, cfg.Transport, cfg.Mode, cfg.Security = "vless", "xhttp", "stream-up", "none"
			cfg.Server, cfg.Port, _ = splitProtocolTarget(addr.String())
			cfg.UUID, _ = uuidBytes(visionServerTestUUID)
			if spec.CertFile != "" {
				cfg.Security, cfg.CAFile = "tls", spec.CertFile
			}
			client, base := xPolicyHTTPClient(t, cfg, version)
			request := func(method string, body io.Reader) *http.Request {
				r, _ := http.NewRequest(method, base+"/lifetime", body)
				r.Host = "localhost"
				r.Header.Set("Origin", "http://front.example")
				r.Header.Set("X-Padding", strings.Repeat("X", 32))
				return r
			}
			down, err := client.Do(request("GET", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer down.Body.Close()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			up, err := client.Do(request("POST", reader))
			if err != nil {
				t.Fatal(err)
			}
			defer up.Body.Close()
			pad := make([]byte, 32)
			if _, err := io.ReadFull(up.Body, pad); err != nil || string(pad) != strings.Repeat("X", 32) {
				t.Fatal("initial upload response padding", err)
			}
			host, port, _ := splitProtocolTarget(echoPeer(t))
			address, _ := Address(host, port)
			header, _ := newProtocol(cfg, false).open(address)
			body := []byte("protocol bytes stay only on the download")
			if _, err = writer.Write(join(header, body)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(body)+2)
			if _, err = io.ReadFull(down.Body, got); err != nil || !bytes.Equal(got, join([]byte{0, 0}, body)) {
				t.Fatal("padding crossed into protocol download", err)
			}
			if _, err := io.ReadFull(up.Body, pad); err != nil || string(pad) != strings.Repeat("X", 32) {
				t.Fatal("periodic upload padding", err)
			}
			if _, err := writer.Write(body); err != nil {
				t.Fatal("upload did not survive setup deadline", err)
			}
			got = make([]byte, len(body))
			if _, err := io.ReadFull(down.Body, got); err != nil || !bytes.Equal(got, body) {
				t.Fatal("download did not survive periodic padding/setup deadline", err)
			}
			writer.Close()
			if tail, err := io.ReadAll(up.Body); err != nil || len(tail) > 32 || strings.Trim(string(tail), "X") != "" {
				t.Fatal("finite upload padding failed to stop/drain", len(tail), err)
			}
			before := time.Now()
			server.Close()
			if time.Since(before) > time.Second || server.Stats().Active != 0 {
				t.Fatal("upload timer retained owner", server.Stats())
			}
		})
	}
}

type xBlockedPaddingWriter struct {
	xPaddingRecorder
	started, release       chan struct{}
	startOnce, releaseOnce sync.Once
}

func (w *xBlockedPaddingWriter) Write([]byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	return 0, io.ErrClosedPipe
}
func (w *xBlockedPaddingWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && deadline.Before(time.Now().Add(50*time.Millisecond)) {
		w.releaseOnce.Do(func() { close(w.release) })
	}
	return nil
}

func TestXHTTPUploadPaddingBlockedWriteOwnerJoin(t *testing.T) {
	e := testServerEngine(t)
	m := &xServerSessions{e: e}
	e.track(m)
	s, err := m.session("blocked")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://localhost/blocked", nil)
	r.Header.Set("Referer", "http://cover.example/?x_padding=marker")
	w := &xBlockedPaddingWriter{xPaddingRecorder: xPaddingRecorder{httptest.NewRecorder()}, started: make(chan struct{}), release: make(chan struct{})}
	c := &serverHTTP2Conn{request: r, writer: w, controller: http.NewResponseController(w)}
	e.track(c)
	s.upload, s.uploadDone = c, make(chan struct{})
	s.deadline = time.Time{}
	e.spawn(func() {
		e.waitXHTTPUpload(c, s, s.uploadDone, XHTTPServerOptions{ScStreamUpServerSecs: &XHTTPPaddingRange{1, 1}})
	})
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("padding writer did not enter")
	}
	joined := make(chan struct{})
	go func() { e.Close(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("blocked upload padding outlived owner")
	}
	if e.Stats().Active != 0 {
		t.Fatal("blocked padding retained admission")
	}
}
