package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestXHTTPPaddingCarriersProtocolsAndModes(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		for i, placement := range []string{"query", "header", "cookie", "queryInHeader"} {
			for j, method := range []string{"repeat-x", "tokenish"} {
				for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
					t.Run(version+"/"+placement+"/"+method+"/"+mode, func(t *testing.T) {
						extra := &XHTTPServerOptions{XPaddingObfsMode: true, XPaddingPlacement: placement, XPaddingMethod: method, XPaddingKey: "pad_key", XPaddingHeader: "Pad-Header", XPaddingBytes: &XHTTPPaddingRange{64, 96}, NoSSEHeader: j == 1,
							SessionIDPlacement: "query", SessionIDKey: "Meta-Session", SeqPlacement: "header", SeqKey: "Meta-Seq"}
						protocol := []string{"vless", "vmess", "trojan", "ss"}[(i+j)%4]
						cfg, server := carrierServerFixtureWithXHTTPExtra(t, protocol, "xhttp", version != "h1", 0, extra, mode, version)
						var clientExtra map[string]any
						json.Unmarshal(cfg.Extra, &clientExtra)
						clientExtra["scMinPostsIntervalMs"] = 1
						cfg.Extra, _ = json.Marshal(clientExtra)
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
						for cycle := 0; cycle < 2; cycle++ {
							body := bytes.Repeat([]byte{byte(cycle + 37)}, 100019)
							if _, err = conn.Write(body); err != nil {
								conn.Close()
								t.Fatal(err)
							}
							got := make([]byte, len(body))
							if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, body) {
								conn.Close()
								t.Fatal("padding changed application bytes", err)
							}
						}
						conn.Close()
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
							t.Fatal("padding retained owner admission")
						}
					})
				}
			}
		}
	}
}

func xPaddingTestRequest(x XHTTPServerOptions, value string) *http.Request {
	r := httptest.NewRequest("POST", "http://localhost/vpn", nil)
	switch x.XPaddingPlacement {
	case "query":
		r.URL.RawQuery = url.QueryEscape(x.XPaddingKey) + "=" + url.QueryEscape(value)
	case "header":
		r.Header.Set(x.XPaddingHeader, value)
	case "cookie":
		r.AddCookie(&http.Cookie{Name: x.XPaddingKey, Value: value})
	case "queryInHeader":
		r.Header.Set(x.XPaddingHeader, "https://cover.example/path?"+url.QueryEscape(x.XPaddingKey)+"="+url.QueryEscape(value))
	}
	return r
}

func xPaddingTestValid(r *http.Request, x XHTTPServerOptions) bool {
	q, err := url.ParseQuery(r.URL.RawQuery)
	return err == nil && xServerValidPadding(r, q, r.Cookies(), x)
}

func TestXHTTPPaddingValidationAndLegacyBoundary(t *testing.T) {
	for _, placement := range []string{"query", "header", "cookie", "queryInHeader"} {
		for _, method := range []string{"repeat-x", "tokenish"} {
			x, err := compileXHTTPMetadata(XHTTPServerOptions{XPaddingObfsMode: true, XPaddingPlacement: placement, XPaddingMethod: method, XPaddingBytes: &XHTTPPaddingRange{64, 64}})
			if err != nil {
				t.Fatal(err)
			}
			value := (xOptions{XPaddingBytes: intRange{64, 64}, XPaddingMethod: method}).padding()
			if !xPaddingTestValid(xPaddingTestRequest(x, value), x) {
				t.Fatal("valid bounded padding rejected", placement, method)
			}
			for _, bad := range []string{"", strings.Repeat("X", 61), strings.Repeat("X", 67), strings.Repeat("A", 8193), "bad\r\nvalue"} {
				if xPaddingTestValid(xPaddingTestRequest(x, bad), x) {
					t.Fatal("malformed padding accepted", placement, method, len(bad))
				}
			}
			r := xPaddingTestRequest(x, value)
			switch placement {
			case "query":
				r.URL.RawQuery += "&x_padding=" + value
			case "header", "queryInHeader":
				r.Header.Add(x.XPaddingHeader, r.Header.Get(x.XPaddingHeader))
			case "cookie":
				r.AddCookie(&http.Cookie{Name: x.XPaddingKey, Value: value})
			}
			if xPaddingTestValid(r, x) {
				t.Fatal("duplicate padding accepted", placement)
			}
			r = xPaddingTestRequest(x, value)
			if placement == "query" {
				r.Header.Set(x.XPaddingHeader, value)
			} else {
				r.URL.RawQuery = "x_padding=" + value
			}
			if xPaddingTestValid(r, x) || xPaddingTestValid(httptest.NewRequest("POST", "http://localhost/vpn", nil), x) {
				t.Fatal("ambiguous/missing required padding accepted", placement)
			}
			r = xPaddingTestRequest(x, value)
			r.Header.Add("Cookie", x.XPaddingKey+"=bad\\cookie")
			if xPaddingTestValid(r, x) {
				t.Fatal("silently discarded malformed cookie bypassed padding policy", placement)
			}
		}
	}
	x, _ := compileXHTTPMetadata(XHTTPServerOptions{})
	r := httptest.NewRequest("POST", "http://localhost/vpn", nil)
	if !xPaddingTestValid(r, x) {
		t.Fatal("unconfigured legacy request no longer accepted")
	}
	r.URL.RawQuery = "x_padding=" + strings.Repeat("X", 100)
	if !xPaddingTestValid(r, x) {
		t.Fatal("legacy query padding rejected")
	}
	r.URL.RawQuery = ""
	r.Header.Set("Referer", "https://cover.example/?x_padding="+strings.Repeat("X", 100))
	if !xPaddingTestValid(r, x) {
		t.Fatal("legacy Referer padding rejected")
	}
	x, _ = compileXHTTPMetadata(XHTTPServerOptions{XPaddingBytes: &XHTTPPaddingRange{100, 1000}})
	for _, bad := range []string{"https://cover.example/?x_padding=%XX", "https://cover.example/?x_padding=" + strings.Repeat("X", 100) + "&x_padding=X", "https://cover.example/?x_padding=X", "https://cover.example/?x_padding=" + strings.Repeat("X", 100) + "#fragment"} {
		r.Header.Set("Referer", bad)
		if xPaddingTestValid(r, x) {
			t.Fatal("invalid legacy Referer padding accepted")
		}
	}
}

func TestXHTTPPaddingConfigurationRangeAndIsolation(t *testing.T) {
	for _, x := range []XHTTPServerOptions{
		{XPaddingBytes: &XHTTPPaddingRange{0, 64}}, {XPaddingBytes: &XHTTPPaddingRange{65, 64}}, {XPaddingBytes: &XHTTPPaddingRange{1, 4097}},
		{XPaddingPlacement: "path"}, {XPaddingMethod: "unknown"}, {XPaddingKey: "bad key"}, {XPaddingHeader: strings.Repeat("K", 129)},
		{XPaddingHeader: "Content-Type"}, {XPaddingHeader: "Set-Cookie"}, {XPaddingHeader: "X-Session"}, {XPaddingKey: "x_seq"},
		{XPaddingHeader: "Data-0", UplinkDataKey: "Data"}, {XPaddingKey: "Data_0", UplinkDataKey: "Data"},
		{XPaddingBytes: &XHTTPPaddingRange{64, 64}, SessionIDPlacement: "header", SessionIDKey: "Referer"},
		{XPaddingBytes: &XHTTPPaddingRange{64, 64}, XPaddingKey: "ignored-legacy-key", SeqPlacement: "query", SeqKey: "x_padding"},
	} {
		if _, err := compileXHTTPMetadata(x); err == nil {
			t.Fatal("invalid padding configuration accepted", x)
		}
	}
	for _, encoded := range []string{`64`, `"64"`, `"64-96"`, `"96-64"`} {
		var r XHTTPPaddingRange
		if err := json.Unmarshal([]byte(encoded), &r); err != nil || r.From != 64 || r.To < 64 || r.To > 96 {
			t.Fatal("padding range syntax", encoded, r, err)
		}
		out, _ := json.Marshal(r)
		var restored XHTTPPaddingRange
		if json.Unmarshal(out, &restored) != nil || restored != r {
			t.Fatal("padding range roundtrip", string(out))
		}
	}
	r := &XHTTPPaddingRange{64, 96}
	x, err := compileXHTTPMetadata(XHTTPServerOptions{XPaddingBytes: r})
	if err != nil {
		t.Fatal(err)
	}
	r.From = 1
	if x.XPaddingBytes.From != 64 || !x.paddingRequired {
		t.Fatal("compiled padding aliases caller state")
	}
	plain, _ := compileXHTTPMetadata(XHTTPServerOptions{NoSSEHeader: true})
	if plain.paddingRequired {
		t.Fatal("SSE option unexpectedly requires request padding")
	}
	encoded, _ := json.Marshal(plain)
	var restored XHTTPServerOptions
	if json.Unmarshal(encoded, &restored) != nil {
		t.Fatal("server option roundtrip")
	}
	restored, err = compileXHTTPMetadata(restored)
	if err != nil || restored.paddingRequired {
		t.Fatal("serialized disabled padding became required", string(encoded), err)
	}
	if _, err := compileXHTTPMetadata(XHTTPServerOptions{SessionIDPlacement: "query", SessionIDKey: "x_padding"}); err != nil {
		t.Fatal("disabled padding changed an existing metadata namespace", err)
	}
}

func TestXHTTPPaddingResponseCarriersAndBound(t *testing.T) {
	for _, plain := range []XHTTPServerOptions{{}, {NoSSEHeader: true}} {
		x, _ := compileXHTTPMetadata(plain)
		w := httptest.NewRecorder()
		xServerHeaders(w, x)
		if w.Header().Get("X-Padding") != strings.Repeat("X", 100) {
			t.Fatal("disabled padding changed legacy response")
		}
	}
	for _, placement := range []string{"query", "header", "cookie", "queryInHeader"} {
		for _, method := range []string{"repeat-x", "tokenish"} {
			x, _ := compileXHTTPMetadata(XHTTPServerOptions{XPaddingObfsMode: true, XPaddingPlacement: placement, XPaddingMethod: method, XPaddingBytes: &XHTTPPaddingRange{4096, 4096}, NoSSEHeader: true})
			w := httptest.NewRecorder()
			xServerHeaders(w, x)
			if w.Header().Get("Content-Type") != "" || w.Header().Get("Content-Encoding") != "identity" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Accel-Buffering") != "no" {
				t.Fatal("response padding replaced invariant headers")
			}
			budget := 0
			for name, values := range w.Header() {
				for _, value := range values {
					budget += 32 + len(name) + len(value)
				}
			}
			if budget > 8192 {
				t.Fatal("response padding bypassed existing header budget", budget)
			}
			r := httptest.NewRequest("POST", "http://localhost/vpn", nil)
			if placement == "cookie" {
				for _, cookie := range w.Result().Cookies() {
					r.AddCookie(cookie)
				}
			} else {
				r.Header = w.Header().Clone()
			}
			if placement != "query" && !xPaddingTestValid(r, x) {
				t.Fatal("response padding uses wrong carrier/size", placement, method)
			}
			if placement == "query" && (w.Header().Get(x.XPaddingHeader) != "" || len(w.Result().Cookies()) != 0) {
				t.Fatal("query padding invented a response carrier")
			}
		}
	}
}

type xPaddingRecorder struct{ *httptest.ResponseRecorder }

func (*xPaddingRecorder) EnableFullDuplex() error          { return nil }
func (*xPaddingRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*xPaddingRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestXHTTPPaddingRejectsBeforeSessionAllocation(t *testing.T) {
	e := testServerEngine(t)
	defer e.Close()
	m := &xServerSessions{e: e}
	e.track(m)
	tpt, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Path: "/vpn", Mode: "packet-up", Extra: &XHTTPServerOptions{XPaddingBytes: &XHTTPPaddingRange{64, 64}}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		r := httptest.NewRequest("POST", "http://localhost/vpn/session/0", strings.NewReader("unforwarded protocol bytes"))
		w := &xPaddingRecorder{httptest.NewRecorder()}
		e.serveXHTTP(w, r, serverSpec{transport: tpt}, m)
		if w.Code != 400 || len(m.items) != 0 || m.buffered.Load() != 0 || e.Stats().Active != 0 {
			t.Fatal("invalid padding allocated a session or retained admission", w.Code, len(m.items), e.Stats())
		}
	}
}
