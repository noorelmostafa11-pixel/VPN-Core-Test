package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestXHTTPServerMetadataPlacementsPayloadAndOwner(t *testing.T) {
	placements := []string{"path", "query", "header", "cookie"}
	for _, httpVersion := range []string{"h1", "h2", "h3"} {
		for i, sessionPlacement := range placements {
			for j, seqPlacement := range placements {
				t.Run(httpVersion+"/"+sessionPlacement+"/"+seqPlacement, func(t *testing.T) {
					x := &XHTTPServerOptions{SessionIDPlacement: sessionPlacement, SeqPlacement: seqPlacement}
					if sessionPlacement != "path" {
						x.SessionIDKey = "Meta-Session"
					}
					if seqPlacement != "path" {
						x.SeqKey = "Meta-Sequence"
					}
					protocol := []string{"vless", "vmess", "trojan", "ss"}[(i+j)%4]
					cfg, server := carrierServerFixtureWithXHTTPExtra(t, protocol, "xhttp", httpVersion != "h1", 0, x, "packet-up", httpVersion)
					client, err := NewEngine(context.Background(), cfg, Hooks{})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					conn, err := client.DialContext(client.ctx, "tcp", echoPeer(t))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					for cycle := 0; cycle < 2; cycle++ {
						body := bytes.Repeat([]byte{byte(31 + cycle)}, 100019)
						if _, err := conn.Write(body); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, len(body))
						if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, body) {
							t.Fatal("metadata changed protocol payload", err)
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
						t.Fatal("metadata retained owner admission")
					}
				})
			}
		}
	}
}

func TestXHTTPServerMetadataStreamModes(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "auto"} {
		for _, placement := range []string{"path", "query", "header", "cookie"} {
			t.Run(mode+"/"+placement, func(t *testing.T) {
				x := &XHTTPServerOptions{SessionIDPlacement: placement, SeqPlacement: "header"}
				cfg, server := carrierServerFixtureWithXHTTPExtra(t, "vless", "xhttp", false, 0, x, mode)
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				conn, err := client.DialContext(client.ctx, "tcp", echoPeer(t))
				if err != nil {
					t.Fatal(err)
				}
				payloadCheck(t, conn)
				client.Close()
				server.Close()
			})
		}
	}
}

func TestXHTTPServerMetadataConfigurationAndIsolation(t *testing.T) {
	for _, x := range []XHTTPServerOptions{
		{SessionIDPlacement: "body"}, {SeqPlacement: "invalid"},
		{SessionIDKey: "ignored-path-key"},
		{SessionIDPlacement: "header", SessionIDKey: "Cookie"},
		{SeqPlacement: "header", SeqKey: "Content-Length"},
		{SessionIDPlacement: "query", SessionIDKey: "bad key"},
		{SessionIDPlacement: "query", SessionIDKey: strings.Repeat("K", 129)},
		{SessionIDPlacement: "header", SessionIDKey: "same", SeqPlacement: "header", SeqKey: "SAME"},
		{SessionIDPlacement: "cookie", SessionIDKey: "same", SeqPlacement: "cookie", SeqKey: "same"},
	} {
		if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Extra: &x}}); err == nil {
			t.Fatal("invalid metadata configuration accepted", x)
		}
	}
	x := &XHTTPServerOptions{SessionIDPlacement: "query"}
	tpt, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Path: "/vpn", Extra: x}})
	if err != nil {
		t.Fatal(err)
	}
	x.SessionIDPlacement = "header"
	if tpt.Extra.SessionIDPlacement != "query" || tpt.Extra.SessionIDKey != "x_session" || tpt.Path != "/vpn/" {
		t.Fatal("compiled metadata aliases mutable configuration", tpt)
	}
	if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "http2", Extra: &XHTTPServerOptions{}}}); err == nil {
		t.Fatal("XHTTP metadata accepted on another carrier")
	}
	for _, extra := range []string{`{"sessionIDPlacement":"header","seqPlacement":"query"}`, `{"uplinkDataPlacement":"header"}`} {
		profile := `{"outbounds":[{"tag":"direct","uri":"direct://"}],"final":"direct","inbounds":[{"protocol":"vless","listen":"127.0.0.1:0","uuids":["` + visionServerTestUUID + `"],"transport":{"type":"xhttp","extra":` + extra + `}}]}`
		_, err := ReadRouterConfig(strings.NewReader(profile))
		if strings.Contains(extra, "uplinkDataPlacement") == (err == nil) {
			t.Fatal("strict profile metadata decoding boundary", extra, err)
		}
	}
}

func TestXHTTPServerMetadataRejectsAmbiguousRequests(t *testing.T) {
	for _, placement := range []string{"query", "header", "cookie"} {
		t.Run(placement, func(t *testing.T) {
			x := &XHTTPServerOptions{SessionIDPlacement: placement, SeqPlacement: placement}
			tpt, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Mode: "auto", Path: "/vpn", Extra: x}})
			if err != nil {
				t.Fatal(err)
			}
			x = tpt.Extra
			request := func(id, seq string) *http.Request {
				r := httptest.NewRequest("POST", "http://example.test/vpn", nil)
				set := func(key, value string) {
					switch placement {
					case "query":
						q := r.URL.Query()
						q.Set(key, value)
						r.URL.RawQuery = q.Encode()
					case "header":
						r.Header.Set(key, value)
					case "cookie":
						r.AddCookie(&http.Cookie{Name: key, Value: value})
					}
				}
				set(x.SessionIDKey, id)
				set(x.SeqKey, seq)
				return r
			}
			good := request("session-1", "0")
			if kind, id, seq, ok := xServerRequest(good, tpt); !ok || kind != "packet" || id != "session-1" || seq != 0 {
				t.Fatal("valid metadata packet rejected", kind, id, seq, ok)
			}
			for _, mutate := range []func(*http.Request){
				func(r *http.Request) {
					switch placement {
					case "query":
						r.URL.RawQuery += "&" + x.SessionIDKey + "=other"
					case "header":
						r.Header.Add(x.SessionIDKey, "other")
					case "cookie":
						r.AddCookie(&http.Cookie{Name: x.SessionIDKey, Value: "other"})
					}
				},
				func(r *http.Request) { r.URL.Path += "/unexpected" },
				func(r *http.Request) { r.URL.RawQuery += "&bad=%zz" },
				func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
				func(r *http.Request) { r.Method = "GET" },
				func(r *http.Request) {
					if placement == "header" {
						r.URL.RawQuery += "&x_session=conflicting"
					} else {
						r.Header.Set("X-Session", "conflicting")
					}
				},
			} {
				r := request("session-1", "0")
				mutate(r)
				if _, _, _, ok := xServerRequest(r, tpt); ok {
					t.Fatal("ambiguous metadata admitted", r.URL, r.Header)
				}
			}
			for _, pair := range [][2]string{{"", "0"}, {"a/b", "0"}, {strings.Repeat("x", 129), "0"}, {"ok", ""}, {"ok", "-1"}, {"ok", "18446744073709551615"}, {"ok", "18446744073709551616"}} {
				if _, _, _, ok := xServerRequest(request(pair[0], pair[1]), tpt); ok {
					t.Fatal("invalid metadata admitted", pair)
				}
			}
		})
	}
}
