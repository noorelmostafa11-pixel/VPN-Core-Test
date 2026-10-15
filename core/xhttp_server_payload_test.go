package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestXHTTPPayloadCarriersProtocolsAndGET(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		for _, placement := range []string{"header", "cookie"} {
			for _, method := range []string{"POST", "GET"} {
				for _, protocol := range []string{"vless", "vmess", "trojan", "ss"} {
					t.Run(version+"/"+placement+"/"+method+"/"+protocol, func(t *testing.T) {
						extra := &XHTTPServerOptions{UplinkDataPlacement: placement, UplinkDataKey: "Packet-Data", SessionIDPlacement: "header", SessionIDKey: "Meta-Session", SeqPlacement: "query", SeqKey: "seq"}
						cfg, server := carrierServerFixtureWithXHTTPExtra(t, protocol, "xhttp", version != "h1", 0, extra, "packet-up", version, method)
						clientExtra := map[string]any{}
						serialized, _ := json.Marshal(extra)
						json.Unmarshal(serialized, &clientExtra)
						clientExtra["scMinPostsIntervalMs"] = 1
						clientExtra["uplinkHTTPMethod"] = method
						clientExtra["uplinkChunkSize"] = "71-139"
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
						body := bytes.Repeat([]byte("payload carrier wire\x00\xff"), 8000)
						if _, err := conn.Write(body); err != nil {
							conn.Close()
							t.Fatal(err)
						}
						got := make([]byte, len(body))
						_, err = io.ReadFull(conn, got)
						conn.Close()
						if err != nil || !bytes.Equal(got, body) {
							t.Fatal("encoded packet carrier changed TCP payload", err)
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
						if server.Stats().Active != 0 || client.Stats().Active != 0 {
							t.Fatal("encoded packet retained admission")
						}
					})
				}
			}
		}
	}
}

func TestXHTTPAutoPayloadMergeAndBodyBudget(t *testing.T) {
	extra := &XHTTPServerOptions{UplinkDataPlacement: "auto", UplinkDataKey: "Mixed"}
	cfg, server := carrierServerFixtureWithXHTTPExtra(t, "vless", "xhttp", false, 0, extra, "packet-up")
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := "http://" + net.JoinHostPort(cfg.Server, itoa(cfg.Port)) + "/native%20path/mixed"
	get, _ := http.NewRequestWithContext(ctx, "GET", base, nil)
	get.Host = "localhost"
	down, err := client.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Body.Close()
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(cfg, false).open(address)
	body := bytes.Repeat([]byte("mixed payload\x00\xff"), 4000)
	wire := join(header, body)
	post, _ := http.NewRequestWithContext(ctx, "POST", base+"/0", bytes.NewReader(wire[23:]))
	post.Host = "localhost"
	encoded := base64.RawURLEncoding.EncodeToString(wire[:17])
	post.Header.Set("Mixed-1", encoded[5:])
	post.Header.Set("Mixed-0", encoded[:5])
	post.AddCookie(&http.Cookie{Name: "Mixed_0", Value: base64.RawURLEncoding.EncodeToString(wire[17:23])})
	up, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	up.Body.Close()
	got := make([]byte, len(body)+2)
	if _, err = io.ReadFull(down.Body, got); err != nil || up.StatusCode != 200 || !bytes.Equal(got, join([]byte{0, 0}, body)) {
		t.Fatal("header/cookie/body order changed protocol bytes", up.StatusCode, err)
	}
	cancel()
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("mixed packet retained admission")
	}
	x, _ := compileXHTTPMetadata(*extra)
	r := httptest.NewRequest("POST", "http://localhost/session/0", strings.NewReader(strings.Repeat("B", xServerPostLimit)))
	r.Header.Set("Mixed-0", "AQ")
	if _, status := xServerPlanPacket(r, x); status != 413 {
		t.Fatal("auto bypassed combined decoded/body size limit", status)
	}
}

func TestXHTTPPayloadRejectsMalformedChunksAndConfiguration(t *testing.T) {
	for _, placement := range []string{"header", "cookie"} {
		x, _ := compileXHTTPMetadata(XHTTPServerOptions{UplinkDataPlacement: placement, UplinkDataKey: "Data"})
		for _, chunks := range [][][2]string{
			{{"0", "AQ"}, {"0", "AQ"}}, {{"1", "AQ"}}, {{"0", "AQ"}, {"2", "AQ"}},
			{{"00", "AQ"}}, {{"-1", "AQ"}}, {{"128", "AQ"}}, {{"", "AQ"}},
			{{"0", ""}}, {{"0", "A"}}, {{"0", "AB"}}, {{"0", "AQ=="}}, {{"0", "A%"}}, {{"0", "AQ\n"}},
			{{"0", strings.Repeat("A", xServerPayloadEncodedLimit+1)}},
		} {
			r := httptest.NewRequest("POST", "http://localhost/id/0", nil)
			for _, chunk := range chunks {
				if placement == "header" {
					r.Header.Add("Data-"+chunk[0], chunk[1])
				} else {
					r.Header.Add("Cookie", "Data_"+chunk[0]+"="+chunk[1])
				}
			}
			if _, status := xServerPlanPacket(r, x); status != http.StatusBadRequest {
				t.Fatal("malformed encoded packet admitted", placement, chunks, status)
			}
		}
	}
	for _, x := range []XHTTPServerOptions{
		{UplinkDataPlacement: "query"}, {UplinkDataPlacement: "header", UplinkDataKey: "bad key"},
		{UplinkDataPlacement: "header", UplinkDataKey: strings.Repeat("K", 129)},
		{UplinkDataPlacement: "header", SessionIDPlacement: "header", SessionIDKey: "X-Data-0"},
		{UplinkDataPlacement: "cookie", SeqPlacement: "cookie", SeqKey: "x_data_1"},
		{UplinkDataPlacement: "body", UplinkDataKey: "Data", SessionIDPlacement: "header", SessionIDKey: "Data-0"},
	} {
		if _, err := compileXHTTPMetadata(x); err == nil {
			t.Fatal("invalid payload configuration accepted", x)
		}
	}
	if _, err := compileServerTransport(ServerConfig{Protocol: "vless", Transport: &ServerTransportConfig{Type: "xhttp", Mode: "stream-up", Extra: &XHTTPServerOptions{UplinkDataPlacement: "header"}}}); err == nil {
		t.Fatal("packet-only placement accepted for stream-up-only listener")
	}
}

func TestXHTTPPayloadUnknownBodyValidationRefund(t *testing.T) {
	for _, placement := range []string{"header", "auto"} {
		t.Run(placement, func(t *testing.T) {
			e := testServerEngine(t)
			m := &xServerSessions{e: e}
			e.track(m)
			s, err := m.session("partial")
			if err != nil {
				t.Fatal(err)
			}
			x, _ := compileXHTTPMetadata(XHTTPServerOptions{UplinkDataPlacement: placement, UplinkDataKey: "Data"})
			body := "unexpected"
			want := 400
			if placement == "auto" {
				body = strings.Repeat("B", xServerPostLimit)
				want = 413
			}
			r := httptest.NewRequest("POST", "http://localhost/partial/0", strings.NewReader(body))
			r.ContentLength = -1
			r.Header.Set("Data-0", "AQID")
			plan, status := xServerPlanPacket(r, x)
			if status != 0 {
				t.Fatal("unknown body rejected before bounded read", status)
			}
			w := httptest.NewRecorder()
			e.receiveXHTTPPacket(&serverHTTP2Conn{request: r, writer: w, controller: http.NewResponseController(w)}, s, 0, plan)
			if w.Code != want || m.buffered.Load() != 0 || len(s.packets) != 0 {
				t.Fatal("invalid body retained decoded bytes", w.Code, m.buffered.Load())
			}
			e.Close()
		})
	}
}

func TestXHTTPPayloadConcurrentDuplicateRefundsAndQuota(t *testing.T) {
	e := testServerEngine(t)
	m := &xServerSessions{e: e}
	if !e.track(m) {
		t.Fatal("manager ownership")
	}
	x, _ := compileXHTTPMetadata(XHTTPServerOptions{UplinkDataPlacement: "header", UplinkDataKey: "Data"})
	s, err := m.session("concurrent")
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "http://localhost/concurrent/0", nil)
		r.Header.Set("Data-0", "AQID")
		return r
	}
	results := make(chan int, 32)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Go(func() {
			r := request()
			plan, status := xServerPlanPacket(r, x)
			if status != 0 {
				results <- status
				return
			}
			w := httptest.NewRecorder()
			c := &serverHTTP2Conn{request: r, writer: w, controller: http.NewResponseController(w)}
			e.receiveXHTTPPacket(c, s, 0, plan)
			results <- w.Code
		})
	}
	workers.Wait()
	close(results)
	accepted := 0
	for status := range results {
		if status == 200 {
			accepted++
		} else if status != 409 {
			t.Fatal("duplicate result", status)
		}
	}
	if accepted != 1 || m.buffered.Load() != 4 {
		t.Fatal("duplicate packet retained scratch or backing allocations", accepted, m.buffered.Load())
	}
	got := make([]byte, 3)
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) || m.buffered.Load() != 0 {
		t.Fatal("decoded allocation lifetime", got, err, m.buffered.Load())
	}
	if !m.reserve(xServerTotalBuffer - 7) {
		t.Fatal("quota setup")
	}
	r := request()
	plan, _ := xServerPlanPacket(r, x)
	w := httptest.NewRecorder()
	e.receiveXHTTPPacket(&serverHTTP2Conn{request: r, writer: w, controller: http.NewResponseController(w)}, s, 1, plan)
	if w.Code != 503 || m.buffered.Load() != xServerTotalBuffer-7 {
		t.Fatal("decode scratch bypassed listener budget", w.Code, m.buffered.Load())
	}
	m.buffered.Add(-(xServerTotalBuffer - 7))
	e.Close()
	if m.buffered.Load() != 0 || e.Stats().Active != 0 {
		t.Fatal("packet owner retained resources")
	}
}
