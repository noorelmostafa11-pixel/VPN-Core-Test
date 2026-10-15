package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestXHTTPSplitProtocolsTCPUDPReuse(t *testing.T) {
	for _, mode := range []string{"stream-up", "packet-up", "auto"} {
		for _, protocol := range []string{"vless", "vmess", "trojan", "ss"} {
			for _, secure := range []bool{false, true} {
				t.Run(mode+"/"+protocol+"/TLS="+boolText(secure), func(t *testing.T) {
					cfg, server := carrierServerFixture(t, protocol, "xhttp", secure, 0, mode)
					client, err := NewEngine(context.Background(), cfg, Hooks{})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					target := echoPeer(t)
					for cycle := 0; cycle < 3; cycle++ {
						conn, err := client.DialContext(client.ctx, "tcp", target)
						if err != nil {
							t.Fatal(err)
						}
						payloadCheck(t, conn)
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
						t.Fatal("split carrier retained admission")
					}
				})
			}
		}
	}
}

func TestXHTTPPacketReorderingConflictAndCancellation(t *testing.T) {
	cfg, server := carrierServerFixture(t, "vless", "xhttp", false, 0, "packet-up")
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	base := "http://" + net.JoinHostPort(cfg.Server, itoa(cfg.Port)) + "/native%20path/"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := func(method, tail string, body []byte) *http.Request {
		r, _ := http.NewRequestWithContext(ctx, method, base+tail, bytes.NewReader(body))
		r.Host = "localhost"
		return r
	}
	down, err := client.Do(request("GET", "ordered", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer down.Body.Close()
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(cfg, false).open(address)
	body := bytes.Repeat([]byte("ordered packet body"), 8192)
	wire := join(header, body)
	for _, post := range []struct {
		tail string
		body []byte
		code int
	}{{"ordered/1", wire[7:], 200}, {"ordered/1", wire[7:], 409}, {"ordered/30", nil, 409}, {"ordered/0", wire[:7], 200}, {"ordered/0", nil, 409}} {
		response, err := client.Do(request("POST", post.tail, post.body))
		if err != nil {
			t.Fatal(post.tail, err)
		}
		response.Body.Close()
		if response.StatusCode != post.code {
			t.Fatal(post.tail, response.StatusCode)
		}
	}
	got := make([]byte, len(body)+2)
	if _, err := io.ReadFull(down.Body, got); err != nil || !bytes.Equal(got, join([]byte{0, 0}, body)) {
		t.Fatal("reordered protocol payload", len(got), err)
	}
	cancel()
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("canceled split session retained admission")
	}
}

func TestXHTTPSessionsQuotaExpiryDeadlineAndOwnerJoin(t *testing.T) {
	e := testServerEngine(t)
	e.config.ConnectTimeout = 50 * time.Millisecond
	m := &xServerSessions{e: e}
	if !e.track(m) {
		t.Fatal("manager ownership")
	}
	defer e.untrack(m)
	if !m.reserve(xServerTotalBuffer) || m.reserve(1) {
		t.Fatal("listener backing allocation budget exceeded")
	}
	m.buffered.Add(-xServerTotalBuffer)
	s, err := m.session("orphan")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("pending")
	if !m.reserve(len(payload)) || s.push(1, xServerPacket{payload, len(payload)}) != nil {
		t.Fatal("pending packet")
	}
	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("split setup deadline ignored", err)
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("unattached session was not expired")
	}
	e.Close() // Joins the expiry watcher, including its refund/removal.
	m.mu.Lock()
	remaining := len(m.items)
	m.mu.Unlock()
	if remaining != 0 || m.buffered.Load() != 0 || e.Stats().Active != 0 {
		t.Fatal("orphan retained buffers/admission", remaining, m.buffered.Load(), e.Stats())
	}
	if _, err := m.session("closed"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed manager admitted a session", err)
	}
}

func TestXHTTPSessionBackingBudgetAndAdmission(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.MaxConnections = 4
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	m := &xServerSessions{e: e}
	if !e.track(m) {
		t.Fatal("manager ownership")
	}
	defer e.untrack(m)
	s, err := m.session("bounded")
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(0); seq < 2; seq++ {
		allocation := make([]byte, xServerPostLimit+1)
		allocation[0] = byte(seq)
		if !m.reserve(len(allocation)) || s.push(seq, xServerPacket{allocation[:1], len(allocation)}) != nil {
			t.Fatal("bounded backing allocation")
		}
	}
	if err := s.push(2, xServerPacket{[]byte{2}, 1}); err == nil {
		t.Fatal("per-session backing budget exceeded")
	}
	if m.buffered.Load() != xServerSessionBuffer {
		t.Fatal("allocation accounting counted only payload length", m.buffered.Load())
	}
	if _, err := s.Read(make([]byte, 1)); err != nil || m.buffered.Load() != xServerPostLimit+1 {
		t.Fatal("consumed backing allocation was not released", m.buffered.Load(), err)
	}
	for i := 0; i < 3; i++ {
		if _, err := m.session("pending-" + itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.session("over-limit"); !errors.Is(err, errXServerAdmission) {
		t.Fatal("orphan session admission was unbounded", err)
	}
	e.Close()
	if m.buffered.Load() != 0 || e.Stats().Active != 0 {
		t.Fatal("owner close retained queue allocations/admission", m.buffered.Load(), e.Stats())
	}
}

func TestXHTTPStreamUpFiniteBodyHalfClose(t *testing.T) {
	cfg, server := carrierServerFixture(t, "vless", "xhttp", false, 0, "stream-up")
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	base := "http://" + net.JoinHostPort(cfg.Server, itoa(cfg.Port)) + "/native%20path/half-close"
	get, _ := http.NewRequest("GET", base, nil)
	get.Host = "localhost"
	down, err := client.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Body.Close()
	host, port, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(host, port)
	header, _ := newProtocol(cfg, false).open(address)
	body := bytes.Repeat([]byte("stream-up final body"), 65536)
	post, _ := http.NewRequest("POST", base, bytes.NewReader(join(header, body)))
	post.Host = "localhost"
	done := make(chan error, 1)
	go func() {
		response, err := client.Do(post)
		if err == nil {
			_, err = io.ReadAll(response.Body)
			response.Body.Close()
		}
		done <- err
	}()
	got, err := io.ReadAll(down.Body)
	if err != nil || !bytes.Equal(got, join([]byte{0, 0}, body)) {
		t.Fatal("finite stream-up upload lost response drain", len(got), err)
	}
	if err := <-done; err != nil {
		t.Fatal("finite stream-up upload handler was not joined", err)
	}
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("finite split session retained admission")
	}
}

func TestXHTTPSplitDownloadSurvivesSetupTimeout(t *testing.T) {
	for _, httpVersion := range []string{"h1", "h2", "h3"} {
		t.Run(httpVersion, func(t *testing.T) {
			serverConfig, _ := ParseURI("direct://")
			serverConfig.ConnectTimeout = 250 * time.Millisecond
			serverConfig.IdleTimeout = 3 * time.Second
			server, err := NewEngine(context.Background(), serverConfig, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID},
				Transport: &ServerTransportConfig{Type: "xhttp", Mode: "stream-up", HTTPVersion: httpVersion, Path: "/native%20path", Host: "localhost"}}
			if httpVersion != "h1" {
				spec.CertFile, spec.KeyFile = testServerCertificate(t)
			}
			addr, err := server.StartServer(spec)
			if err != nil {
				t.Fatal(err)
			}
			clientConfig := defaults()
			clientConfig.Protocol, clientConfig.Transport, clientConfig.Mode, clientConfig.Security = "vless", "xhttp", "stream-up", "none"
			clientConfig.Server, clientConfig.Port, _ = splitProtocolTarget(addr.String())
			clientConfig.UUID, _ = uuidBytes(visionServerTestUUID)
			clientConfig.Path, clientConfig.Host = "/native path", "localhost"
			if spec.CertFile != "" {
				clientConfig.Security = "tls"
				clientConfig.CAFile = spec.CertFile
				clientConfig.ServerName = clientConfig.Server
				clientConfig.Fingerprint = "native"
				clientConfig.ALPN = []string{httpVersion}
			}
			if err := clientConfig.Validate(); err != nil {
				t.Fatal(err)
			}
			client, err := NewEngine(context.Background(), clientConfig, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			conn, err := client.DialContext(client.ctx, "tcp", echoPeer(t))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			for cycle, payload := range [][]byte{[]byte("before setup timeout"), []byte("after setup timeout")} {
				if _, err := conn.Write(payload); err != nil {
					t.Fatal("split upload stopped", cycle, err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatal("split download stopped", cycle, err)
				}
				time.Sleep(400 * time.Millisecond)
			}
			conn.Close()
			client.Close()
			server.Close()
			if client.Stats().Active != 0 || server.Stats().Active != 0 {
				t.Fatal("split timeout regression retained admission")
			}
		})
	}
}

func TestXHTTPSplitProtectionCancellationAndMalformed(t *testing.T) {
	for _, mode := range []string{"stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := ParseURI("direct://")
			entered, exited := make(chan struct{}, 1), make(chan struct{}, 1)
			server, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(ctx context.Context, _ int64) error {
				entered <- struct{}{}
				<-ctx.Done()
				exited <- struct{}{}
				return ctx.Err()
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "xhttp", Mode: mode, Path: "/test"}})
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{DisableCompression: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			base := "http://" + addr.String() + "/test/"
			for _, tail := range []string{"bad/id/extra", "id/-1", "id/18446744073709551616", "%00", "id//"} {
				r, _ := http.NewRequest("POST", base+tail, bytes.NewReader(nil))
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusNotFound {
					t.Fatal("malformed split request admitted", tail, response.StatusCode)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			get, _ := http.NewRequestWithContext(ctx, "GET", base+"cancel", nil)
			down, err := client.Do(get)
			if err != nil {
				t.Fatal(err)
			}
			defer down.Body.Close()
			protocol := defaults()
			protocol.Protocol = "vless"
			protocol.UUID, _ = uuidBytes(visionServerTestUUID)
			host, port, _ := splitProtocolTarget(echoPeer(t))
			address, _ := Address(host, port)
			header, _ := newProtocol(protocol, false).open(address)
			tail := "cancel"
			if mode == "packet-up" {
				tail += "/0"
			}
			post, _ := http.NewRequestWithContext(ctx, "POST", base+tail, bytes.NewReader(header))
			up, err := client.Do(post)
			if err != nil {
				t.Fatal(err)
			}
			defer up.Body.Close()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("protected split dial was not entered")
			}
			cancel()
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("download cancellation did not cancel protected dialing")
			}
			server.Close()
			if server.Stats().Active != 0 {
				t.Fatal("canceled split owner retained admission")
			}
		})
	}
}

func TestXHTTPPartialPostOwnerLossAndOversizeRejection(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.ConnectTimeout = 2 * time.Second
	server, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "xhttp", Mode: "packet-up"}})
	if err != nil {
		t.Fatal(err)
	}
	var manager *xServerSessions
	server.mu.Lock()
	for resource := range server.closers {
		if m, ok := resource.(*xServerSessions); ok {
			manager = m
		}
	}
	server.mu.Unlock()
	if manager == nil || manager.items != nil || manager.buffered.Load() != 0 {
		t.Fatal("split listener eagerly created sessions or payload allocations")
	}
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	base := "http://" + addr.String()
	response, err := client.Post(base+"/oversize/0", "application/octet-stream", bytes.NewReader(make([]byte, xServerPostLimit+1)))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	manager.mu.Lock()
	count := len(manager.items)
	manager.mu.Unlock()
	if response.StatusCode != 413 || count != 0 || manager.buffered.Load() != 0 {
		t.Fatal("oversize request created a session or buffer", response.StatusCode, count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	get, _ := http.NewRequestWithContext(ctx, "GET", base+"/pending", nil)
	down, err := client.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Body.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	post, _ := http.NewRequestWithContext(ctx, "POST", base+"/pending/0", reader)
	done := make(chan error, 1)
	go func() {
		response, err := client.Do(post)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for manager.buffered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if manager.buffered.Load() == 0 {
		t.Fatal("partial upload body did not enter bounded allocation")
	}
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("partial split POST retained the owner")
	}
	cancel()
	writer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("partial POST client was not joined")
	}
	if manager.buffered.Load() != 0 || server.Stats().Active != 0 {
		t.Fatal("partial POST retained backing allocation/admission", manager.buffered.Load(), server.Stats())
	}
}
