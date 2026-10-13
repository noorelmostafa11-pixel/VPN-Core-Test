package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hc "github.com/apernet/hysteria/core/v2/client"
	hs "github.com/apernet/hysteria/core/v2/server"
)

func hysteriaFixture(t *testing.T) (Config, hs.Server) {
	t.Helper()
	cert, key := testServerCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := hs.NewServer(&hs.Config{Conn: packet, TLSConfig: hs.TLSConfig{Certificates: []tls.Certificate{pair}}, Authenticator: hyAuth{"test-auth"}, UDPIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve() }()
	t.Cleanup(func() { server.Close(); <-done })
	cfg, err := ParseURI("hy2://test-auth@" + packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = cert
	cfg.ConnectTimeout = time.Second
	return cfg, server
}
func udpEchoPeer(t *testing.T) string {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			p.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { p.Close(); <-done })
	return p.LocalAddr().String()
}
func checkHysteriaUDP(t *testing.T, s PacketStream) {
	t.Helper()
	defer s.Close()
	s.SetDeadline(time.Now().Add(4 * time.Second))
	for _, size := range []int{1, 1400, 32000, 60000} {
		body := []byte(strings.Repeat("z", size))
		if err := s.WritePacket(body); err != nil {
			t.Fatal(err)
		}
		r, err := s.ReadPacket()
		if err != nil || string(r.Payload) != string(body) {
			t.Fatalf("UDP size %d: got %d bytes, %v", size, len(r.Payload), err)
		}
	}
}
func TestHysteriaTCPUDPAndCache(t *testing.T) {
	cfg, _ := hysteriaFixture(t)
	target := echoPeer(t)
	host, port, err := splitProtocolTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	var protects atomic.Int32
	e, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { protects.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 32; i++ {
		c, err := e.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(i, err)
		}
		payloadCheck(t, c)
	}
	if protects.Load() != 1 {
		t.Fatalf("expected one reused protected QUIC transport; got %d", protects.Load())
	}
	uhost, uport, _ := splitProtocolTarget(udpEchoPeer(t))
	s, err := e.dialPacket(e.ctx, uhost, uport)
	if err != nil {
		t.Fatal(err)
	}
	checkHysteriaUDP(t, s)
	c, err := e.dialTCP(e.ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("engine close did not join promptly")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("live connection survived owner loss")
	}
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}
func TestHysteriaRejectsAuthTrustAndProtection(t *testing.T) {
	cfg, _ := hysteriaFixture(t)
	cases := []struct {
		name  string
		edit  func(*Config)
		hooks Hooks
		want  string
	}{
		{"auth", func(c *Config) { c.Password = "wrong" }, Hooks{}, "HYSTERIA_HANDSHAKE_FAILED"},
		{"trust", func(c *Config) { c.CAFile = "" }, Hooks{}, "HYSTERIA_HANDSHAKE_FAILED"},
		{"pin", func(c *Config) { c.Options["pinsha256"] = strings.Repeat("00", 32) }, Hooks{}, "HYSTERIA_HANDSHAKE_FAILED"},
		{"protect", func(*Config) {}, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }}, "SOCKET_PROTECTION_FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{}
			tc.edit(&c)
			conn, err := Dial(WithHooks(context.Background(), tc.hooks), c, "127.0.0.1", 80)
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
}
func TestHysteriaHandshakeTimeoutAndDualFamily(t *testing.T) {
	cfg, _ := hysteriaFixture(t)
	cfg.Server = "bootstrap.test"
	var protected atomic.Int32
	ctx := WithHooks(context.Background(), Hooks{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}, Protect: func(context.Context, int64) error { protected.Add(1); return nil }})
	host, port, _ := splitProtocolTarget(echoPeer(t))
	c, err := Dial(ctx, cfg, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, c)
	if protected.Load() != 1 {
		t.Fatal("working IPv4 waited for IPv6", protected.Load())
	}
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	cfg.Server = "127.0.0.1"
	_, cfg.Port, _ = splitProtocolTarget(blackhole.LocalAddr().String())
	cfg.ConnectTimeout = 100 * time.Millisecond
	start := time.Now()
	c, err = Dial(context.Background(), cfg, host, port)
	if c != nil {
		c.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("handshake timeout", time.Since(start), err)
	}
}
func TestHysteriaServerOfficialClientAndClose(t *testing.T) {
	cert, key := testServerCertificate(t)
	e := testServerEngine(t)
	addr, err := e.StartServer(ServerConfig{Protocol: "hysteria2", Listen: "127.0.0.1:0", Password: "test-auth", CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	b, _ := os.ReadFile(cert)
	roots.AppendCertsFromPEM(b)
	client, _, err := hc.NewClient(&hc.Config{ServerAddr: addr, Auth: "test-auth", TLSConfig: hc.TLSConfig{ServerName: "127.0.0.1", RootCAs: roots}, QUICConfig: hc.QUICConfig{DisableChromeParrot: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := 0; i < 16; i++ {
		c, err := client.TCP(echoPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		payloadCheck(t, c)
	}
	u, err := client.UDP()
	if err != nil {
		t.Fatal(err)
	}
	target := udpEchoPeer(t)
	checkHysteriaUDP(t, &hyPackets{conn: u, owner: nopCloser{}, address: target})
	live, err := client.TCP(echoPeer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("server Close did not join")
	}
	live.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := live.Read(make([]byte, 1)); err == nil {
		t.Fatal("live stream survived server shutdown")
	}
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
func TestHysteriaPinAndReconnect(t *testing.T) {
	cfg, server := hysteriaFixture(t)
	b, _ := os.ReadFile(cfg.CAFile)
	block, _ := pem.Decode(b)
	hash := sha256.Sum256(block.Bytes)
	cfg.Options["pinsha256"] = hex.EncodeToString(hash[:])
	cfg.CAFile = ""
	c, err := Dial(context.Background(), cfg, "127.0.0.1", 1)
	if c != nil {
		c.Close()
	}
	if err == nil || strings.Contains(err.Error(), "HANDSHAKE") {
		t.Fatalf("valid pin did not authenticate: %v", err)
	}
	cfg.Options = map[string]string{}
	cert, key := testServerCertificate(t)
	cfg.CAFile = cert
	server.Close()
	// A new fixture reuses its own address across server restart, proving that
	// a dead cached transport is not handed to the next connection attempt.
	packet, err := net.ListenPacket("udp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)))
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := tls.LoadX509KeyPair(cert, key)
	srv, err := hs.NewServer(&hs.Config{Conn: packet, TLSConfig: hs.TLSConfig{Certificates: []tls.Certificate{pair}}, Authenticator: hyAuth{"test-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); srv.Serve() }()
	defer func() { srv.Close(); <-done }()
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	target := echoPeer(t)
	conn, err := e.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	srv.Close()
	<-done
	e.clients.mu.Lock()
	for _, entry := range e.clients.entries {
		entry.client.Close()
	}
	e.clients.mu.Unlock()
	packet, err = net.ListenPacket("udp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)))
	if err != nil {
		t.Fatal(err)
	}
	srv, err = hs.NewServer(&hs.Config{Conn: packet, TLSConfig: hs.TLSConfig{Certificates: []tls.Certificate{pair}}, Authenticator: hyAuth{"test-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	done = make(chan struct{})
	go func() { defer close(done); srv.Serve() }()
	conn, err = e.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
}
func TestClientCacheConcurrentCloseAndLimits(t *testing.T) {
	cache := newClientCache(context.Background())
	var opened, closed atomic.Int32
	open := func(context.Context) (io.Closer, error) { opened.Add(1); return &countCloser{n: &closed}, nil }
	var leases []*clientLease
	for i := 0; i < 64; i++ {
		l, err := cache.get(context.Background(), itoa(i), open)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if _, err := cache.get(context.Background(), "overflow", open); err == nil {
		t.Fatal("cache limit absent")
	}
	leases[0].Close()
	l, err := cache.get(context.Background(), "replacement", open)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); cache.Close() }()
	}
	workers.Wait()
	for _, l := range leases {
		l.Close()
	}
	if opened.Load() != 65 || closed.Load() != 65 {
		t.Fatal(opened.Load(), closed.Load())
	}
}

type countCloser struct{ n *atomic.Int32 }

func (c *countCloser) Close() error { c.n.Add(1); return nil }

func TestHysteriaObfsChromeAndReno(t *testing.T) {
	cert, key := testServerCertificate(t)
	for _, mode := range []string{"none", "salamander", "gecko"} {
		t.Run(mode, func(t *testing.T) {
			e := testServerEngine(t)
			opts := map[string]string{"congestion": "reno"}
			if mode != "none" {
				opts["obfs"] = mode
				opts["obfs-password"] = "test-obfs-secret"
			}
			a, err := e.StartServer(ServerConfig{Protocol: "hysteria2", Listen: "127.0.0.1:0", Password: "test-auth", CertFile: cert, KeyFile: key, Options: opts})
			if err != nil {
				t.Fatal(err)
			}
			uri := "hy2://test-auth@" + a.String() + "?fp=chrome&congestion=reno"
			if mode != "none" {
				uri += "&obfs=" + mode + "&obfs-password=test-obfs-secret"
			}
			cfg, err := ParseURI(uri)
			if err != nil {
				t.Fatal(err)
			}
			cfg.CAFile = cert
			h, p, _ := splitProtocolTarget(echoPeer(t))
			conn, err := Dial(context.Background(), cfg, h, p)
			if err != nil {
				t.Fatal(err)
			}
			payloadCheck(t, conn)
			h, p, _ = splitProtocolTarget(udpEchoPeer(t))
			s, err := DialPacket(context.Background(), cfg, h, p)
			if err != nil {
				t.Fatal(err)
			}
			checkHysteriaUDP(t, s)
		})
	}
}
func TestHysteriaStreamCancellationLeavesOtherFlowsAlive(t *testing.T) {
	cert, key := testServerCertificate(t)
	cfg, _ := ParseURI("direct://")
	var pending atomic.Int32
	server, err := NewEngine(context.Background(), cfg, Hooks{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":9") {
			pending.Add(1)
			defer pending.Add(-1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	a, err := server.StartServer(ServerConfig{Protocol: "hysteria2", Listen: "127.0.0.1:0", Password: "test-auth", CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = ParseURI("hy2://test-auth@" + a.String())
	cfg.CAFile = cert
	cfg.ConnectTimeout = time.Second
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	live, err := client.DialContext(context.Background(), "tcp", echoPeer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	failed, err := client.DialContext(ctx, "tcp", "127.0.0.1:9")
	if failed != nil {
		failed.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("stream cancel was not bounded", err)
	}
	payloadCheck(t, live)
	server.Close()
	if pending.Load() != 0 {
		t.Fatal("pending dial survived shutdown")
	}
}
