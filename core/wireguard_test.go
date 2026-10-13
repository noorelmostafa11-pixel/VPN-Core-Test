package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
	wc "golang.zx2c4.com/wireguard/conn"
	wd "golang.zx2c4.com/wireguard/device"
	wn "golang.zx2c4.com/wireguard/tun/netstack"
)

func testWireKeys(t *testing.T) (string, string) {
	t.Helper()
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public)
}
func wireFixture(t *testing.T) (Config, *wn.Net, *wd.Device) {
	t.Helper()
	private, public := testWireKeys(t)
	clientPrivate, clientPublic := testWireKeys(t)
	tun, network, err := wn.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.71.0.1"), netip.MustParseAddr("fd71::1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := wd.NewDeviceWithWorkers(tun, wc.NewStdNetBind(), &wd.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}, 2)
	pri, _ := wireKey(private)
	pub, _ := wireKey(clientPublic)
	err = dev.IpcSet("private_key=" + pri + "\npublic_key=" + pub + "\nallowed_ip=10.71.0.2/32\nallowed_ip=fd71::2/128\n")
	if err != nil {
		t.Fatal(err)
	}
	if err = dev.Up(); err != nil {
		t.Fatal(err)
	}
	ipc, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := ""
	for _, line := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" {
		t.Fatal("no server port")
	}
	t.Cleanup(func() { dev.Close(); <-dev.EventReaderDone() })
	cfg, err := ParseURI("wireguard://" + url.User(clientPrivate).String() + "@127.0.0.1:" + port + "?public-key=" + url.QueryEscape(public) + "&local-address=10.71.0.2/32,fd71::2/128")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnectTimeout = 5 * time.Second
	return cfg, network, dev
}
func wireTCPPeer(t *testing.T, n *wn.Net, host string) string {
	t.Helper()
	l, err := n.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(host), 0))
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); workers.Wait() })
	return l.Addr().String()
}
func wireUDPPeer(t *testing.T, n *wn.Net, host string) string {
	t.Helper()
	p, err := n.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(host), 0))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			size, a, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			p.WriteTo(b[:size], a)
		}
	}()
	t.Cleanup(func() { p.Close(); <-done })
	return p.LocalAddr().String()
}
func TestWireGuardAuthenticatedTCPUDPAndOwnerClose(t *testing.T) {
	cfg, n, _ := wireFixture(t)
	var protects atomic.Int32
	e, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { protects.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, host := range []string{"10.71.0.1", "fd71::1"} {
		target := wireTCPPeer(t, n, host)
		for i := 0; i < 16; i++ {
			c, err := e.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			payloadCheck(t, c)
		}
		h, p, _ := splitProtocolTarget(wireUDPPeer(t, n, host))
		stream, err := e.dialPacket(e.ctx, h, p)
		if err != nil {
			t.Fatal(err)
		}
		stream.SetDeadline(time.Now().Add(2 * time.Second))
		body := []byte("WireGuard encrypted UDP verified")
		if err = stream.WritePacket(body); err != nil {
			t.Fatal(err)
		}
		r, err := stream.ReadPacket()
		stream.Close()
		if err != nil || string(r.Payload) != string(body) {
			t.Fatal(r, err)
		}
	}
	if protects.Load() != 2 {
		t.Fatal("expected reused protected v4/v6 bind", protects.Load())
	}
	live, err := e.DialContext(context.Background(), "tcp", wireTCPPeer(t, n, "10.71.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("WireGuard owner close not joined", time.Since(start))
	}
	if _, err := live.Read(make([]byte, 1)); err == nil {
		t.Fatal("wireguard stream survived owner close")
	}
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}
func TestWireGuardAuthAndProtectionFailure(t *testing.T) {
	cfg, n, _ := wireFixture(t)
	h, p, _ := splitProtocolTarget(wireTCPPeer(t, n, "10.71.0.1"))
	c := cfg
	_, c.PublicKey = testWireKeys(t)
	c.ConnectTimeout = 100 * time.Millisecond
	start := time.Now()
	conn, err := Dial(context.Background(), c, h, p)
	if conn != nil {
		conn.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("bad peer key accepted or timeout unbounded", err)
	}
	ctx := WithHooks(context.Background(), Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
	conn, err = Dial(ctx, cfg, h, p)
	if conn != nil {
		conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "SOCKET_PROTECTION_FAILED") {
		t.Fatal(err)
	}
}
func TestWireGuardConfigBoundaries(t *testing.T) {
	cfg, _, _ := wireFixture(t)
	for _, option := range []string{"unknown", "local-address", "public-key", "preshared-key", "allowed-ips", "dns", "mtu", "keepalive"} {
		c := cfg
		c.Options = map[string]string{}
		for k, v := range cfg.Options {
			c.Options[k] = v
		}
		c.Options[option] = "invalid"
		if option == "public-key" {
			c.PublicKey = "invalid"
		}
		if c.Validate() == nil {
			t.Fatal("invalid", option)
		}
	}

}

func TestWireGuardServerNativeForwarderTCPUDPAndClose(t *testing.T) {
	serverPrivate, serverPublic := testWireKeys(t)
	clientPrivate, clientPublic := testWireKeys(t)
	e := testServerEngine(t)
	spec := ServerConfig{Protocol: "wireguard", Listen: "127.0.0.1:0", WireGuard: &WireGuardServerConfig{PrivateKey: serverPrivate, Peers: []WireGuardPeerConfig{{PublicKey: clientPublic, AllowedIPs: []string{"10.71.0.2/32", "fd71::2/128"}}}}}
	a, err := e.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseURI("wg://" + url.User(clientPrivate).String() + "@" + a.String() + "?public-key=" + url.QueryEscape(serverPublic) + "&local-address=10.71.0.2,fd71::2")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := echoPeer(t)
	for i := 0; i < 16; i++ {
		c, err := client.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		payloadCheck(t, c)
	}
	h, p, _ := splitProtocolTarget(udpEchoPeer(t))
	s, err := client.dialPacket(client.ctx, h, p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(3 * time.Second))
	body := []byte("native WireGuard UDP relay verified")
	if err = s.WritePacket(body); err != nil {
		t.Fatal(err)
	}
	r, err := s.ReadPacket()
	if err != nil || string(r.Payload) != string(body) {
		t.Fatal(r, err)
	}
	live, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	client.Close()
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("server owner close not joined", time.Since(start))
	}
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}

func TestWireGuardPresharedKeyAndEndpointIPv4Preference(t *testing.T) {
	cfg, n, dev := wireFixture(t)
	psk, _ := testWireKeys(t)
	key, _ := wireKey(psk)
	raw, _ := base64.StdEncoding.DecodeString(cfg.Password)
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if err = dev.IpcSet("public_key=" + fmt.Sprintf("%x", pub) + "\npreshared_key=" + key + "\n"); err != nil {
		t.Fatal(err)
	}
	cfg.Options["preshared-key"] = psk
	cfg.Server = "bootstrap.test"
	var calls atomic.Int32
	hooks := Hooks{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}, Protect: func(context.Context, int64) error { calls.Add(1); return nil }}
	h, p, _ := splitProtocolTarget(wireTCPPeer(t, n, "10.71.0.1"))
	conn, err := Dial(WithHooks(context.Background(), hooks), cfg, h, p)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	if calls.Load() != 2 {
		t.Fatal("working IPv4 launched an unnecessary IPv6 handshake", calls.Load())
	}
	wrong, _ := testWireKeys(t)
	cfg.Options["preshared-key"] = wrong
	cfg.ConnectTimeout = 100 * time.Millisecond
	cfg.Server = "127.0.0.1"
	conn, err = Dial(context.Background(), cfg, h, p)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("incorrect PSK accepted")
	}
}
func TestWireGuardDNSStaysInsideEncryptedPeer(t *testing.T) {
	cfg, n, _ := wireFixture(t)
	tcp := wireTCPPeer(t, n, "10.71.0.1")
	_, targetPort, _ := splitProtocolTarget(tcp)
	dns, err := n.ListenUDPAddrPort(netip.MustParseAddrPort("10.71.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	done := make(chan struct{})
	var queried atomic.Int32
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			count, a, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buf[:count]) != nil || len(request.Questions) != 1 {
				continue
			}
			q := request.Questions[0]
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions}
			if q.Type == dnsmessage.TypeA {
				queried.Add(1)
				answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{10, 71, 0, 1}}}}
			}
			body, _ := answer.Pack()
			dns.WriteTo(body, a)
		}
	}()
	cfg.Options["dns"] = "10.71.0.1"
	conn, err := Dial(context.Background(), cfg, "inside.test", targetPort)
	if err != nil {
		dns.Close()
		<-done
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	dns.Close()
	<-done
	if queried.Load() == 0 {
		t.Fatal("encrypted resolver not used")
	}
}

func TestWireGuardCacheAdmissionDoesNotEvictActivePeers(t *testing.T) {
	cache := newClientCache(context.Background())
	defer cache.Close()
	var closed atomic.Int32
	open := func(context.Context) (io.Closer, error) { return &countCloser{n: &closed}, nil }
	var leases []*clientLease
	for i := 0; i < 8; i++ {
		l, err := cache.get(context.Background(), "wireguard:"+itoa(i), open)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if _, err := cache.get(context.Background(), "wireguard:overflow", open); err == nil {
		t.Fatal("WireGuard cache exceeded eight active peers")
	}
	l, err := cache.get(context.Background(), "hysteria2:separate", open)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	leases[0].Close()
	l, err = cache.get(context.Background(), "wireguard:replacement", open)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if closed.Load() != 1 {
		t.Fatal("did not retire only the idle WireGuard peer", closed.Load())
	}
	for _, l := range leases {
		l.Close()
	}
	cache.Close()
	if closed.Load() != 10 {
		t.Fatal(closed.Load())
	}
}
