package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const tuicTestUUID = "12345678-1234-4567-9234-567812345678"

func tuicFixture(t *testing.T, mode string) (Config, *Engine) {
	t.Helper()
	cert, key := testServerCertificate(t)
	server := testServerEngine(t)
	a, err := server.StartServer(ServerConfig{Protocol: "tuic", Listen: "127.0.0.1:0", UUIDs: []string{tuicTestUUID}, Password: "test-auth", CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseURI("tuic://" + tuicTestUUID + ":test-auth@" + a.String() + "?udp-relay-mode=" + mode)
	if err != nil {
		t.Fatal(err)
	}
	c.CAFile = cert
	return c, server
}

func TestTUICFullConeRoutingProtectionAndPortReuse(t *testing.T) {
	var protected atomic.Int32
	cfg, _ := ParseURI("direct://")
	e, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { protected.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	b := newTUICRelay(e.ctx, e, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	defer b.Close()
	var sockets []net.PacketConn
	var port int
	for i := 0; i < 2; i++ {
		s, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		sockets = append(sockets, s)
		if _, err = b.WriteTo([]byte("full cone"), s.LocalAddr().String()); err != nil {
			t.Fatal(err)
		}
		s.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 100)
		_, source, err := s.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		_, p, _ := splitProtocolTarget(source.String())
		if i == 0 {
			port = p
		} else if p != port {
			t.Fatal("UDP source port changed between destinations")
		}
		// A second, previously unused source sends a reply to the same socket.
		other, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		other.WriteTo([]byte("unsolicited reply"), source)
		other.Close()
		buf = make([]byte, 100)
		n, _, err := b.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "unsolicited reply" {
			t.Fatal(err)
		}
	}
	if protected.Load() != 1 {
		t.Fatal("direct socket not protected/reused", protected.Load())
	}
	b.Close()
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
	// Existing associations re-evaluate a new block policy instead of reusing
	// the direct socket to bypass it.
	routes := RouterConfig{Outbounds: []OutboundConfig{{Tag: "d", URI: "direct://"}, {Tag: "b", URI: "block://"}}, Final: "d"}
	r, err := NewRouterEngine(context.Background(), routes, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	relay := newTUICRelay(r.ctx, r, nil)
	defer relay.Close()
	addr := sockets[0].LocalAddr().String()
	if _, err = relay.WriteTo([]byte("allowed"), addr); err != nil {
		t.Fatal(err)
	}
	routes.Final = "b"
	if err = r.Router().Reload(routes); err != nil {
		t.Fatal(err)
	}
	if _, err = relay.WriteTo([]byte("blocked"), addr); err == nil {
		t.Fatal("existing direct socket bypassed block policy")
	}
}
func TestTUICConcurrentLargeTCPAndClientOwnerClose(t *testing.T) {
	cfg, _ := tuicFixture(t, "native")
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	target := echoPeer(t)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := e.DialContext(context.Background(), "tcp", target)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			body := bytes.Repeat([]byte("large TUIC\x00\xff"), 32768)
			done := make(chan error, 1)
			go func() { done <- writeAll(c, body) }()
			reply := make([]byte, len(body))
			_, err = io.ReadFull(c, reply)
			if err == nil && !bytes.Equal(body, reply) {
				err = errors.New("payload mismatch")
			}
			if x := <-done; err == nil {
				err = x
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	conn, err := e.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("client owner did not join promptly")
	}
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("live stream survived client Close")
	}
}
func TestTUICReuseTCPUDPAndClose(t *testing.T) {
	for _, mode := range []string{"native", "quic"} {
		t.Run(mode, func(t *testing.T) {
			cfg, server := tuicFixture(t, mode)
			var protected atomic.Int32
			client, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { protected.Add(1); return nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			target := echoPeer(t)
			for i := 0; i < 32; i++ {
				c, err := client.DialContext(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(i, err)
				}
				payloadCheck(t, c)
			}
			if protected.Load() != 1 {
				t.Fatal("QUIC transport was not reused", protected.Load())
			}
			h, p, _ := splitProtocolTarget(udpEchoPeer(t))
			for i := 0; i < 8; i++ {
				s, err := client.dialPacket(client.ctx, h, p)
				if err != nil {
					t.Fatal(err)
				}
				checkHysteriaUDP(t, s)
			}
			live, err := client.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer live.Close()
			if err = writeAll(live, []byte("ready")); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadFull(live, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			server.Close()
			if time.Since(start) > time.Second {
				t.Fatal("server Close did not join promptly", time.Since(start))
			}
			live.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = live.Read(make([]byte, 1)); err == nil {
				t.Fatal("stream survived owner shutdown")
			}
			client.Close()
			if server.Stats().Active != 0 || client.Stats().Active != 0 {
				t.Fatal("flow budget leaked")
			}
		})
	}
}
func TestTUICAuthTrustProtectionTimeoutAndFallback(t *testing.T) {
	cfg, _ := tuicFixture(t, "native")
	host, port, _ := splitProtocolTarget(echoPeer(t))
	for _, name := range []string{"auth", "uuid", "trust", "pin", "protect"} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{}
			ctx := context.Background()
			switch name {
			case "auth":
				c.Password = "wrong"
			case "uuid":
				c.UUID[0] ^= 1
			case "trust":
				c.CAFile = ""
			case "pin":
				c.Options["pinsha256"] = strings.Repeat("00", 32)
			case "protect":
				ctx = WithHooks(ctx, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
			}
			conn, err := Dial(ctx, c, host, port)
			if conn != nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				err = writeAll(conn, []byte("must not relay"))
				if err == nil {
					_, err = conn.Read(make([]byte, 1))
				}
			}
			if err == nil {
				t.Fatal("rejected settings relayed data", name)
			}
		})
	}
	ctx := WithHooks(context.Background(), Hooks{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}})
	cfg.Server = "tuic.test"
	cfg.ServerName = "127.0.0.1"
	c, err := Dial(ctx, cfg, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, c)
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
		t.Fatal("handshake timeout", err, time.Since(start))
	}
}
func TestTUICFragmentsAndAssociationBounds(t *testing.T) {
	a, _ := Address("fragment.test", 443)
	body := bytes.Repeat([]byte{37}, 60000)
	frames, err := tuicPacketFrames(5, 9, a, body, true)
	if err != nil {
		t.Fatal(err)
	}
	var d tuicDefrag
	var packet Datagram
	ready := false
	for i := len(frames) - 1; i >= 0; i-- {
		f, err := readTUICFragment(bytes.NewReader(frames[i][2:]))
		if err != nil {
			t.Fatal(err)
		}
		packet, ready, err = d.add(f)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !ready || !bytes.Equal(packet.Payload, body) || !bytes.Equal(packet.Address, a) {
		t.Fatal("reordered fragmentation failed")
	}
	bad := append([]byte(nil), frames[0][2:]...)
	bad[4] = 0
	if _, err = readTUICFragment(bytes.NewReader(bad)); err == nil {
		t.Fatal("zero fragments accepted")
	}
	cfg, _ := tuicFixture(t, "native")
	p, err := newTUICClient(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	peer := p.(*tuicPeer)
	defer peer.Close()
	for i := 0; i < 64; i++ {
		if _, err = peer.association(uint16(i), true, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = peer.association(64, true, true); err == nil {
		t.Fatal("association limit bypassed")
	}
	first, _ := peer.association(0, true, false)
	first.Close()
	if a, err := peer.association(0, true, true); err != nil || a != nil {
		t.Fatal("retired association resurrected", err)
	}
	for _, uri := range []string{"tuic://bad:p@127.0.0.1", "tuic://" + tuicTestUUID + ":p@127.0.0.1?udp-relay-mode=invalid", "tuic://" + tuicTestUUID + ":p@127.0.0.1?unknown=1", "tuic://" + tuicTestUUID + ":p@127.0.0.1?fp=invalid"} {
		if _, err = ParseURI(uri); err == nil {
			t.Fatal(uri)
		}
	}
}
