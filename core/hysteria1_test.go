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

func hy1Fixture(t *testing.T, obfs bool) (Config, *Engine) {
	t.Helper()
	cert, key := testServerCertificate(t)
	server := testServerEngine(t)
	opts := map[string]string{"upmbps": "100", "downmbps": "100"}
	query := "auth=test-auth&upmbps=100&downmbps=100"
	if obfs {
		opts["obfs"], opts["obfsparam"] = "xplus", "test-obfs"
		query += "&obfs=xplus&obfsParam=test-obfs"
	}
	a, err := server.StartServer(ServerConfig{Protocol: "hysteria", Listen: "127.0.0.1:0", Password: "test-auth", CertFile: cert, KeyFile: key, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseURI("hysteria://" + a.String() + "?" + query)
	if err != nil {
		t.Fatal(err)
	}
	c.CAFile = cert
	return c, server
}
func TestHysteria1ReusePayloadAndOwner(t *testing.T) {
	for _, obfs := range []bool{false, true} {
		t.Run(itoa(map[bool]int{false: 0, true: 1}[obfs]), func(t *testing.T) {
			cfg, server := hy1Fixture(t, obfs)
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
				t.Fatal("transport not reused", protected.Load())
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
			live.SetDeadline(time.Now().Add(5 * time.Second))
			writeAll(live, []byte("ready"))
			if _, err = io.ReadFull(live, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			server.Close()
			if time.Since(start) > time.Second {
				t.Fatal("slow owner close", time.Since(start))
			}
			if _, err = live.Read(make([]byte, 1)); err == nil {
				t.Fatal("stream survived owner")
			}
			client.Close()
			if server.Stats().Active != 0 || client.Stats().Active != 0 {
				t.Fatal("leaked flow budget")
			}
		})
	}
}
func TestHysteria1ConcurrentLargeAndReconnect(t *testing.T) {
	cfg, server := hy1Fixture(t, false)
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := echoPeer(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := client.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			body := bytes.Repeat([]byte("large"), 40000)
			if err = writeAll(c, body); err != nil {
				t.Error(err)
				return
			}
			got := make([]byte, len(body))
			if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, body) {
				t.Error("payload", err)
			}
		}()
	}
	wg.Wait()
	// Lose the physical session without stopping the client. A new dial must
	// create a fresh transport instead of burning through cached dead sessions.
	client.clients.mu.Lock()
	var peer *hy1Peer
	for _, entry := range client.clients.entries {
		if p, ok := entry.client.(*hy1Peer); ok {
			peer = p
		}
	}
	client.clients.mu.Unlock()
	if peer == nil {
		t.Fatal("client missing")
	}
	peer.Close()
	c, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, c)
	client.Close()
	server.Close()
}
func TestHysteria1RejectionsAndIPv4Fallback(t *testing.T) {
	cfg, _ := hy1Fixture(t, false)
	h, p, _ := splitProtocolTarget(echoPeer(t))
	for _, name := range []string{"auth", "trust", "pin", "protect"} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{"upmbps": "100", "downmbps": "100"}
			ctx := context.Background()
			switch name {
			case "auth":
				c.Password = "wrong"
			case "trust":
				c.CAFile = ""
			case "pin":
				c.Options["pinsha256"] = strings.Repeat("00", 32)
			case "protect":
				ctx = WithHooks(ctx, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
			}
			conn, err := Dial(ctx, c, h, p)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("accepted", name)
			}
		})
	}
	ctx := WithHooks(context.Background(), Hooks{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}})
	cfg.Server = "hy1.test"
	cfg.ServerName = "127.0.0.1"
	c, err := Dial(ctx, cfg, h, p)
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
	c, err = Dial(context.Background(), cfg, h, p)
	if c != nil {
		c.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("timeout", err)
	}
}
func TestHysteria1WireBounds(t *testing.T) {
	a, _ := Address("fragment.test", 443)
	body := bytes.Repeat([]byte{91}, 60000)
	frames, err := hy1Frames(7, 9, a, body)
	if err != nil {
		t.Fatal(err)
	}
	var df hy1Defrag
	var got Datagram
	var ready bool
	for i := len(frames) - 1; i >= 0; i-- {
		f, err := hy1ReadFragment(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		got, ready, err = df.add(f)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !ready || !bytes.Equal(got.Payload, body) || !bytes.Equal(got.Address, a) {
		t.Fatal("fragment mismatch")
	}
	f, _ := hy1ReadFragment(frames[0])
	df = hy1Defrag{}
	df.add(f)
	f, _ = hy1ReadFragment(frames[1])
	f.address, _ = Address("different.test", 443)
	if _, _, err = df.add(f); err == nil {
		t.Fatal("mixed fragment destinations")
	}
	for _, wire := range [][]byte{nil, {0, 0, 0, 1, 255, 255}, append(frames[0], 1)} {
		if _, err := hy1ReadFragment(wire); err == nil {
			t.Fatal("malformed packet")
		}
	}
	df = hy1Defrag{}
	f, _ = hy1ReadFragment(frames[0])
	for i := uint16(1); i <= 8; i++ {
		f.id = i
		if _, _, err = df.add(f); err != nil {
			t.Fatal(err)
		}
	}
	f.id = 9
	if _, _, err = df.add(f); err == nil {
		t.Fatal("fragment count unbounded")
	}
	if _, _, _, _, err = hy1ReadHello(bytes.NewReader(hy1Hello(3, 0, 1, "auth"))); err == nil {
		t.Fatal("zero rate")
	}
	if _, _, _, _, err = hy1ReadHello(bytes.NewReader(append(hy1Hello(3, 1, 1, "auth")[:17], 255, 255))); err == nil {
		t.Fatal("auth size")
	}
}
func TestHysteria1Validation(t *testing.T) {
	base := "hysteria://host.test:443?auth=a&upmbps=100&downmbps=100"
	if _, err := ParseURI(base); err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{base + "&auth=b", base + "&Auth=b", base + "&protocol=faketcp", base + "&obfs=xplus", base + "&fp=chrome", base + "&upmbps=0", base + "&hop=1", strings.Replace(base, ":443", "", 1)} {
		if _, err := ParseURI(uri); err == nil {
			t.Fatal("invalid URI accepted", uri)
		}
	}
}

func TestHysteria1ServerProtectionBudgetAndUDPPolicy(t *testing.T) {
	for _, mode := range []string{"protect", "budget", "udp-disabled"} {
		t.Run(mode, func(t *testing.T) {
			cert, key := testServerCertificate(t)
			cfg, _ := ParseURI("direct://")
			hooks := Hooks{}
			if mode == "budget" {
				cfg.MaxConnections = 1
			}
			if mode == "protect" {
				hooks.Protect = func(context.Context, int64) error { return errors.New("denied") }
			}
			server, err := NewEngine(context.Background(), cfg, hooks)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			opts := map[string]string{"upmbps": "100", "downmbps": "100"}
			if mode == "udp-disabled" {
				opts["disable-udp"] = "true"
			}
			addr, err := server.StartServer(ServerConfig{Protocol: "hysteria", Listen: "127.0.0.1:0", Password: "test-auth", CertFile: cert, KeyFile: key, Options: opts})
			if err != nil {
				t.Fatal(err)
			}
			c, err := ParseURI("hysteria://" + addr.String() + "?auth=test-auth&upmbps=100&downmbps=100")
			if err != nil {
				t.Fatal(err)
			}
			c.CAFile = cert
			client, err := NewEngine(context.Background(), c, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			target := echoPeer(t)
			if mode == "protect" {
				conn, err := client.DialContext(context.Background(), "tcp", target)
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Fatal("TCP bypassed socket protection")
				}
			} else {
				live, err := client.DialContext(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				defer live.Close()
				if mode == "budget" {
					other, err := client.DialContext(context.Background(), "tcp", target)
					if other != nil {
						other.Close()
					}
					if err == nil {
						t.Fatal("flow budget exceeded")
					}
				}
			}
			h, p, _ := splitProtocolTarget(udpEchoPeer(t))
			s, err := client.dialPacket(client.ctx, h, p)
			if mode == "protect" {
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				s.SetDeadline(time.Now().Add(time.Second))
				if err = s.WritePacket([]byte("protected")); err == nil {
					_, err = s.ReadPacket()
				}
				if err == nil {
					t.Fatal("UDP bypassed socket protection")
				}
			} else {
				if s != nil {
					s.Close()
				}
				if err == nil {
					t.Fatal("UDP policy/budget exceeded")
				}
			}
			client.Close()
			server.Close()
			if client.Stats().Active != 0 || server.Stats().Active != 0 {
				t.Fatal("budget leaked on rejection")
			}
		})
	}
}
func TestHysteria1AssociationLimitAndCancelledDatagram(t *testing.T) {
	cfg, _ := hy1Fixture(t, false)
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h, p, _ := splitProtocolTarget(udpEchoPeer(t))
	var list []PacketStream
	defer func() {
		for _, s := range list {
			s.Close()
		}
	}()
	for i := 0; i < 64; i++ {
		s, err := client.dialPacket(client.ctx, h, p)
		if err != nil {
			t.Fatal(i, err)
		}
		list = append(list, s)
	}
	s, err := client.dialPacket(client.ctx, h, p)
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Fatal("unbounded sessions")
	}
	peer, lease, err := getHy1(client.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = peer.conn.ProjectSendDatagramContext(ctx, []byte("cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatal("datagram ignored cancellation", err)
	}
	list[0].Close()
	// Closing one session must not close other sessions on the shared transport.
	checkHysteriaUDP(t, list[1])
}
