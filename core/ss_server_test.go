package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func ssServerTestSecret(method string, chain int) string {
	if !stringsHasModern(method) {
		return "synthetic server secret"
	}
	var keys []string
	for i := 0; i < chain; i++ {
		keys = append(keys, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 31)}, ssCipherSpec(method).key)))
	}
	return strings.Join(keys, ":")
}
func ssServerFixture(t *testing.T, method string, chain int, secure bool) (Config, *Engine) {
	t.Helper()
	e := testServerEngine(t)
	secret := ssServerTestSecret(method, chain)
	spec := ServerConfig{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: method, Password: secret}
	if secure {
		spec.CertFile, spec.KeyFile = testServerCertificate(t)
	}
	addr, err := e.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaults()
	cfg.Protocol, cfg.Transport, cfg.Security, cfg.Cipher, cfg.Password = "ss", "raw", "none", method, secret
	cfg.Server, cfg.Port, _ = splitProtocolTarget(addr.String())
	if secure {
		cfg.Security = "tls"
		cfg.CAFile = spec.CertFile
		cfg.ServerName = cfg.Server
	}
	return cfg, e
}
func TestSSServerAllMethodsNativeUDPOwnerClose(t *testing.T) {
	for _, method := range ssMethods {
		t.Run(method, func(t *testing.T) {
			cfg, server := ssServerFixture(t, method, 1, false)
			client, err := NewEngine(context.Background(), cfg, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			h, p, _ := splitProtocolTarget(udpEchoPeer(t))
			for cycle := 0; cycle < 4; cycle++ {
				s, err := client.dialPacket(client.ctx, h, p)
				if err != nil {
					t.Fatal(err)
				}
				s.SetDeadline(time.Now().Add(4 * time.Second))
				for _, size := range []int{1, 1400, 32000, 60000} {
					body := bytes.Repeat([]byte{byte(cycle + 11)}, size)
					if err = s.WritePacket(body); err != nil {
						t.Fatal(err)
					}
					got, err := s.ReadPacket()
					if err != nil || !bytes.Equal(body, got.Payload) {
						t.Fatal(method, size, err)
					}
				}
				s.Close()
			}
			server.Close()
			client.Close()
			if server.Stats().Active != 0 || client.Stats().Active != 0 {
				t.Fatal("SS UDP leaked ownership")
			}
		})
	}
}
func TestSS2022ServerTCPIdentityTLSAndRepeatedClose(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		chains := []int{1}
		if method != "2022-blake3-chacha20-poly1305" {
			chains = []int{1, 2, 3}
		}
		for _, chain := range chains {
			t.Run(method+"/"+itoa(chain), func(t *testing.T) {
				cfg, server := ssServerFixture(t, method, chain, false)
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				target := echoPeer(t)
				for cycle := 0; cycle < 16; cycle++ {
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
				s.SetDeadline(time.Now().Add(3 * time.Second))
				if err = s.WritePacket([]byte("identity UDP")); err != nil {
					t.Fatal(err)
				}
				got, err := s.ReadPacket()
				if err != nil || string(got.Payload) != "identity UDP" {
					t.Fatal(err)
				}
				s.Close()
				live, err := client.DialContext(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				defer live.Close()
				live.SetDeadline(time.Now().Add(2 * time.Second))
				live.Write([]byte("owner"))
				if _, err = io.ReadFull(live, make([]byte, 5)); err != nil {
					t.Fatal(err)
				}
				server.Close()
				if _, err = live.Read(make([]byte, 1)); err == nil {
					t.Fatal("SS TCP survived owner")
				}
				if server.Stats().Active != 0 {
					t.Fatal("SS TCP/UDP slots retained")
				}
			})
		}
	}
	cfg, _ := ssServerFixture(t, "2022-blake3-aes-128-gcm", 1, true)
	h, p, _ := splitProtocolTarget(echoPeer(t))
	c, err := Dial(context.Background(), cfg, h, p)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, c)
}

func TestSS2022ServerUDPReplayMigrationAndFullCone(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			cfg, server := ssServerFixture(t, method, 1, false)
			codec, _ := newSSUDP(cfg)
			first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			clientA, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			defer clientA.Close()
			clientB, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			defer clientB.Close()
			destination, _ := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Server, itoa(cfg.Port)))
			addr, _ := Address("127.0.0.1", first.LocalAddr().(*net.UDPAddr).Port)
			wire, _ := codec.encode(Datagram{addr, []byte("original")})
			clientA.WriteToUDP(wire, destination)
			buf := make([]byte, 65535)
			first.SetDeadline(time.Now().Add(2 * time.Second))
			n, source, err := first.ReadFromUDP(buf)
			if err != nil || string(buf[:n]) != "original" {
				t.Fatal(err)
			}
			clientB.WriteToUDP(wire, destination) // Replay must not change the return address.
			first.SetDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err = first.ReadFromUDP(buf); err == nil {
				t.Fatal("replayed packet forwarded")
			}
			second.WriteToUDP([]byte("full cone"), source)
			clientA.SetDeadline(time.Now().Add(2 * time.Second))
			n, _, err = clientA.ReadFromUDP(buf)
			if err != nil {
				t.Fatal(err)
			}
			got, err := codec.decode(buf[:n])
			if err != nil || string(got.Payload) != "full cone" {
				t.Fatal(err)
			}
			wire, _ = codec.encode(Datagram{addr, []byte("migrated")})
			clientB.WriteToUDP(wire, destination)
			first.SetDeadline(time.Now().Add(2 * time.Second))
			n, newSource, err := first.ReadFromUDP(buf)
			if err != nil || string(buf[:n]) != "migrated" || newSource.String() != source.String() {
				t.Fatal("session socket changed", err)
			}
			first.WriteToUDP([]byte("return to latest client"), source)
			clientB.SetDeadline(time.Now().Add(2 * time.Second))
			n, _, err = clientB.ReadFromUDP(buf)
			if err != nil {
				t.Fatal(err)
			}
			got, err = codec.decode(buf[:n])
			if err != nil || string(got.Payload) != "return to latest client" {
				t.Fatal(err)
			}
			server.Close()
			if server.Stats().Active != 0 {
				t.Fatal("migration leaked")
			}
		})
	}
}
func TestSS2022ServerHeaderReplayTamperingAndLimits(t *testing.T) {
	cfg := defaults()
	cfg.Protocol, cfg.Cipher, cfg.Password = "ss", "2022-blake3-aes-128-gcm", ssServerTestSecret("2022-blake3-aes-128-gcm", 1)
	s, _ := newSSServerState(cfg, nil)
	addr, _ := Address("target.test", 443)
	parse := func(wire []byte) error {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { defer server.Close(); _, _, err := ss2022ServerConn(server, s); done <- err }()
		client.SetDeadline(time.Now().Add(time.Second))
		writeAll(client, wire)
		client.Close()
		return <-done
	}
	p := newProtocol(cfg, false)
	wire, _ := p.open(addr)
	if err := parse(wire); err != nil {
		t.Fatal(err)
	}
	virtual, _ := Address(uotV2Host, 1)
	virtual[len(virtual)-1] = 0
	p = newProtocol(cfg, false)
	uotWire, _ := p.open(virtual)
	if err := parse(uotWire); err != nil {
		t.Fatal("valid UOT virtual port rejected", err)
	}
	if err := parse(wire); err == nil || !strings.Contains(err.Error(), "REPLAY") {
		t.Fatal("TCP salt replay", err)
	}
	for _, mode := range []string{"fixed", "variable"} {
		p = newProtocol(cfg, false)
		bad, _ := p.open(addr)
		offset := cfgKeySize(cfg)
		if mode == "variable" {
			offset = len(bad) - 1
		}
		bad[offset] ^= 1
		if err := parse(bad); err == nil {
			t.Fatal("corrupt header accepted")
		}
	}
	if err := parse([]byte{1}); err == nil {
		t.Fatal("partial initial read accepted")
	}
	s.mu.Lock()
	s.salts = map[[32]byte]time.Time{}
	for i := 0; i < 8192; i++ {
		var id [32]byte
		copy(id[:], wide(uint64(i)))
		s.salts[id] = time.Now().Add(time.Minute)
	}
	s.mu.Unlock()
	if err := s.rememberSalt([]byte("new")); err == nil {
		t.Fatal("live replay entries evicted")
	}
	for _, options := range []map[string]string{{"udp": "maybe"}, {"extra": "1"}} {
		if _, err := newSSServerState(cfg, options); err == nil {
			t.Fatal("bad server option")
		}
	}
}
func cfgKeySize(c Config) int { return ssCipherSpec(c.Cipher).key }

func TestSSServerUDPProtectionFailureAndDisabledListener(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	e, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	addr, err := e.StartServer(ServerConfig{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: "aes-256-gcm", Password: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	clientCfg := defaults()
	clientCfg.Transport, clientCfg.Security = "raw", "none"
	clientCfg.Protocol, clientCfg.Cipher, clientCfg.Password = "ss", "aes-256-gcm", "synthetic"
	clientCfg.Server, clientCfg.Port, _ = splitProtocolTarget(addr.String())
	client, err := NewEngine(context.Background(), clientCfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h, p, _ := splitProtocolTarget(udpEchoPeer(t))
	stream, err := client.dialPacket(client.ctx, h, p)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(150 * time.Millisecond))
	stream.WritePacket([]byte("denied"))
	if _, err = stream.ReadPacket(); err == nil {
		t.Fatal("unprotected relay")
	}
	e.Close()
	if e.Stats().Active != 0 {
		t.Fatal("protect leaked budget")
	}
	owner := testServerEngine(t)
	disabled, err := owner.StartServer(ServerConfig{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: "aes-256-gcm", Password: "synthetic", Options: map[string]string{"udp": "false"}})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", disabled.String())
	if err != nil {
		t.Fatal("disabled UDP bound a socket", err)
	}
	udp.Close()
}

func ssMalformedRequest(t *testing.T, c *ssUDP, kind byte, stamp int64, padding uint16) []byte {
	t.Helper()
	a, _ := Address("127.0.0.1", 443)
	separate := join(c.session, wide(0))
	body := join([]byte{kind}, wide(uint64(stamp)), word(int(padding)), a, []byte("payload"))
	if c.method() == "chacha20-poly1305" {
		nonce := randomBytes(24)
		wire, err := c.seal(c.master, nonce, join(separate, body), "xchacha20-ietf-poly1305")
		if err != nil {
			t.Fatal(err)
		}
		return append(nonce, wire...)
	}
	header, _ := aesECB(c.master, separate, false)
	key, _ := subkey(c.master, c.session, c.spec.key, true)
	wire, _ := c.seal(key, separate[4:], body, c.method())
	return append(header, wire...)
}
func TestSS2022UDPAdmissionBoundsCorruptionAndExpiry(t *testing.T) {
	routes := RouterConfig{MaxConnections: 512, Outbounds: []OutboundConfig{{Tag: "blocked", URI: "block://"}}, Final: "blocked"}
	e, err := NewRouterEngine(context.Background(), routes, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cfg := defaults()
	cfg.Protocol, cfg.Cipher, cfg.Password = "ss", "2022-blake3-aes-128-gcm", ssServerTestSecret("2022-blake3-aes-128-gcm", 1)
	state, _ := newSSServerState(cfg, nil)
	p, err := e.startSSUDP(state, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := newSSUDP(cfg)
	for _, invalid := range [][]byte{
		ssMalformedRequest(t, codec, 1, time.Now().Unix(), 0),
		ssMalformedRequest(t, codec, 0, time.Now().Unix()+40, 0),
		ssMalformedRequest(t, codec, 0, time.Now().Unix()-40, 0),
		ssMalformedRequest(t, codec, 0, time.Now().Unix(), 65535),
		{0},
	} {
		if _, err := state.decodeUDP(invalid); err == nil {
			t.Fatal("invalid UDP admitted")
		}
	}
	a, _ := Address("127.0.0.1", 443)
	for i := 0; i < 128; i++ {
		codec, _ = newSSUDP(cfg)
		wire, _ := codec.encode(Datagram{a, []byte("bounded")})
		packet, err := state.decodeUDP(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.admit(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000 + i}); err != nil {
			t.Fatal(err)
		}
	}
	codec, _ = newSSUDP(cfg)
	wire, _ := codec.encode(Datagram{a, []byte("over limit")})
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 1
	if _, err := state.decodeUDP(bad); err == nil {
		t.Fatal("corrupt packet authenticated")
	}
	packet, _ := state.decodeUDP(wire)
	if err = p.admit(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}); err == nil {
		t.Fatal("UDP peer cap ignored")
	}
	if e.Stats().Active != 128 {
		t.Fatal("shared budget", e.Stats())
	}
	p.expire(time.Now().Add(59 * time.Second))
	p.mu.Lock()
	count := len(p.peers)
	p.mu.Unlock()
	if count != 128 {
		t.Fatal("replay state expired before one minute")
	}
	p.expire(time.Now().Add(66 * time.Second))
	deadline := time.Now().Add(3 * time.Second)
	for e.Stats().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if e.Stats().Active != 0 {
		t.Fatal("expired UDP workers retained")
	}
	p.stop()
	e.Close()
}
func TestSSServerIPv6AndAtomicBindRollback(t *testing.T) {
	echo, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer echo.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr)
		}
	}()
	defer func() { echo.Close(); <-done }()
	cfg, server := ssServerFixture(t, "2022-blake3-aes-256-gcm", 1, false)
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, err := client.dialPacket(client.ctx, "::1", echo.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(2 * time.Second))
	stream.WritePacket([]byte("IPv6 payload"))
	got, err := stream.ReadPacket()
	if err != nil || string(got.Payload) != "IPv6 payload" {
		t.Fatal(err)
	}
	server.Close()
	// UDP's allocator may pick an occupied TCP port (including TIME_WAIT).
	// Reserve both transports before injecting the actual TCP listener into
	// the production dual-bind path, so only the intended UDP bind can fail.
	var reserved net.Listener
	var held net.PacketConn
	for trial := 0; trial < 8; trial++ {
		reserved, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		held, err = net.ListenPacket("udp4", reserved.Addr().String())
		if err == nil {
			break
		}
		reserved.Close()
	}
	if err != nil {
		t.Fatal("test dual-port reservation", err)
	}
	defer reserved.Close()
	defer held.Close()
	owner := testServerEngine(t)
	spec, err := compileServer(ServerConfig{Protocol: "ss", Listen: reserved.Addr().String(), Cipher: "aes-256-gcm", Password: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	listener, packets, err := owner.listenSSServer(spec.ss, reserved.Addr().String(), func(network, address string) (net.Listener, error) {
		calls++
		if network != "tcp" || address != reserved.Addr().String() {
			t.Fatal("fixed listen address changed")
		}
		return reserved, nil
	})
	var bindErr *net.OpError
	if !errors.As(err, &bindErr) || bindErr.Op != "listen" || bindErr.Net != "udp" || calls != 1 || listener != nil || packets != nil {
		t.Fatal("explicit UDP bind failure/attempt count", calls, err)
	}
	// A deadline bounds a broken rollback; only ErrClosed proves cleanup.
	reserved.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	if _, err = reserved.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed dual bind retained owned TCP listener", err)
	}
	owner.mu.Lock()
	_, tracked := owner.closers[reserved]
	owner.mu.Unlock()
	if tracked || owner.Stats().Active != 0 {
		t.Fatal("failed fixed-port bind retained owner resources")
	}
}

func TestSS2022StoppedPeerRetainsReplayWithoutRefresh(t *testing.T) {
	e := testServerEngine(t)
	cfg := defaults()
	cfg.Protocol, cfg.Cipher, cfg.Password = "ss", "2022-blake3-aes-128-gcm", ssServerTestSecret("2022-blake3-aes-128-gcm", 1)
	state, _ := newSSServerState(cfg, nil)
	p, err := e.startSSUDP(state, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	codec, _ := newSSUDP(cfg)
	a, _ := Address("127.0.0.1", 443)
	wire, _ := codec.encode(Datagram{a, []byte("first")})
	packet, _ := state.decodeUDP(wire)
	if err = p.admit(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	peer := p.peers[string(packet.clientID[:])]
	last, addr := peer.last.Load(), peer.address.Load()
	peer.cancel()
	p.mu.Unlock()
	wire, _ = codec.encode(Datagram{a, []byte("after stop")})
	packet, _ = state.decodeUDP(wire)
	if err = p.admit(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 10001}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("stopped relay accepted new packet", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.peers) != 1 || p.peers[string(packet.clientID[:])] != peer || peer.last.Load() != last || peer.address.Load() != addr {
		t.Fatal("stopped peer replay state was replaced or refreshed")
	}
}

func TestSSServerAutomaticDualPortCollisionRecoveryAndBound(t *testing.T) {
	for _, alwaysOccupied := range []bool{false, true} {
		t.Run(itoa(boolInt(alwaysOccupied)), func(t *testing.T) {
			e := testServerEngine(t)
			cfg := defaults()
			cfg.Cipher, cfg.Password = "aes-256-gcm", "synthetic"
			state, _ := newSSServerState(cfg, nil)
			var held []net.PacketConn
			defer func() {
				for _, socket := range held {
					socket.Close()
				}
			}()
			var collided []string
			calls := 0
			listen := func(network, address string) (net.Listener, error) {
				calls++
				if !alwaysOccupied && calls > 1 {
					return net.Listen(network, address)
				}
				// Reserve a real UDP port before supplying its TCP listener.
				// This deterministically reproduces the OS allocator collision.
				for trial := 0; trial < 8; trial++ {
					udp, err := net.ListenPacket("udp", address)
					if err != nil {
						return nil, err
					}
					tcp, err := net.Listen(network, udp.LocalAddr().String())
					if err == nil {
						held = append(held, udp)
						collided = append(collided, tcp.Addr().String())
						return tcp, nil
					}
					udp.Close()
				}
				return nil, errors.New("test port reservation failed")
			}
			listener, packets, err := e.listenSSServer(state, "127.0.0.1:0", listen)
			if alwaysOccupied {
				if err == nil || calls != 8 || listener != nil || packets != nil {
					t.Fatal("automatic bind was not bounded", calls, err)
				}
			} else {
				if err != nil || calls < 2 || calls > 8 || listener.Addr().String() != packets.conn.LocalAddr().String() {
					t.Fatal("automatic dual-port recovery", calls, err)
				}
				listener.Close()
				e.untrack(listener)
				packets.stop()
			}
			for _, addr := range collided {
				tcp, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatal("failed attempt retained TCP socket", err)
				}
				tcp.Close()
			}
			e.Close()
			if e.Stats().Active != 0 {
				t.Fatal("failed bind retained flow budget")
			}
		})
	}
}
func TestSSServerCountersCannotWrap(t *testing.T) {
	cfg := defaults()
	cfg.Protocol, cfg.Cipher, cfg.Password = "ss", "2022-blake3-aes-128-gcm", ssServerTestSecret("2022-blake3-aes-128-gcm", 1)
	s, _ := newSSServerState(cfg, nil)
	var buf bytes.Buffer
	w, _ := newSSServerChunks(&buf, s, bytes.Repeat([]byte{1}, 16))
	r, _ := newSSServerChunks(&buf, s, bytes.Repeat([]byte{1}, 16))
	for i := range w.nonce {
		w.nonce[i] = 255
		r.nonce[i] = 255
	}
	wire, err := w.seal([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(wire)
	if _, err := r.open(1); err != nil {
		t.Fatal(err)
	}
	if _, err := w.seal([]byte{1}); err == nil {
		t.Fatal("write nonce wrap")
	}
	if _, err := r.open(1); err == nil {
		t.Fatal("read nonce wrap")
	}
	peer := ssUDPServerPeer{server: &ssUDPServer{state: s}, counter: ^uint64(0)}
	if _, err = peer.encode(Datagram{}); err == nil {
		t.Fatal("UDP packet ID wrap")
	}
}

func TestSS2022MigrationRetainsSourceRoutingForProxy(t *testing.T) {
	remote := testServerEngine(t)
	remote.config.ListenPort = 0
	proxy, err := remote.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	routes := RouterConfig{Outbounds: []OutboundConfig{{Tag: "proxy", URI: "socks5://" + proxy.String()}, {Tag: "blocked", URI: "block://"}},
		Rules: []RouteRule{{SourceCIDRs: []string{"127.0.0.1/32"}, Outbound: "proxy"}}, Final: "blocked"}
	server, err := NewRouterEngine(context.Background(), routes, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	method := "2022-blake3-aes-128-gcm"
	key := ssServerTestSecret(method, 1)
	listen, err := server.StartServer(ServerConfig{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: method, Password: key})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer first.Close()
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skip("second loopback address unavailable")
	}
	defer second.Close()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	cfg := defaults()
	cfg.Protocol, cfg.Cipher, cfg.Password = "ss", method, key
	codec, _ := newSSUDP(cfg)
	address, _ := Address("127.0.0.1", sink.LocalAddr().(*net.UDPAddr).Port)
	dest, _ := net.ResolveUDPAddr("udp4", listen.String())
	buf := make([]byte, 65535)
	for cycle, source := range []*net.UDPConn{first, second, first} {
		wire, _ := codec.encode(Datagram{address, []byte("source policy")})
		source.WriteToUDP(wire, dest)
		sink.SetDeadline(time.Now().Add(time.Second))
		if cycle == 1 {
			sink.SetDeadline(time.Now().Add(150 * time.Millisecond))
		}
		n, from, err := sink.ReadFromUDP(buf)
		if cycle == 1 {
			if err == nil {
				t.Fatal("source CIDR block bypassed cached proxy")
			}
			continue
		}
		if err != nil || string(buf[:n]) != "source policy" {
			t.Fatal("proxy source metadata lost", err)
		}
		sink.WriteToUDP(buf[:n], from)
		source.SetDeadline(time.Now().Add(time.Second))
		n, _, err = source.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := codec.decode(buf[:n])
		if err != nil || string(packet.Payload) != "source policy" {
			t.Fatal(err)
		}
	}
	server.Close()
	remote.Close()
	if server.Stats().Active != 0 || remote.Stats().Active != 0 {
		t.Fatal("proxy migration leak")
	}
}
