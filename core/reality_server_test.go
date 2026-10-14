package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func realityServerTestConfig(t *testing.T, target string) RealityServerConfig {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return RealityServerConfig{PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ServerNames: []string{"localhost"}, ShortIDs: []string{"a1b2c3d4"}, Target: target}
}

func realityServerFixture(t *testing.T, flow bool) (Config, *Engine, *httptest.Server) {
	t.Helper()
	decoy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "configured decoy HTTPS body") }))
	t.Cleanup(decoy.Close)
	r := realityServerTestConfig(t, strings.TrimPrefix(decoy.URL, "https://"))
	e := testServerEngine(t)
	spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Reality: &r}
	if flow {
		spec.Options = map[string]string{"flow": vlessVisionFlow}
	}
	a, err := e.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, _ := decodeKey(r.PrivateKey)
	private, _ := ecdh.X25519().NewPrivateKey(privateBytes)
	uri := "vless://" + visionServerTestUUID + "@" + a.String() + "?security=reality&sni=localhost&fp=chrome&sid=a1b2c3d4&pbk=" + base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	if flow {
		uri += "&flow=" + vlessVisionFlow
	}
	cfg, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, e, decoy
}

func TestRealityServerProfilesTCPUDPAndOwnerClose(t *testing.T) {
	for _, flow := range []bool{false, true} {
		for _, fingerprint := range []string{"native", "chrome", "firefox", "safari", "ios", "edge", "qq"} {
			t.Run(itoa(boolInt(flow))+"/"+fingerprint, func(t *testing.T) {
				cfg, server, _ := realityServerFixture(t, flow)
				cfg.Fingerprint = fingerprint
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				target := echoPeer(t)
				for cycle := 0; cycle < 8; cycle++ {
					c, err := client.DialContext(context.Background(), "tcp", target)
					if err != nil {
						t.Fatalf("REALITY dial: %#v; rejected=%d", err, server.Stats().Rejected)
					}
					payloadCheck(t, c)
				}
				h, port, _ := splitProtocolTarget(udpEchoPeer(t))
				for cycle := 0; cycle < 4; cycle++ {
					p, err := client.dialPacket(client.ctx, h, port)
					if err != nil {
						t.Fatal(err)
					}
					checkHysteriaUDP(t, p)
					p.Close()
				}
				server.Close()
				client.Close()
				if server.Stats().Active != 0 || client.Stats().Active != 0 {
					t.Fatal("REALITY owner retained budget")
				}
			})
		}
	}
}

func TestRealityServerOrdinaryTLSFallbackPreservesHello(t *testing.T) {
	cfg, server, decoy := realityServerFixture(t, true)
	root := x509.NewCertPool()
	root.AddCert(decoy.Certificate())
	c, err := tls.Dial("tcp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)), &tls.Config{RootCAs: root, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err = writeAll(c, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "configured decoy HTTPS body" {
		t.Fatal("fallback bytes lost", err)
	}
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("fallback owner retained budget")
	}
}

func realityTestHello(t *testing.T, s *realityServerState, stamp int64, name string, id [8]byte) []byte {
	t.Helper()
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte{3, 3}, randomBytes(32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 2, 0x13, 1, 1, 0)
	names := join(word(3+len(name)), []byte{0}, word(len(name)), []byte(name))
	shares := join(word(36), word(29), word(32), sk.PublicKey().Bytes())
	ext := join(word(0), word(len(names)), names, word(43), word(3), []byte{2, 3, 4}, word(51), word(len(shares)), shares)
	body = append(body, word(len(ext))...)
	body = append(body, ext...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	shared, _ := sk.ECDH(s.private.PublicKey())
	auth, _ := hkdf.Key(sha256.New, shared, hello[6:26], "REALITY", 32)
	block, _ := aes.NewCipher(auth)
	gcm, _ := cipher.NewGCM(block)
	plain := make([]byte, 16)
	plain[0], plain[1], plain[2] = 26, 7, 28
	binary.BigEndian.PutUint32(plain[4:8], uint32(stamp))
	copy(plain[8:], id[:])
	sealed := gcm.Seal(nil, hello[26:38], plain, hello)
	copy(hello[39:71], sealed)
	return hello
}

func TestRealityServerAuthReplayTimestampAndBounds(t *testing.T) {
	cfg := realityServerTestConfig(t, "127.0.0.1:443")
	s, err := compileRealityServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	id := [8]byte{0xa1, 0xb2, 0xc3, 0xd4}
	hello := realityTestHello(t, s, now.Unix(), "localhost", id)
	if _, err = s.authenticate(hello, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.authenticate(hello, now); err == nil {
		t.Fatal("REALITY replay accepted")
	}
	corrupt := append([]byte(nil), hello...)
	corrupt[40] ^= 1
	for _, invalid := range [][]byte{corrupt, hello[:70], realityTestHello(t, s, now.Unix()-40, "localhost", id), realityTestHello(t, s, now.Unix()+40, "localhost", id), realityTestHello(t, s, now.Unix(), "foreign.test", id), realityTestHello(t, s, now.Unix(), "localhost", [8]byte{})} {
		if _, err := s.authenticate(invalid, now); err == nil {
			t.Fatal("invalid authentication admitted")
		}
	}
	s.mu.Lock()
	s.replay = map[[32]byte]time.Time{}
	for i := 0; i < 8192; i++ {
		s.replay[sha256.Sum256(wide(uint64(i)))] = now.Add(time.Minute)
	}
	s.mu.Unlock()
	fresh := realityTestHello(t, s, now.Unix(), "localhost", id)
	if _, err = s.authenticate(fresh, now); err == nil {
		t.Fatal("live replay cache evicted")
	}
	s.mu.Lock()
	for key := range s.replay {
		s.replay[key] = now.Add(-time.Second)
	}
	s.mu.Unlock()
	if _, err = s.authenticate(fresh, now); err != nil {
		t.Fatal("expired cache not reclaimed", err)
	}
}

func TestRealityServerFragmentedHelloAndTrailingBytes(t *testing.T) {
	s, _ := compileRealityServer(realityServerTestConfig(t, "127.0.0.1:443"))
	hello := realityTestHello(t, s, time.Now().Unix(), "localhost", [8]byte{0xa1, 0xb2, 0xc3, 0xd4})
	wire := join(shadowRecord(22, hello[:2]), shadowRecord(22, hello[2:61]), shadowRecord(22, append(append([]byte(nil), hello[61:]...), []byte("retained tail")...)))
	got, prefix, err := readRealityHello(bytes.NewReader(wire))
	if err != nil || !bytes.Equal(hello, got) || !bytes.Equal(prefix, wire) {
		t.Fatal("fragmented hello/tail lost", err)
	}
	for _, invalid := range [][]byte{{22, 3, 3, 0x40, 1}, {23, 3, 3, 0, 1, 0}, {22, 3, 3, 0, 4, 1, 0xff, 0xff, 0xff}} {
		if _, _, err = readRealityHello(bytes.NewReader(invalid)); err == nil {
			t.Fatal("oversized/wrong hello admitted")
		}
	}
}

func TestRealityServerFallbackProtectionAndInvalidConfig(t *testing.T) {
	base := realityServerTestConfig(t, "127.0.0.1:443")
	for _, mutate := range []func(*RealityServerConfig){
		func(c *RealityServerConfig) { c.PrivateKey = "bad" },
		func(c *RealityServerConfig) { c.ServerNames = nil },
		func(c *RealityServerConfig) { c.ShortIDs = []string{"a", "a1b2c3d40000000000"} },
		func(c *RealityServerConfig) { c.ShortIDs = []string{"", "00"} },
		func(c *RealityServerConfig) { c.ServerNames = []string{"localhost", "LOCALHOST"} },
		func(c *RealityServerConfig) { c.MaxTimeDiffMS = -1 },
		func(c *RealityServerConfig) { c.Target = "invalid" },
	} {
		bad := base
		mutate(&bad)
		if _, err := compileRealityServer(bad); err == nil {
			t.Fatal("invalid REALITY settings accepted")
		}
	}
	if _, err := compileServer(ServerConfig{Protocol: "ss", Reality: &base}); err == nil {
		t.Fatal("REALITY ignored on wrong protocol")
	}
	if _, err := compileServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Reality: &base, CertFile: "unused"}); err == nil {
		t.Fatal("conflicting TLS accepted")
	}
	var protects atomic.Int32
	cfg, _ := ParseURI("direct://")
	e, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { protects.Add(1); return errors.New("denied") }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Reality: &base})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	writeAll(c, []byte("invalid hello"))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("fallback bypassed protection")
	}
	e.Close()
	if protects.Load() != 1 || e.Stats().Active != 0 {
		t.Fatal("protected fallback/lifecycle", protects.Load(), e.Stats())
	}
}
