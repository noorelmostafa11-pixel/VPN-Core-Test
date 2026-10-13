package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func shadowFixture(t *testing.T, version string) (Config, *Engine) {
	t.Helper()
	cert, _ := testServerCertificate(t)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "synthetic handshake web server") }))
	backend.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	backend.StartTLS()
	t.Cleanup(backend.Close)
	server := testServerEngine(t)
	a, err := server.StartServer(ServerConfig{Protocol: "shadowtls", Listen: "127.0.0.1:0", Password: "shadow-auth", Cipher: "aes-256-gcm", Options: map[string]string{"version": version, "handshake": strings.TrimPrefix(backend.URL, "https://"), "ss-password": "ss-auth", "uot": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseURI("shadowtls://shadow-auth@" + a.String() + "?version=" + version + "&method=aes-256-gcm&ss-password=ss-auth&uot=2&sni=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	c.CAFile = cert
	return c, server
}
func TestShadowTLSBothVersionsTCPUDPAndOwnerClose(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			cfg, server := shadowFixture(t, version)
			client, err := NewEngine(context.Background(), cfg, Hooks{})
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
			h, p, _ := splitProtocolTarget(udpEchoPeer(t))
			s, err := client.dialPacket(client.ctx, h, p)
			if err != nil {
				t.Fatal(err)
			}
			checkHysteriaUDP(t, s)
			live, err := client.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer live.Close()
			writeAll(live, []byte("ready"))
			if _, err = io.ReadFull(live, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			server.Close()
			if time.Since(start) > time.Second {
				t.Fatal("server Close not joined", time.Since(start))
			}
			live.SetDeadline(time.Now().Add(time.Second))
			if _, err = live.Read(make([]byte, 1)); err == nil {
				t.Fatal("stream survived server loss")
			}
			client.Close()
			if server.Stats().Active != 0 {
				t.Fatal(server.Stats())
			}
		})
	}
}
func TestShadowTLSAuthTrustProtectionAndTimeout(t *testing.T) {
	cfg, _ := shadowFixture(t, "3")
	h, p, _ := splitProtocolTarget(echoPeer(t))
	for _, name := range []string{"auth", "trust", "pin", "protect"} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{}
			for k, v := range cfg.Options {
				c.Options[k] = v
			}
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
				t.Fatal("invalid settings accepted", name)
			}
		})
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	cfg.Server, cfg.Port, _ = splitProtocolTarget(l.Addr().String())
	cfg.ConnectTimeout = 100 * time.Millisecond
	start := time.Now()
	c, err := Dial(context.Background(), cfg, h, p)
	if c != nil {
		c.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("handshake timeout", err)
	}
	<-done
}
func TestShadowTLSRejectsTamperingReplayAndSlicing(t *testing.T) {
	for _, mode := range []string{"tamper", "replay", "slice"} {
		t.Run(mode, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			sr := bytes.Repeat([]byte{7}, 32)
			sender := shadowMAC("auth", sr, []byte("S"))
			receiver := shadowMAC("auth", sr, []byte("S"))
			body := []byte("integrity payload")
			tag := shadowTag(sender, body, true)
			frame := shadowRecord(23, append(append([]byte(nil), tag...), body...))
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer right.Close()
				writeAll(right, frame)
				bad := append([]byte(nil), frame...)
				switch mode {
				case "tamper":
					bad[len(bad)-1] ^= 1
				case "slice":
					bad = shadowRecord(23, bad[5:len(bad)-1])
				}
				writeAll(right, bad)
				io.Copy(io.Discard, right)
			}()
			c := &shadowConn{Conn: left, version: 3, readMAC: receiver}
			buf := make([]byte, len(body))
			if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, body) {
				t.Fatal(err)
			}
			if _, err := c.Read(buf); err == nil || !strings.Contains(err.Error(), "INTEGRITY") {
				t.Fatal("invalid record accepted", err)
			}
			wg.Wait()
		})
	}
}

func TestShadowTLSStrictServerHelloVersion(t *testing.T) {
	body := make([]byte, 39)
	body[0] = 2
	body[4], body[5] = 3, 3
	body[38] = 0
	body = append(body, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	frame := shadowRecord(22, body)
	if !shadowTLS13(frame) {
		t.Fatal("TLS 1.3 ServerHello rejected")
	}
	frame[len(frame)-1] = 3
	if shadowTLS13(frame) {
		t.Fatal("TLS 1.2 accepted as strict v3")
	}
	if shadowTLS13(frame[:43]) {
		t.Fatal("truncated ServerHello accepted")
	}
}
