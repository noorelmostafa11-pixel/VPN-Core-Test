package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func anyFixture(t *testing.T, scheme string) (Config, *Engine) {
	t.Helper()
	cert, key := testServerCertificate(t)
	server := testServerEngine(t)
	options := map[string]string{}
	if scheme != "" {
		options["padding-scheme"] = scheme
	}
	addr, err := server.StartServer(ServerConfig{Protocol: "anytls", Listen: "127.0.0.1:0", Password: "test-auth", CertFile: cert, KeyFile: key, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseURI("anytls://test-auth@" + addr.String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = cert
	return cfg, server
}
func TestAnyTLSReuseTCPUDPAndUpdatedPadding(t *testing.T) {
	cfg, _ := anyFixture(t, "stop=3\n0=40-50\n1=180-240\n2=800-900,c,900-1000")
	var protects atomic.Int32
	client, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { protects.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := echoPeer(t)
	for i := 0; i < 32; i++ {
		conn, err := client.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(i, err)
		}
		payloadCheck(t, conn)
	}
	if protects.Load() != 1 {
		t.Fatal("idle AnyTLS transport was not reused", protects.Load())
	}
	h, p, _ := splitProtocolTarget(udpEchoPeer(t))
	packets, err := client.dialPacket(client.ctx, h, p)
	if err != nil {
		t.Fatal(err)
	}
	checkHysteriaUDP(t, packets)
	conn, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	client.Close()
	if time.Since(start) > time.Second {
		t.Fatal("AnyTLS Close did not join")
	}
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("live stream survived owner close")
	}
	if client.Stats().Active != 0 {
		t.Fatal(client.Stats())
	}
}
func TestAnyTLSUOTNonConnectMultipleTargets(t *testing.T) {
	cfg, _ := anyFixture(t, "")
	conn, err := dialAnyTLS(context.Background(), cfg, uotV2Host, 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = writeAll(conn, []byte{0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	packets := &uotPackets{Conn: conn, connect: false}
	for i := 0; i < 4; i++ {
		h, p, _ := splitProtocolTarget(udpEchoPeer(t))
		packets.address, _ = Address(h, p)
		packets.SetDeadline(time.Now().Add(3 * time.Second))
		body := []byte("independent UOT destination")
		if err = packets.WritePacket(body); err != nil {
			t.Fatal(err)
		}
		reply, err := packets.ReadPacket()
		if err != nil || string(reply.Payload) != string(body) {
			t.Fatal(reply, err)
		}
	}
}
func TestAnyTLSRejectsAuthTrustProtectionAndRemoteDial(t *testing.T) {
	cfg, _ := anyFixture(t, "")
	for _, name := range []string{"auth", "trust", "pin", "protect", "destination"} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{}
			ctx := context.Background()
			port := 80
			if name == "auth" {
				c.Password = "wrong"
			}
			if name == "trust" {
				c.CAFile = ""
			}
			if name == "pin" {
				c.Options["pinsha256"] = strings.Repeat("00", 32)
			}
			if name == "protect" {
				ctx = WithHooks(ctx, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
			}
			if name == "destination" {
				port = 9
			}
			conn, err := Dial(ctx, c, "127.0.0.1", port)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("invalid AnyTLS connection accepted", name)
			}
		})
	}
}
func TestAnyTLSReadDeadlineAndSessionOwnerShutdown(t *testing.T) {
	cfg, server := anyFixture(t, "")
	h, p, _ := splitProtocolTarget(echoPeer(t))
	conn, err := Dial(context.Background(), cfg, h, p)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Time{})
	payloadCheck(t, conn)
	start := time.Now()
	server.Close()
	if time.Since(start) > time.Second {
		t.Fatal("AnyTLS server shutdown not joined")
	}
}
func TestAnyTLSPaddingAndURIInputLimits(t *testing.T) {
	for _, text := range []string{"stop=99", "stop=8\nstop=2", "stop=8\n0=c", "stop=8\n1=0-99999", "stop=8\n2=9-1", "stop=8\n2=16000-16000,16000-16000,16000-16000,16000-16000,16000-16000"} {
		if _, err := parseAnyPadding(text); err == nil {
			t.Fatal(text)
		}
	}
	for _, uri := range []string{"anytls://@127.0.0.1", "anytls://password@127.0.0.1?unknown=value", "anytls://password@127.0.0.1/path", "anytls://password@127.0.0.1?peer=a&peer=b"} {
		if _, err := ParseURI(uri); err == nil {
			t.Fatal(uri)
		}
	}
	cfg, _ := anyFixture(t, "")
	cfg.ConnectTimeout = 30 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	h, p, _ := splitProtocolTarget(listener.Addr().String())
	cfg.Server, cfg.Port = h, p
	start := time.Now()
	conn, err := Dial(context.Background(), cfg, "127.0.0.1", 80)
	if conn != nil {
		conn.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("TLS handshake timeout", err)
	}
}

func TestAnyTLSLargePayloadAndConcurrentSessionReuse(t *testing.T) {
	cfg, _ := anyFixture(t, "")
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := echoPeer(t)
	var workers sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			conn, err := client.DialContext(context.Background(), "tcp", target)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			body := []byte(strings.Repeat("large concurrent AnyTLS\x00\xff", 32768))
			done := make(chan error, 1)
			go func() { done <- writeAll(conn, body) }()
			reply := make([]byte, len(body))
			_, err = io.ReadFull(conn, reply)
			if err != nil {
				conn.Close()
			}
			sendErr := <-done
			if err == nil {
				err = sendErr
			}
			if err == nil && string(body) != string(reply) {
				err = errors.New("AnyTLS payload mismatch")
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
func TestAnyTLSVersionOneServerAndMonotonicReuse(t *testing.T) {
	cfg, _ := anyFixture(t, "")
	conn, err := proxySocket(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	auth := sha256.Sum256([]byte(cfg.Password))
	if err = writeAll(conn, append(auth[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
	scheme, _ := parseAnyPadding(anyDefaultPadding)
	if err = writeAll(conn, anyFrame(anySettings, 0, []byte("v=1\nclient=independent-test\npadding-md5="+scheme.hash))); err != nil {
		t.Fatal(err)
	}
	h, p, _ := splitProtocolTarget(echoPeer(t))
	address, _ := Address(h, p)
	for id := uint32(1); id <= 4; id++ {
		body := []byte("AnyTLS version one verified")
		wire := append(anyFrame(anySYN, id, nil), anyFrame(anyPSH, id, address)...)
		wire = append(wire, anyFrame(anyPSH, id, body)...)
		if err = writeAll(conn, wire); err != nil {
			t.Fatal(err)
		}
		var reply []byte
		for len(reply) < len(body) {
			var header [7]byte
			if _, err = io.ReadFull(conn, header[:]); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, binary.BigEndian.Uint16(header[5:]))
			if _, err = io.ReadFull(conn, data); err != nil {
				t.Fatal(err)
			}
			if header[0] == anySYNACK || header[0] == anyServerSettings {
				t.Fatal("v2 command sent to v1 client")
			}
			if header[0] == anyPSH && binary.BigEndian.Uint32(header[1:]) == id {
				reply = append(reply, data...)
			}
		}
		if string(reply) != string(body) {
			t.Fatal("v1 payload mismatch")
		}
		if err = writeAll(conn, anyFrame(anyFIN, id, nil)); err != nil {
			t.Fatal(err)
		}
	}
}
