package core

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServerCertificate(t *testing.T) (string, string) {
	t.Helper()
	temporary := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer temporary.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: temporary.Certificate().Raw})
	key, err := x509.MarshalPKCS8PrivateKey(temporary.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, certificate, 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	return certPath, keyPath
}
func testServerEngine(t *testing.T) *Engine {
	t.Helper()
	c, _ := ParseURI("direct://")
	e, err := NewEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func TestVLESSAndTrojanServerTCPUDP(t *testing.T) {
	cert, key := testServerCertificate(t)
	for _, protocol := range []string{"vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			e := testServerEngine(t)
			spec := ServerConfig{Protocol: protocol, Listen: "127.0.0.1:0", UUIDs: []string{"12345678-1234-4567-9234-567812345678"}, Password: "server-secret", CertFile: cert, KeyFile: key}
			a, err := e.StartServer(spec)
			if err != nil {
				t.Fatal(err)
			}
			auth := "12345678-1234-4567-9234-567812345678"
			if protocol == "trojan" {
				auth = "server-secret"
			}
			config, err := ParseURI(protocol + "://" + auth + "@" + a.String() + "?security=tls")
			if err != nil {
				t.Fatal(err)
			}
			config.CAFile = cert
			target := echoPeer(t)
			host, p, _ := net.SplitHostPort(target)
			port, _ := number(p, 1, 65535)
			conn, err := Dial(context.Background(), config, host, port)
			if err != nil {
				t.Fatal(err)
			}
			payloadCheck(t, conn)
			u, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				b := make([]byte, 65535)
				for {
					n, a, err := u.ReadFrom(b)
					if err != nil {
						return
					}
					u.WriteTo(b[:n], a)
				}
			}()
			host, p, _ = net.SplitHostPort(u.LocalAddr().String())
			port, _ = number(p, 1, 65535)
			packets, err := DialPacket(context.Background(), config, host, port)
			if err != nil {
				t.Fatal(err)
			}
			packets.SetDeadline(time.Now().Add(3 * time.Second))
			if err = packets.WritePacket([]byte("server UDP verified")); err != nil {
				packets.Close()
				t.Fatal(err)
			}
			reply, err := packets.ReadPacket()
			packets.Close()
			if err != nil || string(reply.Payload) != "server UDP verified" {
				t.Fatal(reply, err)
			}
			u.Close()
			<-done
		})
	}
}
func TestShadowsocksServerLegacyAndAEADTCP(t *testing.T) {
	for _, method := range ssMethods {
		if strings.HasPrefix(method, "2022-") {
			continue
		}
		t.Run(method, func(t *testing.T) {
			e := testServerEngine(t)
			a, err := e.StartServer(ServerConfig{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: method, Password: "server-secret"})
			if err != nil {
				t.Fatal(err)
			}
			config, err := ParseURI("ss://" + method + ":server-secret@" + a.String())
			if err != nil {
				t.Fatal(err)
			}
			target := echoPeer(t)
			host, p, _ := net.SplitHostPort(target)
			port, _ := number(p, 1, 65535)
			conn, err := Dial(context.Background(), config, host, port)
			if err != nil {
				t.Fatal(err)
			}
			payloadCheck(t, conn)
		})
	}
}
func TestServerRejectsInvalidCredentialsAndReleasesBudget(t *testing.T) {
	e := testServerEngine(t)
	a, err := e.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{"12345678-1234-4567-9234-567812345678"}})
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := ParseURI("vless://00000000-0000-0000-0000-000000000000@" + a.String() + "?security=none")
	for i := 0; i < 32; i++ {
		conn, err := Dial(context.Background(), bad, "127.0.0.1", 1)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write([]byte("rejected"))
		var b [1]byte
		if _, err = conn.Read(b[:]); err == nil {
			t.Fatal("bad UUID accepted")
		}
		conn.Close()
	}
	deadline := time.Now().Add(time.Second)
	for e.Stats().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if e.Stats().Active != 0 {
		t.Fatal("rejected server clients retained", e.Stats())
	}
	e.Close()
	if conn, err := net.DialTimeout("tcp", a.String(), 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("server listener retained")
	}
	if _, err = e.StartServer(ServerConfig{Protocol: "trojan", Listen: "127.0.0.1:0", Password: "secret"}); err == nil {
		t.Fatal("Trojan plaintext server accepted")
	}
}
func TestServerUsesRoutingPolicy(t *testing.T) {
	c := RouterConfig{Outbounds: []OutboundConfig{{Tag: "deny", URI: "block://"}}, Final: "deny"}
	e, err := NewRouterEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{"12345678-1234-4567-9234-567812345678"}})
	if err != nil {
		t.Fatal(err)
	}
	config, _ := ParseURI("vless://12345678-1234-4567-9234-567812345678@" + a.String() + "?security=none")
	target := echoPeer(t)
	host, p, _ := net.SplitHostPort(target)
	port, _ := number(p, 1, 65535)
	conn, err := Dial(context.Background(), config, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("must not escape"))
	var reply [1]byte
	if _, err = conn.Read(reply[:]); err == nil {
		t.Fatal("blocked request returned a success response")
	}
}
