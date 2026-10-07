package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// The external fixture is an independent Python/OpenSSL TLS endpoint. Fixed
// seeds exercise randomized ClientHello variations reproducibly.
func TestRandomizedOpenSSLProfiles(t *testing.T) {
	endpoint, caPath := os.Getenv("VPN_CORE_TLS_TEST_SERVER"), os.Getenv("VPN_CORE_TLS_TEST_CA")
	if endpoint == "" || caPath == "" {
		t.Skip("external OpenSSL fixture not requested")
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("test CA")
	}
	for _, name := range []string{"randomized", "randomizednoalpn"} {
		for i := 0; i < 256; i++ {
			id, _ := profile(name)
			hash := sha256.Sum256([]byte(fmt.Sprintf("project-randomized-profile-%d", i)))
			seed := utls.PRNGSeed(hash)
			id.Seed = &seed
			cfg := &utls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: utls.VersionTLS12, NextProtos: []string{"http/1.1"}}
			conn, err := net.DialTimeout("tcp", endpoint, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			u := utls.UClient(conn, cfg, id)
			if err = u.BuildHandshakeState(); err != nil {
				_ = conn.Close()
				t.Fatalf("seed %d build: %v", i, err)
			}
			if err = enforceTLSVersions(u, cfg, utls.VersionTLS12); err != nil {
				_ = conn.Close()
				t.Fatalf("seed %d version policy: %v", i, err)
			}
			if cfg.MaxVersion != utls.VersionTLS13 {
				t.Fatalf("profile %s seed %d does not offer TLS 1.3", name, i)
			}
			if name == "randomizednoalpn" {
				for _, extension := range u.Extensions {
					if _, ok := extension.(*utls.ALPNExtension); ok {
						t.Fatalf("profile %s seed %d offered ALPN", name, i)
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = u.HandshakeContext(ctx)
			cancel()
			if err != nil {
				_ = conn.Close()
				t.Errorf("profile %s seed %d handshake (maximum %x): %v", name, i, cfg.MaxVersion, err)
				continue
			}
			if !permittedCipher(u.ConnectionState().CipherSuite) {
				t.Errorf("seed %d cipher policy", i)
			}
			message := []byte("randomized-profile-tls-test")
			_ = u.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = u.Write(message); err != nil {
				t.Fatalf("profile %s seed %d write: %v", name, i, err)
			}
			echo := make([]byte, len(message))
			if _, err = io.ReadFull(u, echo); err != nil || !bytes.Equal(echo, message) {
				t.Fatalf("profile %s seed %d data transfer: %v", name, i, err)
			}
			_ = u.Close()
			_ = conn.Close()
		}
	}
}
