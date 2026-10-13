package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func sshFixture(t *testing.T, stall bool) (Config, string, func()) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userPriv)
	config := ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == "user" && string(p) == "secret" {
			return nil, nil
		}
		return nil, errors.New("auth rejected")
	}, PublicKeyCallback: func(c ssh.ConnMetadata, p ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() == "user" && string(p.Marshal()) == string(userSigner.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, errors.New("auth rejected")
	}}
	_ = public
	_ = userPub
	config.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	clients := map[net.Conn]bool{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			clients[raw] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer raw.Close()
				defer func() { mu.Lock(); delete(clients, raw); mu.Unlock() }()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				conn, channels, requests, err := ssh.NewServerConn(raw, &config)
				if err != nil {
					return
				}
				defer conn.Close()
				raw.SetDeadline(time.Time{})
				var handlers sync.WaitGroup
				handlers.Add(1)
				go func() { defer handlers.Done(); ssh.DiscardRequests(requests) }()
				for c := range channels {
					if c.ChannelType() != "direct-tcpip" {
						c.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					if stall {
						continue
					}
					channel, requests, err := c.Accept()
					if err != nil {
						continue
					}
					handlers.Add(2)
					go func() { defer handlers.Done(); ssh.DiscardRequests(requests) }()
					go func() { defer handlers.Done(); defer channel.Close(); io.Copy(channel, channel) }()
				}
				handlers.Wait()
			}()
		}
	}()
	closeServer := func() {
		once.Do(func() {
			close(stop)
			l.Close()
			mu.Lock()
			for c := range clients {
				c.Close()
			}
			mu.Unlock()
			workers.Wait()
		})
	}
	t.Cleanup(closeServer)
	cfg, err := ParseURI("ssh://user:secret@" + l.Addr().String() + "?hostkey=" + url.QueryEscape(ssh.FingerprintSHA256(signer.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(userPriv, "synthetic test key")
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(key, pem.EncodeToMemory(block), 0600)
	return cfg, key, closeServer
}
func TestSSHPayloadAuthKeysKnownHostsAndLifecycle(t *testing.T) {
	cfg, key, _ := sshFixture(t, false)
	for _, auth := range []string{"password", "private_key", "known_hosts"} {
		t.Run(auth, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{"hostkey": cfg.Options["hostkey"]}
			if auth == "private_key" {
				c.Password = ""
				c.Options["private-key"] = key
			}
			if auth == "known_hosts" {
				raw, _ := os.ReadFile(key)
				user, err := ssh.ParsePrivateKey(raw)
				if err != nil {
					t.Fatal(err)
				}
				_ = user
				// Use a separate key from the actual server's handshake by recording the
				// callback's verified public key without accepting an untrusted key.
				clientConf, _ := sshClientConfig(cfg)
				var serverKey ssh.PublicKey
				verify := clientConf.HostKeyCallback
				clientConf.HostKeyCallback = func(h string, a net.Addr, k ssh.PublicKey) error { serverKey = k; return verify(h, a, k) }
				rawConn, err := net.Dial("tcp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)))
				if err != nil {
					t.Fatal(err)
				}
				cc, _, _, err := ssh.NewClientConn(rawConn, rawConn.RemoteAddr().String(), clientConf)
				if err != nil {
					t.Fatal(err)
				}
				cc.Close()
				cc.Wait()
				path := filepath.Join(t.TempDir(), "known_hosts")
				os.WriteFile(path, []byte(knownhosts.Line([]string{net.JoinHostPort(cfg.Server, itoa(cfg.Port))}, serverKey)+"\n"), 0600)
				c.Options = map[string]string{"known-hosts": path}
			}
			var protects int
			e, err := NewEngine(context.Background(), c, Hooks{Protect: func(context.Context, int64) error { protects++; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			for i := 0; i < 16; i++ {
				conn, err := e.DialContext(context.Background(), "tcp", "target.test:443")
				if err != nil {
					t.Fatal(err)
				}
				payloadCheck(t, conn)
			}
			conn, err := e.DialContext(context.Background(), "tcp", "target.test:443")
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			e.Close()
			if time.Since(start) > time.Second {
				t.Fatal("SSH close not joined")
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("SSH survived owner close")
			}
			if protects != 17 || e.Stats().Active != 0 {
				t.Fatal(protects, e.Stats())
			}
		})
	}
}
func TestSSHRejectsTrustAuthProtectionAndUDP(t *testing.T) {
	cfg, _, _ := sshFixture(t, false)
	for _, test := range []string{"auth", "pin", "missing_key", "protect", "udp"} {
		t.Run(test, func(t *testing.T) {
			c := cfg
			c.Options = map[string]string{"hostkey": cfg.Options["hostkey"]}
			ctx := context.Background()
			if test == "auth" {
				c.Password = "wrong"
			}
			if test == "pin" {
				c.Options["hostkey"] = "SHA256:" + strings.Repeat("A", 43)
			}
			if test == "missing_key" {
				delete(c.Options, "hostkey")
			}
			if test == "protect" {
				ctx = WithHooks(ctx, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
			}
			if test == "udp" {
				s, err := DialPacket(ctx, c, "target.test", 443)
				if s != nil {
					s.Close()
				}
				if err == nil || err.Error() != "SSH_TCP_ONLY" {
					t.Fatal(err)
				}
				return
			}
			conn, err := Dial(ctx, c, "target.test", 443)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("SSH accepted invalid settings")
			}
		})
	}
}
func TestSSHChannelTimeout(t *testing.T) {
	cfg, _, closeServer := sshFixture(t, true)
	cfg.ConnectTimeout = 100 * time.Millisecond
	start := time.Now()
	conn, err := Dial(context.Background(), cfg, "target.test", 443)
	if conn != nil {
		conn.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("channel timeout not bounded", err, time.Since(start))
	}
	closeServer()
}
