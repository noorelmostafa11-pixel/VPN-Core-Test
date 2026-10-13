package core

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshServerKey(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host-key")
	if err = os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return path, signer
}

func TestSSHServerProtectionAndSharedChannelBudget(t *testing.T) {
	key, signer := sshServerKey(t)
	spec := ServerConfig{Protocol: "ssh", Listen: "127.0.0.1:0", Password: "secret", KeyFile: key, Options: map[string]string{"username": "user"}}
	for _, protection := range []bool{false, true} {
		cfg, _ := ParseURI("direct://")
		cfg.MaxConnections = 1
		hooks := Hooks{}
		if protection {
			hooks.Protect = func(context.Context, int64) error { return errors.New("denied") }
		}
		e, err := NewEngine(context.Background(), cfg, hooks)
		if err != nil {
			t.Fatal(err)
		}
		a, err := e.StartServer(spec)
		if err != nil {
			e.Close()
			t.Fatal(err)
		}
		client, err := ssh.Dial("tcp", a.String(), &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
		if err != nil {
			e.Close()
			t.Fatal(err)
		}
		target := echoPeer(t)
		first, err := client.Dial("tcp", target)
		if protection {
			if err == nil {
				first.Close()
				t.Fatal("protection failure bypassed")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			writeAll(first, []byte("ready"))
			if _, err = io.ReadFull(first, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			if second, err := client.Dial("tcp", target); err == nil {
				second.Close()
				t.Fatal("shared channel budget bypassed")
			}
			first.Close()
		}
		client.Close()
		e.Close()
		if e.Stats().Active != 0 {
			t.Fatal(e.Stats())
		}
	}
}
func sshServerFixture(t *testing.T) (Config, *Engine, ServerConfig, ssh.Signer) {
	t.Helper()
	key, signer := sshServerKey(t)
	server := testServerEngine(t)
	spec := ServerConfig{Protocol: "ssh", Listen: "127.0.0.1:0", Password: "secret", KeyFile: key, Options: map[string]string{"username": "user"}}
	a, err := server.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseURI("ssh://user:secret@" + a.String() + "?hostkey=" + url.QueryEscape(ssh.FingerprintSHA256(signer.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, server, spec, signer
}
func TestSSHServerPayloadAuthenticationAndOwnerClose(t *testing.T) {
	cfg, server, _, _ := sshServerFixture(t)
	h, p, _ := splitProtocolTarget(echoPeer(t))
	for i := 0; i < 32; i++ {
		c, err := Dial(context.Background(), cfg, h, p)
		if err != nil {
			t.Fatal(i, err)
		}
		payloadCheck(t, c)
	}
	bad := cfg
	bad.Password = "wrong"
	if c, err := Dial(context.Background(), bad, h, p); err == nil {
		c.Close()
		t.Fatal("bad password accepted")
	}
	bad = cfg
	bad.Username = "other"
	if c, err := Dial(context.Background(), bad, h, p); err == nil {
		c.Close()
		t.Fatal("bad username accepted")
	}
	c, err := Dial(context.Background(), cfg, h, p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = writeAll(c, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	server.Close()
	if time.Since(start) > time.Second {
		t.Fatal("SSH server did not join", time.Since(start))
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream survived owner close")
	}
	if server.Stats().Active != 0 {
		t.Fatal(server.Stats())
	}
}
func TestSSHServerConcurrentChannelsAndForbiddenRequests(t *testing.T) {
	cfg, server, _, signer := sshServerFixture(t)
	client, err := ssh.Dial("tcp", net.JoinHostPort(cfg.Server, itoa(cfg.Port)), &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if c, _, err := client.OpenChannel("session", nil); err == nil {
		c.Close()
		t.Fatal("shell/command channel accepted")
	}
	if ok, _, err := client.SendRequest("tcpip-forward", true, nil); err != nil || ok {
		t.Fatal("reverse forwarding accepted", err)
	}
	if ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil || !ok {
		t.Fatal("keepalive rejected", err)
	}
	target := echoPeer(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := client.Dial("tcp", target)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			body := bytes.Repeat([]byte("SSH channel payload\x00\xff"), 8192)
			done := make(chan error, 1)
			go func() { done <- writeAll(c, body) }()
			reply := make([]byte, len(body))
			_, err = io.ReadFull(c, reply)
			if err == nil && !bytes.Equal(body, reply) {
				err = io.ErrUnexpectedEOF
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
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal(server.Stats())
	}
}
func TestSSHServerPublicKeyAuthAndIdleClose(t *testing.T) {
	_, server, spec, hostSigner := sshServerFixture(t)
	_, authorized := sshServerKey(t)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(path, append(ssh.MarshalAuthorizedKey(authorized.PublicKey()), []byte("\n  \n")...), 0600)
	spec.Password = ""
	spec.Options = map[string]string{"username": "user", "authorized-keys": path}
	a, err := server.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.Dial("tcp", a.String(), &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.PublicKeys(authorized)}, HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial("tcp", echoPeer(t))
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, c)
	client.Close()
	_, wrong := sshServerKey(t)
	client, err = ssh.Dial("tcp", a.String(), &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.PublicKeys(wrong)}, HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey())})
	if err == nil {
		client.Close()
		t.Fatal("unauthorized public key accepted")
	}
	cfg, _ := ParseURI("direct://")
	cfg.IdleTimeout = 80 * time.Millisecond
	idle, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	a, err = idle.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	client, err = ssh.Dial("tcp", a.String(), &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.PublicKeys(authorized)}, HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle physical transport not closed")
	}
}
