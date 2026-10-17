package core_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	sshlib "golang.org/x/crypto/ssh"
)

func nodeSSHInbound(t *testing.T, keyAuth, blocked bool, idle uint32) (string, *sshlib.ClientConfig) {
	t.Helper()
	host, path := nodeSSHKey(t, "synthetic-host-passphrase")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	portNumber, _ := strconv.Atoi(port)
	listener.Close()
	settings := map[string]any{"username": "user", "password": "synthetic", "hostKeyFile": path, "hostKeyPassphrase": "synthetic-host-passphrase"}
	client := &sshlib.ClientConfig{User: "user", Auth: []sshlib.AuthMethod{sshlib.Password("synthetic")}, HostKeyCallback: sshlib.FixedHostKey(host.PublicKey()), Timeout: 3 * time.Second}
	if keyAuth {
		key, _ := nodeSSHKey(t, "")
		file := filepath.Join(t.TempDir(), "authorized_keys")
		keyData := append([]byte("# synthetic authorized keys\n\n"), sshlib.MarshalAuthorizedKey(key.PublicKey())...)
		keyData = append(keyData, []byte("\n# trailing comment\n")...)
		if err := os.WriteFile(file, keyData, 0o600); err != nil {
			t.Fatal(err)
		}
		settings["password"], settings["authorizedKeysFile"] = "", file
		client.Auth = []sshlib.AuthMethod{sshlib.PublicKeys(key)}
	}
	config := map[string]any{
		"policy":    map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 1, "connIdle": idle, "uplinkOnly": 1, "downlinkOnly": 1}}},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": portNumber, "protocol": "ssh", "settings": settings}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}, map[string]any{"protocol": "blackhole", "tag": "blocked"}},
	}
	if blocked {
		config["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "ip": []string{"127.0.0.1"}, "outboundTag": "blocked"}}}
	}
	data, _ := json.Marshal(config)
	instance, err := core.StartInstance("json", data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return address, client
}

func nodeSSHRawClient(t *testing.T, address string, config *sshlib.ClientConfig) *sshlib.Client {
	t.Helper()
	raw, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, channels, requests, err := sshlib.NewClientConn(raw, address, config)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.SetDeadline(time.Time{})
	client := sshlib.NewClient(conn, channels, requests)
	t.Cleanup(func() { raw.Close(); client.Close(); client.Wait() })
	return client
}

func nodeSSHEchoTarget(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	var workers sync.WaitGroup
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(conns, conn); mu.Unlock() }()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				conn.Write(nodeSSHGreeting)
				io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for conn := range conns {
			conn.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SSH TCP target did not join")
		}
	})
	return listener.Addr().String(), &count
}

func TestSSHInboundIndependentClient(t *testing.T) {
	for _, keyAuth := range []bool{false, true} {
		t.Run(fmt.Sprint("publickey=", keyAuth), func(t *testing.T) {
			target, count := nodeSSHEchoTarget(t)
			address, config := nodeSSHInbound(t, keyAuth, false, 10)
			client := nodeSSHRawClient(t, address, config)
			// Several channels on one SSH connection exercise isolated session
			// metadata, Xray routing and simultaneous server-first relays.
			var workers sync.WaitGroup
			for range 8 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					conn, err := client.Dial("tcp", target)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					got := make([]byte, len(nodeSSHGreeting))
					if err := nodeHyRead(t, conn, got); err != nil || !bytes.Equal(got, nodeSSHGreeting) {
						t.Error("SSH inbound server-first", err)
						return
					}
					if _, err := conn.Write(nodeSSHBody); err != nil {
						t.Error(err)
						return
					}
					body := make([]byte, len(nodeSSHBody))
					if err := nodeHyRead(t, conn, body); err != nil || !bytes.Equal(body, nodeSSHBody) {
						t.Error("SSH inbound exact payload", err)
					}
				}()
			}
			workers.Wait()
			if count.Load() != 8 {
				t.Fatal("SSH channel routing or target count mismatch", count.Load())
			}
		})
	}
}

func TestSSHInboundRejectsAuthenticationAndUnsupportedRequests(t *testing.T) {
	address, config := nodeSSHInbound(t, false, false, 10)
	for _, fault := range []string{"password", "username", "publickey"} {
		bad := *config
		switch fault {
		case "password":
			bad.Auth = []sshlib.AuthMethod{sshlib.Password("wrong")}
		case "username":
			bad.User = "wrong"
		case "publickey":
			key, _ := nodeSSHKey(t, "")
			bad.Auth = []sshlib.AuthMethod{sshlib.PublicKeys(key)}
		}
		if client, err := sshlib.Dial("tcp", address, &bad); err == nil {
			client.Close()
			t.Fatal("SSH unauthorized user accepted", fault)
		}
	}
	client := nodeSSHRawClient(t, address, config)
	for _, name := range []string{"session", "forwarded-tcpip", "auth-agent@openssh.com"} {
		if channel, _, err := client.OpenChannel(name, nil); err == nil {
			channel.Close()
			t.Fatal("SSH unsupported channel accepted", name)
		}
	}
	for _, payload := range [][]byte{nil, {0, 0, 0, 255}, sshlib.Marshal(struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}{"127.0.0.1", 65536, "127.0.0.1", 1})} {
		if channel, _, err := client.OpenChannel("direct-tcpip", payload); err == nil {
			channel.Close()
			t.Fatal("SSH malformed target accepted")
		}
	}
	if ok, _, err := client.SendRequest("tcpip-forward", true, nil); err != nil || ok {
		t.Fatal("SSH remote forwarding accepted", err)
	}
	if ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil || !ok {
		t.Fatal("SSH keepalive failed", err)
	}
}

func TestSSHInboundUsesXrayRouting(t *testing.T) {
	target, count := nodeSSHEchoTarget(t)
	address, config := nodeSSHInbound(t, false, true, 5)
	client := nodeSSHRawClient(t, address, config)
	conn, err := client.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("blocked application bytes"))
	if err := nodeHyRead(t, conn, make([]byte, 1)); err == nil {
		t.Fatal("SSH bypassed blackhole routing")
	}
	if count.Load() != 0 {
		t.Fatal("SSH dialed target outside Xray dispatcher")
	}
}

func TestSSHInboundIdleChannelDoesNotCancelActiveSibling(t *testing.T) {
	target, _ := nodeSSHEchoTarget(t)
	address, config := nodeSSHInbound(t, false, false, 1)
	client := nodeSSHRawClient(t, address, config)
	idle, err := client.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	active, err := client.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	for _, conn := range []net.Conn{idle, active} {
		if err := nodeHyRead(t, conn, make([]byte, len(nodeSSHGreeting))); err != nil {
			t.Fatal(err)
		}
	}
	closed := make(chan error, 1)
	go func() { var b [1]byte; _, err := idle.Read(b[:]); closed <- err }()
	for range 20 {
		if _, err := active.Write([]byte{0x7f}); err != nil {
			t.Fatal("sibling write canceled", err)
		}
		if err := nodeHyRead(t, active, make([]byte, 1)); err != nil {
			t.Fatal("sibling read canceled", err)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		<-timer.C
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("idle channel delivered unexplained payload")
		}
	case <-time.After(2 * time.Second):
		idle.Close()
		<-closed
		t.Fatal("SSH idle channel did not close")
	}
}

func TestSSHInboundBoundsConcurrentChannels(t *testing.T) {
	target, _ := nodeSSHEchoTarget(t)
	address, config := nodeSSHInbound(t, false, false, 15)
	client := nodeSSHRawClient(t, address, config)
	channels := make([]net.Conn, 0, 64)
	defer func() {
		for _, channel := range channels {
			channel.Close()
		}
	}()
	for range 64 {
		channel, err := client.Dial("tcp", target)
		if err != nil {
			t.Fatal("SSH channel limit below documented bound", len(channels), err)
		}
		channels = append(channels, channel)
		if err := nodeHyRead(t, channel, make([]byte, len(nodeSSHGreeting))); err != nil {
			t.Fatal(err)
		}
	}
	if extra, err := client.Dial("tcp", target); err == nil {
		extra.Close()
		t.Fatal("SSH unbounded channel accepted")
	}
	// Rejection must not invalidate an already authenticated active channel.
	if _, err := channels[0].Write([]byte("after-limit")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("after-limit"))
	if err := nodeHyRead(t, channels[0], got); err != nil || string(got) != "after-limit" {
		t.Fatal("SSH channel limit canceled active flow", err)
	}
}
