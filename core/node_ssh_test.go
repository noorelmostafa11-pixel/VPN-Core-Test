package core_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all"
	sshlib "golang.org/x/crypto/ssh"
)

var (
	nodeSSHBody     = bytes.Repeat([]byte{0, 255, 0x5a}, 40001)
	nodeSSHGreeting = []byte("independent SSH server-first\n")
)

func nodeSSHKey(t *testing.T, passphrase string) (sshlib.Signer, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sshlib.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = sshlib.MarshalPrivateKey(key, "synthetic")
	} else {
		block, err = sshlib.MarshalPrivateKeyWithPassphrase(key, "synthetic", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return signer, path
}

// This peer speaks SSH directly through x/crypto. It never uses the added
// proxy handler/config/forwarding codec to produce or inspect the wire.
type nodeSSHPeer struct {
	address string
	pin     string
	accepts atomic.Int32
	auth    atomic.Int32
	streams atomic.Int32
	bytes   atomic.Int64
	targets chan string
	stages  chan string
	closed  chan struct{}
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	workers sync.WaitGroup
}

func newNodeSSHPeer(t *testing.T, mode string, userKey sshlib.PublicKey) *nodeSSHPeer {
	t.Helper()
	signer, _ := nodeSSHKey(t, "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &nodeSSHPeer{address: listener.Addr().String(), pin: sshlib.FingerprintSHA256(signer.PublicKey()), targets: make(chan string, 16), stages: make(chan string, 32), closed: make(chan struct{}), conns: make(map[net.Conn]struct{})}
	config := &sshlib.ServerConfig{
		PasswordCallback: func(metadata sshlib.ConnMetadata, password []byte) (*sshlib.Permissions, error) {
			p.auth.Add(1)
			if metadata.User() != "user" || string(password) != "synthetic" {
				return nil, fmt.Errorf("wrong synthetic credentials")
			}
			return nil, nil
		},
	}
	if userKey != nil {
		config.PasswordCallback = nil
		config.PublicKeyCallback = func(metadata sshlib.ConnMetadata, key sshlib.PublicKey) (*sshlib.Permissions, error) {
			if metadata.User() != "user" || !bytes.Equal(key.Marshal(), userKey.Marshal()) {
				return nil, fmt.Errorf("wrong synthetic key")
			}
			return nil, nil
		}
	}
	config.AddHostKey(signer)
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[raw] = struct{}{}
			p.mu.Unlock()
			p.accepts.Add(1)
			p.stages <- "accepted"
			p.workers.Add(1)
			go func() {
				defer p.workers.Done()
				defer raw.Close()
				defer func() { p.mu.Lock(); delete(p.conns, raw); p.mu.Unlock() }()
				raw.SetDeadline(time.Now().Add(20 * time.Second))
				if mode == "stall-handshake" {
					io.Copy(io.Discard, raw)
					return
				}
				conn, channels, requests, err := sshlib.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer conn.Close()
				var workers sync.WaitGroup
				transportDone := make(chan struct{})
				workers.Add(1)
				go func() { defer workers.Done(); sshlib.DiscardRequests(requests) }()
				for next := range channels {
					p.stages <- "open"
					if mode == "stall-open" {
						// Do not accept/reject. The client's channel-open deadline
						// must close this transport rather than leave a worker.
						continue
					}
					var request struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if next.ChannelType() != "direct-tcpip" || sshlib.Unmarshal(next.ExtraData(), &request) != nil || request.Port != 443 || request.Origin != "127.0.0.1" || request.OriginPort != 0 {
						t.Error("wrong independent SSH forwarding envelope")
						next.Reject(sshlib.Prohibited, "invalid test request")
						continue
					}
					p.targets <- request.Host
					p.streams.Add(1)
					channel, replies, err := next.Accept()
					if err != nil {
						continue
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						repliesDone := make(chan struct{})
						go func() { sshlib.DiscardRequests(replies); close(repliesDone) }()
						defer func() { channel.Close(); <-repliesDone }()
						if _, err := channel.Write(nodeSSHGreeting); err != nil {
							return
						}
						if mode == "block-upload" {
							<-transportDone
							return
						}
						if mode == "block-download" {
							channel.Write(bytes.Repeat([]byte{0x5a}, 8*1024*1024))
							return
						}
						body := make([]byte, len(nodeSSHBody))
						n, err := io.ReadFull(channel, body)
						p.bytes.Add(int64(n))
						if err != nil {
							return
						}
						if !bytes.Equal(body, nodeSSHBody) {
							t.Error("SSH changed application bytes")
							return
						}
						if mode == "half-close" {
							if extra, err := io.ReadAll(channel); err != nil || len(extra) != 0 {
								t.Error("SSH half-close was not delivered", err)
								return
							}
						}
						for len(body) != 0 {
							n := min(len(body), 1473)
							if _, err := channel.Write(body[:n]); err != nil {
								return
							}
							body = body[n:]
						}
						channel.CloseWrite()
						io.Copy(io.Discard, channel)
					}()
				}
				close(transportDone)
				conn.Close()
				conn.Wait()
				workers.Wait()
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		p.mu.Lock()
		for raw := range p.conns {
			raw.Close()
		}
		p.mu.Unlock()
		go func() { p.workers.Wait(); close(p.closed) }()
		select {
		case <-p.closed:
		case <-time.After(5 * time.Second):
			t.Error("independent SSH peer workers did not join")
		}
	})
	return p
}

func nodeSSHInstance(t *testing.T, peer *nodeSSHPeer, format, password, pin, keyFile, passphrase string) *core.Instance {
	t.Helper()
	_, portText, _ := net.SplitHostPort(peer.address)
	port, _ := strconv.Atoi(portText)
	var data []byte
	var err error
	if format == "uri" {
		data = []byte("ssh://" + url.UserPassword("user", password).String() + "@" + peer.address + "?hostkey=" + url.QueryEscape(pin))
	} else if format == "node" || format == "go" {
		node := &conf.NodeDescription{Version: 1, Protocol: "ssh", Address: "127.0.0.1", Port: uint16(port), Credentials: conf.NodeCredentials{Username: "user", Password: &password}, Parameters: map[string]string{"hostkey": pin}}
		if format == "node" {
			data, err = json.Marshal(node)
		} else {
			selection, err := conf.ResolveNode(node)
			if err != nil {
				t.Fatal(err)
			}
			config, err := (&conf.Config{OutboundConfigs: []conf.OutboundDetourConfig{*selection.Outbound}}).Build()
			if err != nil {
				t.Fatal(err)
			}
			instance, err := core.New(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(); err != nil {
				instance.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			return instance
		}
	} else {
		data, err = json.Marshal(map[string]any{
			"policy":    map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 1, "connIdle": 3, "uplinkOnly": 1, "downlinkOnly": 1}}},
			"outbounds": []any{map[string]any{"protocol": "ssh", "settings": map[string]any{"address": "127.0.0.1", "port": port, "username": "user", "password": password, "hostKey": pin, "privateKeyFile": keyFile, "privateKeyPassphrase": passphrase}}},
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.StartInstance(format, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func nodeSSHExchange(t *testing.T, conn net.Conn) {
	t.Helper()
	want := append(append([]byte{}, nodeSSHGreeting...), nodeSSHBody...)
	got := make([]byte, len(want))
	if err := nodeHyRead(t, conn, got[:len(nodeSSHGreeting)]); err != nil {
		t.Fatal("SSH server-first", err)
	}
	for offset := 0; offset < len(nodeSSHBody); {
		n := min(17011, len(nodeSSHBody)-offset)
		if _, err := conn.Write(nodeSSHBody[offset : offset+n]); err != nil {
			t.Fatal(err)
		}
		offset += n
	}
	if err := nodeHyRead(t, conn, got[len(nodeSSHGreeting):]); err != nil || !bytes.Equal(got, want) {
		t.Fatal("SSH exact stream", err)
	}
}

func TestNodeSSHIndependentPeer(t *testing.T) {
	for _, format := range []string{"uri", "node", "go", "json"} {
		t.Run(format, func(t *testing.T) {
			peer := newNodeSSHPeer(t, "echo", nil)
			instance := nodeSSHInstance(t, peer, format, "synthetic", peer.pin, "", "")
			for _, target := range []xnet.Address{xnet.LocalHostIP, xnet.DomainAddress("synthetic.invalid"), xnet.LocalHostIPv6} {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				conn, err := core.Dial(ctx, instance, xnet.TCPDestination(target, 443))
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				nodeSSHExchange(t, conn)
				conn.Close()
				cancel()
				got := <-peer.targets
				want := target.String()
				if target.Family().IsIP() {
					want = target.IP().String()
				}
				if got != want {
					t.Fatal("SSH target changed or resolved locally", got, want)
				}
			}
			if peer.accepts.Load() != 3 || peer.streams.Load() != 3 || peer.auth.Load() != 3 || peer.bytes.Load() != int64(3*len(nodeSSHBody)) {
				t.Fatal("SSH replay, pooling or missing payload")
			}
		})
	}
}

func TestNodeSSHPrivateKeyAuthentication(t *testing.T) {
	key, path := nodeSSHKey(t, "synthetic-passphrase")
	peer := newNodeSSHPeer(t, "echo", key.PublicKey())
	instance := nodeSSHInstance(t, peer, "json", "", peer.pin, path, "synthetic-passphrase")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, instance, xnet.TCPDestination(xnet.LocalHostIP, 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	nodeSSHExchange(t, conn)
}

func TestNodeSSHRejectsPeerFailures(t *testing.T) {
	for _, fault := range []string{"pin", "auth", "stall-handshake", "stall-open"} {
		t.Run(fault, func(t *testing.T) {
			peer := newNodeSSHPeer(t, fault, nil)
			pin, password := peer.pin, "synthetic"
			if fault == "pin" {
				key, _ := nodeSSHKey(t, "")
				pin = sshlib.FingerprintSHA256(key.PublicKey())
			}
			if fault == "auth" {
				password = "incorrect"
			}
			instance := nodeSSHInstance(t, peer, "json", password, pin, "", "")
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, instance, xnet.TCPDestination(xnet.LocalHostIP, 443))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write([]byte("must-not-be-replayed"))
			if err := nodeHyRead(t, conn, make([]byte, 1)); err == nil {
				t.Fatal("SSH failure accepted")
			}
			if peer.accepts.Load() != 1 || peer.streams.Load() != 0 || peer.bytes.Load() != 0 {
				t.Fatal("fault not exercised or SSH payload replayed")
			}
			wantAuth := int32(0)
			if fault == "auth" || fault == "stall-open" {
				wantAuth = 1
			}
			if peer.auth.Load() != wantAuth {
				t.Fatal("host-key bypass or repeated authentication", peer.auth.Load())
			}
		})
	}
}
