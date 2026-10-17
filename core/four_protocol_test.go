package core_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/socks"
	"google.golang.org/protobuf/proto"
)

func scopeInstance(t *testing.T, config any) *core.Instance {
	t.Helper()
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	v, err := core.StartInstance("json", body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestFourProtocolRemoteClientRemoval(t *testing.T) {
	v := scopeInstance(t, map[string]any{"outbounds": []any{map[string]any{"protocol": "freedom"}}})
	// Retained original protobufs/configuration DTOs do not register clients.
	for _, message := range []proto.Message{&socks.ClientConfig{}, &http.ClientConfig{}} {
		if _, err := core.CreateObject(v, message); err == nil {
			t.Fatal("local ingress package registered an excluded remote client")
		}
	}
}

func scopeEchoTargets(t *testing.T) (xnet.Destination, xnet.Destination) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	closed := false
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			conns[conn] = true
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(conns, conn); mu.Unlock() }()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	go func() {
		defer workers.Done()
		body := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFrom(body)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(body[:n], addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		tcp.Close()
		udp.Close()
		mu.Lock()
		closed = true
		for conn := range conns {
			conn.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("scope echo endpoints did not join")
		}
	})
	tcpPort := tcp.Addr().(*net.TCPAddr).Port
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	return xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(tcpPort)), xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(udpPort))
}

func scopeExchange(t *testing.T, v *core.Instance, tcp, udp xnet.Destination) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, v, tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := bytes.Repeat([]byte{0, 255, 0x5a}, 40001)
	done := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(body); {
			n := min(1473, len(body)-offset)
			if _, err := conn.Write(body[offset : offset+n]); err != nil {
				done <- err
				return
			}
			offset += n
		}
		got := make([]byte, len(body))
		_, err := io.ReadFull(conn, got)
		if err == nil && !bytes.Equal(got, body) {
			err = fmt.Errorf("TCP payload changed")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		conn.Close()
		<-done
		t.Fatal("TCP scope exchange timed out")
	}
	packet, err := core.DialUDP(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(udp.Port)}
	for _, size := range []int{32, 1400, 3800} {
		body := bytes.Repeat([]byte{0x69}, size)
		if n, err := packet.WriteTo(body, target); err != nil || n != len(body) {
			t.Fatal("UDP scope write", n, err)
		}
		go func() {
			got := make([]byte, 8192)
			n, from, err := packet.ReadFrom(got)
			if err == nil && (!bytes.Equal(body, got[:n]) || from.String() != target.String()) {
				err = fmt.Errorf("UDP payload/boundary/source changed")
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			packet.Close()
			<-done
			t.Fatal("UDP scope exchange timed out")
		}
	}
}

func TestFourProtocolRuntimeInputs(t *testing.T) {
	const id = "11111111-2222-4333-8444-555555555555"
	tcpTarget, udpTarget := scopeEchoTargets(t)
	for _, variant := range []string{"vless", "vmess", "trojan", "ss-aes-256-gcm", "ss-aes-192-gcm", "ss-2022-blake3-aes-128-gcm"} {
		t.Run(variant, func(t *testing.T) {
			protocol, scheme := variant, variant
			password := "synthetic-scope-password"
			credentials := conf.NodeCredentials{ID: id}
			settings := map[string]any{"clients": []any{map[string]any{"id": id}}}
			clientSettings := map[string]any{"address": "127.0.0.1", "id": id}
			if variant == "vless" {
				settings["decryption"] = "none"
				clientSettings["encryption"] = "none"
			}
			if variant == "vmess" {
				clientSettings["security"] = "aes-128-gcm"
			}
			if variant == "trojan" {
				credentials = conf.NodeCredentials{Password: &password}
				settings = map[string]any{"clients": []any{map[string]any{"password": password}}}
				clientSettings = map[string]any{"address": "127.0.0.1", "password": password}
			}
			if method, ok := strings.CutPrefix(variant, "ss-"); ok {
				protocol, scheme = "shadowsocks", "ss"
				if method == "2022-blake3-aes-128-gcm" {
					password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x47}, 16))
				}
				credentials = conf.NodeCredentials{Method: method, Password: &password}
				settings = map[string]any{"method": method, "password": password, "network": "tcp,udp"}
				clientSettings = map[string]any{"address": "127.0.0.1", "method": method, "password": password}
			}
			reserved, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reserved.Addr().(*net.TCPAddr).Port
			reserved.Close()
			serverStream := map[string]any{"network": "tcp"}
			clientStream := map[string]any{"network": "tcp"}
			parameters := map[string]string{}
			if variant == "trojan" {
				certificate, pin := cert.MustGenerate(nil, cert.DNSNames("scope.example"))
				serverStream["security"] = "tls"
				serverStream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate}))}, "key": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: certificate.PrivateKey}))}}}}
				clientStream["security"] = "tls"
				clientStream["tlsSettings"] = map[string]any{"serverName": "scope.example", "pinnedPeerCertSha256": hex.EncodeToString(pin[:])}
				parameters["sni"] = "scope.example"
				parameters["pcs"] = hex.EncodeToString(pin[:])
			}
			// Authenticated proxy inbounds protect private addresses by default.
			// Permit only the synthetic loopback echo endpoints in this fixture.
			scopeInstance(t, map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings, "streamSettings": serverStream}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}})
			clientSettings["port"] = port
			for _, format := range []string{"json", "uri", "node", "go"} {
				t.Run(format, func(t *testing.T) {
					var v *core.Instance
					if format == "json" {
						v = scopeInstance(t, map[string]any{"outbounds": []any{map[string]any{"protocol": protocol, "settings": clientSettings, "streamSettings": clientStream}}})
					} else {
						node := &conf.NodeDescription{Version: 1, Protocol: scheme, Address: "127.0.0.1", Port: uint16(port), Credentials: credentials, Parameters: parameters}
						if format == "go" {
							selection, err := conf.ResolveNode(node)
							if err != nil {
								t.Fatal(err)
							}
							config, err := (&conf.Config{OutboundConfigs: []conf.OutboundDetourConfig{*selection.Outbound}}).Build()
							if err != nil {
								t.Fatal(err)
							}
							v, err = core.New(config)
							if err == nil {
								err = v.Start()
							}
							if err != nil {
								if v != nil {
									v.Close()
								}
								t.Fatal(err)
							}
						} else {
							var body []byte
							if format == "node" {
								body, err = json.Marshal(node)
							} else {
								query := url.Values{}
								for k, value := range parameters {
									query.Set(k, value)
								}
								if variant == "vmess" {
									query.Set("encryption", "aes-128-gcm")
								}
								user := url.User(id)
								if scheme == "ss" {
									user = url.UserPassword(credentials.Method, password)
								} else if scheme == "trojan" {
									user = url.User(password)
								}
								body = []byte(scheme + "://" + user.String() + "@127.0.0.1:" + strconv.Itoa(port) + "?" + query.Encode())
							}
							if err == nil {
								v, err = core.StartInstance(format, body)
							}
							if err != nil {
								t.Fatal(err)
							}
						}
						t.Cleanup(func() { v.Close() })
					}
					scopeExchange(t, v, tcpTarget, udpTarget)
				})
			}
		})
	}
}
