package core_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	q "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/crypto/blake2b"
)

// The peer uses QUIC/HTTP3 directly, literal Hysteria2 application framing and
// an independent Salamander packet wrapper. It does not use the fork's
// Hysteria handlers, transport, protobufs or node conversion to generate wire.
type nodeHyPacket struct {
	net.PacketConn
	key   []byte
	reads atomic.Int32
}

func (p *nodeHyPacket) ReadFrom(dst []byte) (int, net.Addr, error) {
	for {
		wire := make([]byte, 65536)
		n, addr, err := p.PacketConn.ReadFrom(wire)
		if err != nil {
			return 0, addr, err
		}
		p.reads.Add(1)
		if len(p.key) == 0 {
			return copy(dst, wire[:n]), addr, nil
		}
		if n <= 8 || n-8 > len(dst) {
			continue
		}
		input := append(append([]byte{}, p.key...), wire[:8]...)
		hash := blake2b.Sum256(input)
		for i, b := range wire[8:n] {
			dst[i] = b ^ hash[i%32]
		}
		return n - 8, addr, nil
	}
}

func (p *nodeHyPacket) WriteTo(src []byte, addr net.Addr) (int, error) {
	if len(p.key) == 0 {
		return p.PacketConn.WriteTo(src, addr)
	}
	wire := make([]byte, len(src)+8)
	if _, err := rand.Read(wire[:8]); err != nil {
		return 0, err
	}
	hash := blake2b.Sum256(append(append([]byte{}, p.key...), wire[:8]...))
	for i, b := range src {
		wire[i+8] = b ^ hash[i%32]
	}
	n, err := p.PacketConn.WriteTo(wire, addr)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(src), nil
}

type nodeHyPeer struct {
	packet                   *nodeHyPacket
	address                  string
	pin                      string
	auth, streams, datagrams atomic.Int32
	errors                   chan error
}

var (
	nodeHyGreeting = []byte("independent Hysteria2 server-first\n")
	nodeHyBody     = bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
)

func newNodeHyPeer(t *testing.T, obfs bool) *nodeHyPeer {
	t.Helper()
	certificate, hash := cert.MustGenerate(nil, cert.DNSNames("node-hy.example"))
	privateKey, err := x509.ParsePKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet := &nodeHyPacket{PacketConn: raw}
	if obfs {
		packet.key = []byte("synthetic-obfs")
	}
	transport := &q.Transport{Conn: packet, DisableGSO: true}
	listener, err := transport.Listen(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: privateKey}}, NextProtos: []string{"h3"}}, &q.Config{EnableDatagrams: true, MaxDatagramFrameSize: 1200, AssumePeerMaxDatagramFrameSize: 1200, DisablePathManager: true})
	if err != nil {
		raw.Close()
		transport.Close()
		t.Fatal(err)
	}
	peer := &nodeHyPeer{packet: packet, address: listener.Addr().String(), pin: hex.EncodeToString(hash[:]), errors: make(chan error, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var mu sync.Mutex
	var accepted *q.Conn
	report := func(err error) {
		if err != nil {
			select {
			case peer.errors <- err:
			default:
			}
		}
	}
	go func() {
		defer close(done)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		mu.Lock()
		accepted = conn
		mu.Unlock()
		defer conn.CloseWithError(0, "")
		var authenticated atomic.Bool
		var workers sync.WaitGroup
		workers.Go(func() {
			for {
				wire, err := conn.ReceiveDatagram(ctx)
				if err != nil {
					return
				}
				if !authenticated.Load() || len(wire) < 9 {
					report(fmt.Errorf("unauthenticated/malformed datagram"))
					return
				}
				reader := bytes.NewReader(wire[8:])
				n, err := quicvarint.Read(reader)
				if err != nil || n == 0 || n > 256 {
					report(fmt.Errorf("invalid datagram target length"))
					return
				}
				address := make([]byte, int(n))
				if _, err := io.ReadFull(reader, address); err != nil || string(address) != "127.0.0.1:443" || reader.Len() == 0 {
					report(fmt.Errorf("datagram target/payload changed"))
					return
				}
				peer.datagrams.Add(1)
				if err := conn.SendDatagram(wire); err != nil {
					report(err)
					return
				}
			}
		})
		server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer.auth.Add(1)
			if r.Method != "POST" || r.Host != "hysteria" || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != "user:synthetic" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			authenticated.Store(true)
			w.Header().Set("Hysteria-UDP", "true")
			w.Header().Set("Hysteria-CC-RX", "0")
			w.WriteHeader(233)
		})}
		server.StreamDispatcher = func(kind http3.FrameType, stream *q.Stream, dispatchErr error) (bool, error) {
			if dispatchErr != nil || kind != 0x401 || !authenticated.Load() {
				return false, nil
			}
			peer.streams.Add(1)
			workers.Go(func() {
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(8 * time.Second))
				reader := quicvarint.NewReader(stream)
				kind, err := quicvarint.Read(reader)
				if err != nil || kind != 0x401 {
					report(fmt.Errorf("TCP frame changed"))
					return
				}
				n, err := quicvarint.Read(reader)
				if err != nil || n == 0 || n > 256 {
					report(fmt.Errorf("TCP target length changed"))
					return
				}
				address := make([]byte, int(n))
				if _, err := io.ReadFull(stream, address); err != nil || string(address) != "127.0.0.1:443" {
					report(fmt.Errorf("TCP target changed"))
					return
				}
				padding, err := quicvarint.Read(reader)
				if err != nil || padding > 4096 {
					report(fmt.Errorf("TCP padding changed"))
					return
				}
				if _, err := io.CopyN(io.Discard, stream, int64(padding)); err != nil {
					report(err)
					return
				}
				if _, err := stream.Write([]byte{0, 0, 0}); err != nil {
					report(err)
					return
				}
				if _, err := stream.Write(nodeHyGreeting); err != nil {
					report(err)
					return
				}
				body := make([]byte, len(nodeHyBody))
				if _, err := io.ReadFull(stream, body); err != nil || !bytes.Equal(body, nodeHyBody) {
					report(fmt.Errorf("TCP application payload changed: %v", err))
					return
				}
				_, err = io.Copy(stream, bytes.NewReader(body))
				report(err)
			})
			return true, nil
		}
		_ = server.ServeQUICConn(conn)
		conn.CloseWithError(0, "")
		workers.Wait()
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mu.Lock()
		if accepted != nil {
			accepted.CloseWithError(0, "")
		}
		mu.Unlock()
		transport.Close()
		raw.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("independent Hysteria2 peer did not join")
		}
		for {
			select {
			case err := <-peer.errors:
				t.Error(err)
			default:
				return
			}
		}
	})
	return peer
}

func nodeHyClient(t *testing.T, peer *nodeHyPeer, format string, obfs bool, password, pin string) *core.Instance {
	t.Helper()
	_, portText, _ := net.SplitHostPort(peer.address)
	port, _ := strconv.ParseUint(portText, 10, 16)
	parameters := map[string]string{"sni": "node-hy.example"}
	if pin != "" {
		parameters["pinSHA256"] = pin
	}
	if obfs {
		parameters["obfs"], parameters["obfs-password"] = "salamander", "synthetic-obfs"
	}
	node := &conf.NodeDescription{Version: 1, Protocol: "hysteria2", Address: "127.0.0.1", Port: uint16(port), Credentials: conf.NodeCredentials{Password: &password}, Parameters: parameters}
	var data []byte
	var err error
	switch format {
	case "uri", "hy2":
		values := url.Values{}
		for key, value := range parameters {
			values.Set(key, value)
		}
		scheme := "hysteria2"
		if format == "hy2" {
			scheme = "hy2"
		}
		data = []byte(scheme + "://" + url.User(password).String() + "@" + peer.address + "/?" + values.Encode())
		format = "uri"
	case "node":
		data, err = json.Marshal(node)
	case "go":
		selection, resolveErr := conf.ResolveNode(node)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		config, buildErr := (&conf.Config{OutboundConfigs: []conf.OutboundDetourConfig{*selection.Outbound}}).Build()
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		instance, newErr := core.New(config)
		if newErr != nil {
			t.Fatal(newErr)
		}
		if err := instance.Start(); err != nil {
			instance.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { instance.Close() })
		return instance
	case "json":
		stream := map[string]any{"network": "hysteria", "security": "tls", "tlsSettings": map[string]any{"serverName": "node-hy.example", "alpn": []string{"h3"}, "pinnedPeerCertSha256": pin}, "hysteriaSettings": map[string]any{"version": 2, "auth": password}}
		if obfs {
			stream["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": "synthetic-obfs"}}}}
		}
		data, err = json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": "127.0.0.1", "port": port}, "streamSettings": stream}}})
	default:
		t.Fatal("unknown test input")
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

func nodeHyRead(t *testing.T, conn net.Conn, data []byte) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(conn, data); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(8 * time.Second):
		conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("core reader did not join after close")
		}
		return fmt.Errorf("core read timed out")
	}
}

func nodeHyReadPacket(t *testing.T, conn net.Conn, data []byte) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() { n, err := conn.Read(data); done <- result{n, err} }()
	select {
	case value := <-done:
		return value.n, value.err
	case <-time.After(8 * time.Second):
		conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("UDP reader did not join after close")
		}
		return 0, fmt.Errorf("UDP read timed out")
	}
}

func TestNodeHysteria2IndependentPeer(t *testing.T) {
	for _, obfs := range []bool{false, true} {
		for _, format := range []string{"json", "uri", "hy2", "node", "go"} {
			t.Run(fmt.Sprintf("%s/obfs%t", format, obfs), func(t *testing.T) {
				peer := newNodeHyPeer(t, obfs)
				instance := nodeHyClient(t, peer, format, obfs, "user:synthetic", peer.pin)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				conn, err := core.Dial(ctx, instance, xnet.TCPDestination(xnet.LocalHostIP, 443))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				greeting := make([]byte, len(nodeHyGreeting))
				if err := nodeHyRead(t, conn, greeting); err != nil || !bytes.Equal(greeting, nodeHyGreeting) {
					t.Fatal("server-first greeting failed", err)
				}
				for _, fragment := range [][]byte{nodeHyBody[:1], nodeHyBody[1:65], nodeHyBody[65:8193], nodeHyBody[8193:]} {
					if _, err := conn.Write(fragment); err != nil {
						t.Fatal(err)
					}
				}
				body := make([]byte, len(nodeHyBody))
				if err := nodeHyRead(t, conn, body); err != nil || !bytes.Equal(body, nodeHyBody) {
					t.Fatal("application TCP echo failed", err)
				}
				udp, err := core.Dial(ctx, instance, xnet.UDPDestination(xnet.LocalHostIP, 443))
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				for _, size := range []int{32, 1400, 3800} {
					want := bytes.Repeat([]byte{byte(size)}, size)
					if _, err := udp.Write(want); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, 8192)
					if n, err := nodeHyReadPacket(t, udp, got); err != nil || n != size || !bytes.Equal(got[:n], want) {
						t.Fatal("application UDP datagram changed", size, n, err)
					}
				}
				if peer.auth.Load() != 1 || peer.streams.Load() != 1 || peer.datagrams.Load() < 3 {
					t.Fatal("actual protocol phases were not reached", peer.auth.Load(), peer.streams.Load(), peer.datagrams.Load())
				}
			})
		}
	}
}

func TestNodeHysteria2RejectsPeerFailures(t *testing.T) {
	for _, format := range []string{"uri", "node"} {
		for _, fault := range []string{"auth", "pin", "untrusted"} {
			t.Run(format+"/"+fault, func(t *testing.T) {
				peer := newNodeHyPeer(t, false)
				password, pin := "user:synthetic", peer.pin
				if fault == "auth" {
					password = "wrong-auth"
				}
				if fault == "pin" {
					pin = "0000000000000000000000000000000000000000000000000000000000000000"
				}
				if fault == "untrusted" {
					pin = ""
				}
				instance := nodeHyClient(t, peer, format, false, password, pin)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				conn, err := core.Dial(ctx, instance, xnet.TCPDestination(xnet.LocalHostIP, 443))
				if err != nil {
					t.Fatal("core dispatch did not reach peer validation", err)
				}
				defer conn.Close()
				if err := nodeHyRead(t, conn, make([]byte, 1)); err == nil {
					t.Fatal("failed peer accepted application bytes")
				}
				if peer.packet.reads.Load() == 0 || peer.streams.Load() != 0 {
					t.Fatal("fault not exercised or protocol fallback occurred")
				}
				wantAuth := int32(0)
				if fault == "auth" {
					wantAuth = 1
				}
				if peer.auth.Load() != wantAuth {
					t.Fatal("unexpected authentication retry or TLS bypass", peer.auth.Load(), wantAuth)
				}
			})
		}
	}
}
