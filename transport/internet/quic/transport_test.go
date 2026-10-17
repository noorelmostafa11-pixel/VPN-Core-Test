package quic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	q "github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ciphers = []protocol.SecurityType{protocol.SecurityType_NONE, protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305}
	headers = []string{"none", "srtp", "utp", "dtls", "wechat", "wechat-video", "wireguard", "dns"}
)

func certificateSettings(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	return &tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)}, ServerName: "localhost"}, &tls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{hash[:]}}
}

// Independent fixed packet prefixes and .NET-verified SHA256 KDF output.
// Neither production auth(), header serialization nor wrapPacket is used.
type oraclePacket struct {
	net.PacketConn
	prefix                                []byte
	auth                                  cipher.AEAD
	mu                                    sync.Mutex
	count, dropped, duplicated, reordered int
	held                                  []byte
	heldAddr                              net.Addr
	fault                                 bool
}

func oracle(t *testing.T, raw net.PacketConn, security protocol.SecurityType, header string) *oraclePacket {
	t.Helper()
	prefixes := map[string]string{"none": "", "srtp": "b5e80001", "utp": "00010100", "wireguard": "04000000", "dtls": "17fefd00010000000000000011", "wechat": "a1080000000100101118302230", "wechat-video": "a1080000000100101118302230", "dns": "00010100000100000000000003777777076578616d706c6503636f6d0000010001"}
	prefix, err := hex.DecodeString(prefixes[header])
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString("4af49d477ebab24ed6b2e65b351f00634ae69c356876cb4e57215497157b0617")
	if err != nil {
		t.Fatal(err)
	}
	var auth cipher.AEAD
	switch security {
	case protocol.SecurityType_AES128_GCM:
		block, _ := aes.NewCipher(key[:16])
		auth, _ = cipher.NewGCM(block)
	case protocol.SecurityType_CHACHA20_POLY1305:
		auth, _ = chacha20poly1305.New(key)
	}
	return &oraclePacket{PacketConn: raw, prefix: prefix, auth: auth}
}

func (p *oraclePacket) ReadFrom(dst []byte) (int, net.Addr, error) {
	buffer := make([]byte, 65536)
	for {
		n, addr, err := p.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, nil, err
		}
		if n <= len(p.prefix) {
			continue
		}
		payload := buffer[len(p.prefix):n]
		if p.auth != nil {
			nonce := p.auth.NonceSize()
			if len(payload) < nonce+p.auth.Overhead() {
				continue
			}
			payload, err = p.auth.Open(nil, payload[:nonce], payload[nonce:], nil)
			if err != nil {
				continue
			}
		}
		if len(payload) > len(dst) {
			continue
		}
		return copy(dst, payload), addr, nil
	}
}

func (p *oraclePacket) WriteTo(src []byte, addr net.Addr) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	wire := bytes.Clone(p.prefix)
	if p.auth == nil {
		wire = append(wire, src...)
	} else {
		// Distinct deterministic nonces from the independent peer's counter.
		nonce := make([]byte, p.auth.NonceSize())
		for i := range 8 {
			nonce[len(nonce)-1-i] = byte(uint64(p.count) >> uint(8*i))
		}
		wire = append(wire, nonce...)
		wire = p.auth.Seal(wire, nonce, src, nil)
	}
	if p.fault && p.count == 5 {
		p.dropped++
		return len(src), nil
	}
	if p.fault && p.count == 9 {
		p.held = bytes.Clone(wire)
		p.heldAddr = addr
		return len(src), nil
	}
	if _, err := p.PacketConn.WriteTo(wire, addr); err != nil {
		return 0, err
	}
	if p.fault && p.count == 7 {
		if _, err := p.PacketConn.WriteTo(wire, addr); err != nil {
			return 0, err
		}
		p.duplicated++
	}
	if p.fault && p.count == 10 && p.held != nil {
		if _, err := p.PacketConn.WriteTo(p.held, p.heldAddr); err != nil {
			return 0, err
		}
		p.held = nil
		p.reordered++
	}
	return len(src), nil
}

func peerListener(t *testing.T, config *Config, security *tls.Config, fault bool, prefixOverride ...[]byte) (*q.Listener, *oraclePacket) {
	t.Helper()
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet := oracle(t, raw, config.Security.Type, config.HeaderType)
	if len(prefixOverride) > 0 {
		// Set the historical wire prefix before QUIC starts its read goroutine.
		packet.prefix = bytes.Clone(prefixOverride[0])
	}
	packet.fault = fault
	transport := &q.Transport{Conn: packet, DisableGSO: true}
	listener, err := transport.Listen(security.GetTLSConfig(), &q.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIncomingUniStreams: -1})
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); transport.Close(); raw.Close() })
	return listener, packet
}

func streamExchange(t *testing.T, conn net.Conn, half func() error) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	// QUIC does not advertise an opened stream until its first byte. No
	// marker is inserted: this byte is part of the exact application payload.
	if _, err := conn.Write([]byte{0x51}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 13)
	if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "server-first\n" {
		t.Fatal("greeting mismatch", err)
	}
	payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
	for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
		if n, err := conn.Write(piece); err != nil || n != len(piece) {
			t.Fatal("fragmented upload failed", n, err)
		}
	}
	if err := half(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("exact download/half-close mismatch", len(got), err)
	}
}

func echoStream(stream *q.Stream) error {
	stream.SetDeadline(time.Now().Add(8 * time.Second))
	first := make([]byte, 1)
	if _, err := io.ReadFull(stream, first); err != nil {
		return err
	}
	if first[0] != 0x51 {
		return errors.New("invented QUIC prefix")
	}
	if _, err := stream.Write([]byte("server-first\n")); err != nil {
		return err
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)) {
		return errors.New("independent upload mismatch")
	}
	if _, err := stream.Write(got); err != nil {
		return err
	}
	return stream.Close()
}

func TestForkLegacyQUICClientIndependentPeer(t *testing.T) {
	for _, security := range ciphers {
		for _, header := range headers {
			t.Run(security.String()+"/"+header, func(t *testing.T) {
				serverTLS, clientTLS := certificateSettings(t)
				config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: security}, HeaderType: header}
				listener, _ := peerListener(t, config, serverTLS, false)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					parent, err := listener.Accept(ctx)
					if err != nil {
						done <- err
						return
					}
					stream, err := parent.AcceptStream(ctx)
					if err == nil {
						err = echoStream(stream)
					}
					done <- err
				}()
				settings := &internet.MemoryStreamConfig{ProtocolName: "quic", ProtocolSettings: config, SecurityType: "tls", SecuritySettings: clientTLS}
				conn, err := Dial(ctx, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.UDPAddr).Port)), settings)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				streamExchange(t, conn, conn.(*streamConn).CloseWrite)
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("peer did not finish")
				}
			})
		}
	}
}

func TestForkLegacyQUICServerIndependentPeer(t *testing.T) {
	for _, security := range ciphers {
		for _, header := range headers {
			t.Run(security.String()+"/"+header, func(t *testing.T) {
				serverTLS, clientTLS := certificateSettings(t)
				config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: security}, HeaderType: header}
				done := make(chan error, 1)
				settings := &internet.MemoryStreamConfig{ProtocolName: "quic", ProtocolSettings: config, SecurityType: "tls", SecuritySettings: serverTLS}
				listener, err := Listen(context.Background(), xnet.LocalHostIP, 0, settings, func(conn stat.Connection) {
					go func() { defer conn.Close(); done <- echoStream(conn.(*streamConn).Stream) }()
				})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				transport := &q.Transport{Conn: oracle(t, raw, security, header), DisableGSO: true}
				defer transport.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				parent, err := transport.Dial(ctx, listener.Addr(), clientTLS.GetTLSConfig(), &q.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
				if err != nil {
					t.Fatal(err)
				}
				defer parent.CloseWithError(0, "")
				stream, err := parent.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				conn := &streamConn{Stream: stream, parent: parent}
				streamExchange(t, conn, stream.Close)
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("server did not finish")
				}
			})
		}
	}
}

func TestForkLegacyQUICLossReorderDuplicate(t *testing.T) {
	serverTLS, clientTLS := certificateSettings(t)
	config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}, HeaderType: "dtls"}
	listener, packet := peerListener(t, config, serverTLS, true)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		parent, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		stream, err := parent.AcceptStream(ctx)
		if err == nil {
			err = echoStream(stream)
		}
		done <- err
	}()
	conn, err := Dial(ctx, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.UDPAddr).Port)), &internet.MemoryStreamConfig{ProtocolSettings: config, SecurityType: "tls", SecuritySettings: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	streamExchange(t, conn, conn.(*streamConn).CloseWrite)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	packet.mu.Lock()
	defer packet.mu.Unlock()
	if packet.dropped != 1 || packet.duplicated != 1 || packet.reordered != 1 || packet.held != nil {
		t.Fatal("fault schedule did not fire", packet.dropped, packet.duplicated, packet.reordered)
	}
}

func TestForkLegacyQUICSecurityGuards(t *testing.T) {
	serverTLS, clientTLS := certificateSettings(t)
	config := &Config{Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE}}
	listener, _ := peerListener(t, config, serverTLS, false)
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.UDPAddr).Port))
	for _, fault := range []string{"pin", "missing-settings", "fingerprint", "version"} {
		t.Run(fault, func(t *testing.T) {
			bad := protoCloneTLS(clientTLS)
			settings := &internet.MemoryStreamConfig{ProtocolSettings: config, SecurityType: "tls", SecuritySettings: bad}
			switch fault {
			case "pin":
				bad.PinnedPeerCertSha256 = [][]byte{bytes.Repeat([]byte{0xff}, 32)}
			case "missing-settings":
				settings.SecuritySettings = nil
			case "fingerprint":
				bad.Fingerprint = "chrome"
			case "version":
				bad.MaxVersion = "1.2"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if conn, err := Dial(ctx, dest, settings); err == nil {
				conn.Close()
				t.Fatal("TLS policy ignored", fault)
			}
		})
	}
}

func protoCloneTLS(config *tls.Config) *tls.Config {
	return &tls.Config{ServerName: config.ServerName, PinnedPeerCertSha256: config.PinnedPeerCertSha256}
}

func TestForkLegacyQUICListenerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var accepted atomic.Int32
	l, err := Listen(ctx, xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{ProtocolSettings: &Config{}}, func(conn stat.Connection) { accepted.Add(1); conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-l.(*Listener).done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not join")
	}
	if accepted.Load() != 0 {
		t.Fatal("unexpected accepted stream")
	}
	if _, err := Listen(ctx, xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{ProtocolSettings: &Config{}}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled listener created", err)
	}
}

func TestForkLegacyQUICMultipleStreams(t *testing.T) {
	serverTLS, clientTLS := certificateSettings(t)
	config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: protocol.SecurityType_CHACHA20_POLY1305}, HeaderType: "wireguard"}
	done := make(chan error, 2)
	var accepted atomic.Int32
	listener, err := Listen(context.Background(), xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{ProtocolSettings: config, SecurityType: "tls", SecuritySettings: serverTLS}, func(conn stat.Connection) {
		accepted.Add(1)
		go func() { defer conn.Close(); done <- echoStream(conn.(*streamConn).Stream) }()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	transport := &q.Transport{Conn: oracle(t, raw, config.Security.Type, config.HeaderType), DisableGSO: true}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	parent, err := transport.Dial(ctx, listener.Addr(), clientTLS.GetTLSConfig(), &q.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.CloseWithError(0, "")
	for range 2 {
		stream, err := parent.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conn := &streamConn{Stream: stream, parent: parent}
		streamExchange(t, conn, conn.CloseWrite)
		conn.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("independent stream did not finish")
		}
	}
	if accepted.Load() != 2 {
		t.Fatal("closing a stream affected its sibling")
	}
}
