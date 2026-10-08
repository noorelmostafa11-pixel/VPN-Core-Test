// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Legacy QUIC stream carrier and SIP003 v2ray-plugin QUIC, without an engine.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"vpn-core/tls-provider/quicbridge"
)

type legacyQUICOptions struct {
	Cipher       string `json:"cipher"`
	Key          string `json:"key"`
	Header       string `json:"header"`
	HeaderDomain string `json:"header_domain"`
}

func (o legacyQUICOptions) protection() (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(o.Key + "xray-quic-salt"))
	switch o.Cipher {
	case "", "none":
		return nil, nil
	case "aes-128-gcm":
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-poly1305":
		return chacha20poly1305.New(key[:])
	default:
		return nil, providerError(400)
	}
}
func (o legacyQUICOptions) validate() error {
	if _, err := newPacketHeader(o.Header, o.HeaderDomain); err != nil {
		return providerError(400)
	}
	_, err := o.protection()
	return err
}

type maskedPacketConn struct {
	net.PacketConn
	header  *packetHeader
	auth    cipher.AEAD
	writeMu sync.Mutex
}

var legacyPacketBuffers = sync.Pool{New: func() any { return make([]byte, 65536) }}

func (p *maskedPacketConn) SetReadBuffer(n int) error {
	return p.PacketConn.(*net.UDPConn).SetReadBuffer(n)
}
func (p *maskedPacketConn) SetWriteBuffer(n int) error {
	return p.PacketConn.(*net.UDPConn).SetWriteBuffer(n)
}
func (p *maskedPacketConn) SyscallConn() (syscall.RawConn, error) {
	return p.PacketConn.(*net.UDPConn).SyscallConn()
}

func (p *maskedPacketConn) WriteTo(data []byte, address net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	wire := data
	if p.auth != nil {
		nonce := make([]byte, p.auth.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return 0, err
		}
		wire = p.auth.Seal(nonce, nonce, data, nil)
	}
	wire = p.header.wrap(wire)
	if _, err := p.PacketConn.WriteTo(wire, address); err != nil {
		return 0, err
	}
	return len(data), nil
}
func (p *maskedPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	buffer := legacyPacketBuffers.Get().([]byte)
	defer legacyPacketBuffers.Put(buffer)
	for {
		n, address, err := p.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, nil, err
		}
		payload, err := p.header.unwrap(buffer[:n])
		if err != nil {
			continue
		}
		if p.auth != nil {
			size := p.auth.NonceSize()
			if len(payload) < size+p.auth.Overhead() {
				continue
			}
			if len(payload)-size-p.auth.Overhead() > len(data) {
				continue
			}
			payload, err = p.auth.Open(data[:0], payload[:size], payload[size:], nil)
			if err != nil {
				continue
			}
		}
		if len(payload) > len(data) {
			continue
		}
		if p.auth != nil {
			return len(payload), address, nil
		}
		return copy(data, payload), address, nil
	}
}

type legacyQUICCloser struct{ conn *quic.Conn }

func (c legacyQUICCloser) Close() error { return c.conn.CloseWithError(0, "") }

func (s *xSession) runLegacyQUIC(c xSettings) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		cancel()
		return
	}
	s.cancel = cancel
	s.mu.Unlock()
	defer cancel()
	if err := c.QUIC.validate(); err != nil {
		s.fail(err)
		return
	}
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.Server, strconv.Itoa(c.Port)))
	if err != nil {
		s.fail(err)
		return
	}
	udp, err := net.ListenPacket("udp", ":0")
	if err != nil {
		s.fail(err)
		return
	}
	defer udp.Close()
	header, _ := newPacketHeader(c.QUIC.Header, c.QUIC.HeaderDomain)
	auth, _ := c.QUIC.protection()
	var packet net.PacketConn = udp
	if header.size() != 0 || auth != nil {
		packet = &maskedPacketConn{PacketConn: udp, header: header, auth: auth}
	}
	transport := &quic.Transport{Conn: packet, ConnectionIDLength: 12}
	defer transport.Close()
	alpn := append([]string{}, c.TLS.ALPN...)
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	handshake, done := context.WithTimeout(ctx, time.Duration(c.TLS.TimeoutMS)*time.Millisecond)
	defer done()
	var cause atomic.Int32
	factory := quicFactoryFor(c.TLS, alpn)
	handshake = quicbridge.WithFactory(handshake, func(ctx context.Context, config *tls.Config) (quicbridge.Conn, error) {
		q, e := factory(ctx, config)
		observed := &observedQUIC{Conn: q, cause: &cause}
		observed.observe(e)
		if e != nil {
			return nil, e
		}
		return observed, nil
	})
	conn, err := transport.Dial(handshake, address, &tls.Config{ServerName: c.TLS.ServerName, NextProtos: alpn, MinVersion: tls.VersionTLS13}, &quic.Config{HandshakeIdleTimeout: time.Duration(c.TLS.TimeoutMS) * time.Millisecond, MaxIdleTimeout: 60 * time.Second, InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
	if err != nil {
		if code := cause.Load(); code != 0 {
			err = providerError(code)
		}
		s.fail(err)
		return
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(handshake)
	if err != nil {
		s.fail(err)
		return
	}
	state := conn.ConnectionState().TLS
	if state.Version != tls.VersionTLS13 || !permittedCipher(state.CipherSuite) {
		s.fail(providerError(310))
		return
	}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return
	}
	s.version, s.alpn, s.state = state.Version, state.NegotiatedProtocol, 1
	s.closers = append(s.closers, legacyQUICCloser{conn})
	s.mu.Unlock()
	go func() {
		_, e := io.CopyBuffer(stream, s.up, make([]byte, 16384))
		if e == nil {
			e = stream.Close()
		}
		if e != nil {
			s.fail(e)
		}
	}()
	_, err = io.CopyBuffer(s.down, stream, make([]byte, 16384))
	if err != nil {
		s.fail(err)
		return
	}
	s.mu.Lock()
	if s.state >= 0 {
		s.state = 2
	}
	s.mu.Unlock()
	s.down.close(nil)
}
