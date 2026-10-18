package quic

import (
	"context"
	gotls "crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	q "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func settingsConfig(settings *internet.MemoryStreamConfig) (*Config, error) {
	if settings == nil {
		return nil, errors.New("legacy QUIC: missing settings")
	}
	config, ok := settings.ProtocolSettings.(*Config)
	if !ok {
		return nil, errors.New("legacy QUIC: invalid settings")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if (settings.SecuritySettings != nil || settings.SecurityType != "") && tls.ConfigFromStreamSettings(settings) == nil {
		return nil, errors.New("legacy QUIC: unsupported or missing TLS settings")
	}
	if err := ValidateLegacyQUICParams(settings.QuicParams); err != nil {
		return nil, err
	}
	return config, nil
}

func transportTLS(settings *internet.MemoryStreamConfig, dest xnet.Destination, server bool) (*gotls.Config, error) {
	security := tls.ConfigFromStreamSettings(settings)
	legacy := security == nil
	if security == nil {
		// Explicit legacy no-TLS-settings mode still uses QUIC TLS1.3 with the
		// historical internal certificate, NOT certificate-policy fallback.
		security = &tls.Config{ServerName: internalDomain}
		if server {
			certificate, _ := cert.MustGenerate(nil, cert.DNSNames(internalDomain), cert.CommonName(internalDomain))
			security.Certificate = []*tls.Certificate{tls.ParseCertificate(certificate)}
		}
	} else if !server && security.Fingerprint != "" && security.Fingerprint != "unsafe" && security.Fingerprint != "hellogolang" && security.Fingerprint != "chrome" {
		return nil, errors.New("legacy QUIC: explicit browser TLS fingerprints are not implemented")
	}
	config := security.GetTLSConfig(tls.WithDestination(dest))
	if legacy && !server {
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = nil
	}
	if config.MaxVersion != 0 && config.MaxVersion < gotls.VersionTLS13 {
		return nil, errors.New("legacy QUIC requires TLS1.3")
	}
	config.MinVersion = gotls.VersionTLS13
	return config, nil
}


func applyLegacyQUICChromeProfile(settings *internet.MemoryStreamConfig, transport *q.Transport, config *q.Config) {
	if profile := tls.ConfigFromStreamSettings(settings); profile != nil && profile.Fingerprint == "chrome" {
		// Native QUIC profile from the pinned quic-go fork, not a
		// substitution for uTLS ClientHello wire verification.
		config.ChromeParrot = true
		transport.ConnectionIDGenerator = q.ZeroLengthConnectionIDGenerator{}
	}
}

func quicConfig() *q.Config {
	return &q.Config{HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 60 * time.Second, InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIncomingStreams: 32, MaxIncomingUniStreams: -1}
}

// There is no process-global connection pool. A dial owns one session/socket;
// the listener may accept up to32 independent bidirectional streams per peer.
type streamConn struct {
	*q.Stream
	parent    *q.Conn
	transport *q.Transport
	packet    net.PacketConn
	mu        sync.Mutex
	closed    bool
	stop      func() bool
	once      sync.Once
}

func (c *streamConn) LocalAddr() net.Addr  { return c.parent.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.parent.RemoteAddr() }
func (c *streamConn) CloseWrite() error    { return c.Stream.Close() }
func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		stop := c.stop
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		c.Stream.SetWriteDeadline(time.Now())
		c.Stream.Close()
		c.Stream.CancelRead(0)
		if c.transport != nil {
			c.parent.CloseWithError(0, "")
			c.transport.Close()
			c.packet.Close()
		}
	})
	return nil
}

func Dial(ctx context.Context, dest xnet.Destination, settings *internet.MemoryStreamConfig) (stat.Connection, error) {
	config, err := settingsConfig(settings)
	if err != nil {
		return nil, err
	}
	security, err := transportTLS(settings, dest, false)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dest.Network = xnet.Network_UDP
	handshake, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	var raw xnet.Conn
	if settings.FinalMask != nil {
		raw, err = settings.FinalMask.DialUDP(handshake, dest)
	} else {
		raw, err = internet.DialSystem(handshake, dest, settings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}
	carrier, ok := raw.(*xnet.PacketConnWrapper)
	if !ok {
		raw.Close()
		return nil, errors.New("legacy QUIC: unsupported packet carrier")
	}
	packet, err := wrapPacket(carrier.PacketConn, config)
	if err != nil {
		raw.Close()
		return nil, err
	}
	transport := &q.Transport{Conn: packet, ConnectionIDLength: 12, DisableGSO: true}
	quicDialConfig := tunedLegacyQUICConfig(settings.QuicParams)
	applyLegacyQUICChromeProfile(settings,transport,quicDialConfig)
	owned := false
	defer func() {
		if !owned {
			transport.Close()
			packet.Close()
		}
	}()
	parent, err := transport.Dial(handshake, carrier.RemoteAddr(), security, quicDialConfig)
	if err != nil {
		return nil, err
	}
	applyLegacyQUICCongestion(parent, settings.QuicParams, false)
	stream, err := parent.OpenStreamSync(handshake)
	if err != nil {
		parent.CloseWithError(0, "")
		return nil, err
	}
	c := &streamConn{Stream: stream, parent: parent, transport: transport, packet: packet}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	c.mu.Lock()
	if c.closed {
		stop()
	} else {
		c.stop = stop
	}
	c.mu.Unlock()
	owned = true
	return c, nil
}

type Listener struct {
	packet      net.PacketConn
	transport   *q.Transport
	listener    *q.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	handler     internet.ConnHandler
	mu          sync.Mutex
	closed      bool
	stop        func() bool
	connections map[*q.Conn]struct{}
	tuning      *internet.QuicParams
	workers     sync.WaitGroup
	done        chan struct{}
}

func (l *Listener) Addr() xnet.Addr { return l.listener.Addr() }
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		<-l.done
		return nil
	}
	l.closed = true
	if l.stop != nil {
		l.stop()
	}
	l.cancel()
	l.listener.Close()
	connections := make([]*q.Conn, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		conn.CloseWithError(0, "")
	}
	l.transport.Close()
	l.packet.Close()
	l.workers.Wait()
	close(l.done)
	return nil
}

func (l *Listener) accept() {
	defer l.workers.Done()
	for {
		conn, err := l.listener.Accept(l.ctx)
		if err != nil {
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			conn.CloseWithError(0, "")
			return
		}
		applyLegacyQUICCongestion(conn, l.tuning, true)
		l.connections[conn] = struct{}{}
		l.workers.Add(1)
		l.mu.Unlock()
		go func() {
			defer l.workers.Done()
			defer func() { conn.CloseWithError(0, ""); l.mu.Lock(); delete(l.connections, conn); l.mu.Unlock() }()
			for {
				stream, err := conn.AcceptStream(l.ctx)
				if err != nil {
					return
				}
				l.handler(&streamConn{Stream: stream, parent: conn})
			}
		}()
	}
}

func Listen(ctx context.Context, address xnet.Address, port xnet.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := settingsConfig(settings)
	if err != nil {
		return nil, err
	}
	if address == nil || address.Family().IsDomain() {
		return nil, errors.New("legacy QUIC: listen address must be an IP")
	}
	security, err := transportTLS(settings, xnet.UDPDestination(address, port), true)
	if err != nil {
		return nil, err
	}
	addr := &xnet.UDPAddr{IP: address.IP(), Port: int(port)}
	var raw xnet.PacketConn
	if settings.FinalMask != nil {
		raw, err = settings.FinalMask.ListenPacket(ctx, addr)
	} else {
		raw, err = internet.ListenSystemPacket(ctx, addr, settings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}
	packet, err := wrapPacket(raw, config)
	if err != nil {
		raw.Close()
		return nil, err
	}
	transport := &q.Transport{Conn: packet, ConnectionIDLength: 12, DisableGSO: true}
	listener, err := transport.Listen(security, tunedLegacyQUICConfig(settings.QuicParams))
	if err != nil {
		transport.Close()
		packet.Close()
		return nil, err
	}
	listenCtx, cancel := context.WithCancel(ctx)
	l := &Listener{packet: packet, transport: transport, listener: listener, ctx: listenCtx, cancel: cancel, handler: handler, connections: make(map[*q.Conn]struct{}), tuning: settings.QuicParams, done: make(chan struct{})}
	l.workers.Add(1)
	stop := context.AfterFunc(ctx, func() { l.Close() })
	l.mu.Lock()
	if l.closed {
		stop()
	} else {
		l.stop = stop
	}
	l.mu.Unlock()
	go l.accept()
	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
