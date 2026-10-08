// Project-owned TLS/QUIC event adapter for the pinned HTTP3 library.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
	"vpn-core/tls-provider/quicbridge"
)

type projectQUIC struct {
	conn   *utls.UQUICConn
	config *utls.Config
	alpn   []string
	params []byte
}

// The pinned QUIC library recognizes crypto/tls alerts, while uTLS has its
// own alert type. Retain the typed cause before that boundary discards it.
// This slot belongs to one dial only; it contains a numeric class, never text.
type observedQUIC struct {
	quicbridge.Conn
	cause *atomic.Int32
}

func (q *observedQUIC) observe(err error) {
	if err != nil {
		if code := tlsErrorCode(err, 0); code != 0 {
			q.cause.CompareAndSwap(0, int32(code))
		}
	}
}
func (q *observedQUIC) Start(ctx context.Context) error {
	err := q.Conn.Start(ctx)
	q.observe(err)
	return err
}
func (q *observedQUIC) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	err := q.Conn.HandleData(level, data)
	q.observe(err)
	return err
}
func (q *observedQUIC) NextEvent() tls.QUICEvent {
	event := q.Conn.NextEvent()
	q.observe(event.Err)
	return event
}

func (p *projectQUIC) SetTransportParameters(b []byte) {
	p.params = append([]byte{}, b...)
	p.conn.SetTransportParameters(b)
}
func (p *projectQUIC) Start(ctx context.Context) error {
	u := p.conn.UnderlyingUConn()
	if err := u.BuildHandshakeState(); err != nil {
		return err
	}
	filtered := u.Extensions[:0]
	for _, ext := range u.Extensions {
		switch v := ext.(type) {
		case *utls.ALPNExtension:
			v.AlpnProtocols = append([]string{}, p.alpn...)
		case *utls.SessionTicketExtension:
			continue
		case *utls.RenegotiationInfoExtension:
			continue
		}
		filtered = append(filtered, ext)
	}
	u.Extensions = append(filtered, &utls.GenericExtension{Id: 57, Data: p.params})
	if err := enforceTLSVersions(u, p.config, utls.VersionTLS13); err != nil {
		return err
	}
	// QUIC never uses TLS compatibility-mode session IDs.
	u.HandshakeState.Hello.SessionId = nil
	return p.conn.Start(ctx)
}
func (p *projectQUIC) Close() error { return p.conn.Close() }
func (p *projectQUIC) NextEvent() tls.QUICEvent {
	e := p.conn.NextEvent()
	return tls.QUICEvent{Kind: tls.QUICEventKind(e.Kind), Level: tls.QUICEncryptionLevel(e.Level), Data: e.Data, Suite: e.Suite, Err: e.Err}
}
func (p *projectQUIC) HandleData(l tls.QUICEncryptionLevel, b []byte) error {
	return p.conn.HandleData(utls.QUICEncryptionLevel(l), b)
}
func (p *projectQUIC) StoreSession(*tls.SessionState) error {
	return errors.New("HTTP3 session events disabled")
}
func (p *projectQUIC) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("client session ticket")
}
func (p *projectQUIC) ConnectionState() tls.ConnectionState {
	s := p.conn.ConnectionState()
	return tls.ConnectionState{Version: s.Version, HandshakeComplete: s.HandshakeComplete, DidResume: s.DidResume, CipherSuite: s.CipherSuite, NegotiatedProtocol: s.NegotiatedProtocol, NegotiatedProtocolIsMutual: s.NegotiatedProtocolIsMutual, ServerName: s.ServerName, PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains, OCSPResponse: s.OCSPResponse, SignedCertificateTimestamps: s.SignedCertificateTimestamps, TLSUnique: s.TLSUnique, ECHAccepted: s.ECHAccepted}
}
func quicFactory(c settings) quicbridge.Factory {
	return quicFactoryFor(c, []string{"h3"})
}
func quicFactoryFor(c settings, alpn []string) quicbridge.Factory {
	return func(ctx context.Context, std *tls.Config) (quicbridge.Conn, error) {
		roots, err := tlsRoots(c)
		if err != nil {
			return nil, err
		}
		cfg := &utls.Config{ServerName: c.ServerName, RootCAs: roots, MinVersion: utls.VersionTLS13, NextProtos: alpn, SessionTicketsDisabled: true}
		if len(c.Pins) > 0 || len(c.Names) > 0 {
			cfg.InsecureSkipVerify = true
			cfg.VerifyPeerCertificate = verifyConfigured(c, roots)
		}
		if c.ECH != "" {
			config, err := resolveECH(ctx, c.ECH, c.ServerName, roots)
			if err != nil {
				return nil, providerError(tlsErrorCode(err, 309))
			}
			cfg.EncryptedClientHelloConfigList = config
		}
		id, err := profile(c.Fingerprint)
		if err != nil {
			return nil, providerError(302)
		}
		if id == utls.HelloGolang {
			native := std.Clone()
			native.ServerName = c.ServerName
			native.RootCAs = roots
			native.MinVersion = tls.VersionTLS13
			native.NextProtos = append([]string{}, alpn...)
			native.SessionTicketsDisabled = true
			native.ClientSessionCache = nil
			native.VerifyPeerCertificate = cfg.VerifyPeerCertificate
			native.InsecureSkipVerify = cfg.InsecureSkipVerify
			native.EncryptedClientHelloConfigList = cfg.EncryptedClientHelloConfigList
			return tls.QUICClient(&tls.QUICConfig{TLSConfig: native}), nil
		}
		// Building a browser profile writes its default ALPN back into cfg.
		// Retain the carrier's protocols separately before that mutation.
		return &projectQUIC{conn: utls.UQUICClient(&utls.QUICConfig{TLSConfig: cfg}, id), config: cfg, alpn: append([]string{}, alpn...)}, nil
	}
}
func (s *xSession) http3Client(c xSettings, x xOptions) (*http.Client, func(), error) {
	if c.TLS.Security != "tls" {
		return nil, nil, providerError(400)
	}
	transport := &http3.Transport{DisableCompression: true, QUICConfig: &quic.Config{HandshakeIdleTimeout: time.Duration(c.TLS.TimeoutMS) * time.Millisecond, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: time.Duration(x.Xmux.HKeepAlivePeriod) * time.Second}}
	transport.Dial = func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		timeout, cancel := context.WithTimeout(ctx, time.Duration(c.TLS.TimeoutMS)*time.Millisecond)
		defer cancel()
		var cause atomic.Int32
		factory := quicFactory(c.TLS)
		timeout = quicbridge.WithFactory(timeout, func(ctx context.Context, config *tls.Config) (quicbridge.Conn, error) {
			conn, err := factory(ctx, config)
			observer := &observedQUIC{Conn: conn, cause: &cause}
			observer.observe(err)
			if err != nil {
				return nil, err
			}
			return observer, nil
		})
		address, err := outboundUDPAddress(timeout, net.JoinHostPort(c.Server, strconv.Itoa(c.Port)))
		if err != nil {
			return nil, err
		}
		udp, err := outboundPacket(timeout, "udp", ":0")
		if err != nil {
			return nil, err
		}
		qt := &quic.Transport{Conn: udp}
		conn, err := qt.Dial(timeout, address, tlsConfig, config)
		if err != nil {
			_ = qt.Close()
			_ = udp.Close()
			if code := cause.Load(); code != 0 {
				return nil, providerError(code)
			}
			return nil, err
		}
		go func() { <-conn.Context().Done(); _ = qt.Close(); _ = udp.Close() }()
		state := conn.ConnectionState().TLS
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h3" || !permittedCipher(state.CipherSuite) {
			_ = conn.CloseWithError(0, "TLS policy")
			return nil, providerError(310)
		}
		s.mu.Lock()
		s.version, s.alpn = state.Version, state.NegotiatedProtocol
		if s.state == 0 {
			s.state = 1
		}
		s.mu.Unlock()
		return conn, nil
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, func() { _ = transport.Close() }, nil
}
