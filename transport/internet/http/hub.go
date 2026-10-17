package http

import (
	"context"
	gotls "crypto/tls"
	"io"
	gonet "net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type serverConn struct {
	request       *http.Request
	writer        http.ResponseWriter
	controller    *http.ResponseController
	local, remote net.Addr
	writeMu       sync.Mutex
	deadlineMu    sync.Mutex
	closed        atomic.Bool
	once          sync.Once
	done          chan struct{}
}

func (c *serverConn) Read(p []byte) (int, error) { return c.request.Body.Read(p) }
func (c *serverConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, gonet.ErrClosed
	}
	n, err := c.writer.Write(p)
	if err == nil {
		err = c.controller.Flush()
	}
	return n, err
}

func (c *serverConn) Close() error {
	c.once.Do(func() {
		c.deadlineMu.Lock()
		c.closed.Store(true)
		// Unblock a flow-control-stalled Write before joining it; ServeHTTP must
		// not return while another goroutine still uses the ResponseWriter.
		if c.writeMu.TryLock() {
			c.deadlineMu.Unlock()
			c.request.Body.Close()
			close(c.done)
			c.writeMu.Unlock()
			return
		}
		c.controller.SetWriteDeadline(time.Now())
		c.deadlineMu.Unlock()
		c.request.Body.Close()
		c.writeMu.Lock()
		close(c.done)
		c.writeMu.Unlock()
	})
	return nil
}
func (c *serverConn) LocalAddr() net.Addr  { return c.local }
func (c *serverConn) RemoteAddr() net.Addr { return c.remote }
func (c *serverConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed.Load() {
		return gonet.ErrClosed
	}
	return c.controller.SetReadDeadline(t)
}

func (c *serverConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed.Load() {
		return gonet.ErrClosed
	}
	return c.controller.SetWriteDeadline(t)
}

func (c *serverConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

type Listener struct {
	listener      net.Listener
	config        *Config
	tlsConfig     *gotls.Config
	realityConfig *goreality.Config
	handler       internet.ConnHandler
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	closed        bool
	connections   map[net.Conn]struct{}
	streams       map[*serverConn]struct{}
	workers       sync.WaitGroup
	done          chan struct{}
	stopParent    func() bool
}

func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		<-l.done
		return nil
	}
	l.closed = true
	if l.stopParent != nil {
		l.stopParent()
	}
	l.cancel()
	l.listener.Close()
	for conn := range l.connections {
		conn.Close()
	}
	streams := make([]*serverConn, 0, len(l.streams))
	for conn := range l.streams {
		streams = append(streams, conn)
	}
	l.mu.Unlock()
	for _, conn := range streams {
		conn.Close()
	}
	l.workers.Wait()
	close(l.done)
	return nil
}

func (l *Listener) serveHTTP(w http.ResponseWriter, r *http.Request, raw net.Conn, trusted []string) {
	u, _ := l.config.requestURL()
	hostOK := l.config.validHost(r.Host)
	encoding := r.Header.Values("Content-Encoding")
	if r.ProtoMajor != 2 || !hostOK || r.Method != l.config.requestMethod() || r.URL.EscapedPath() != u.EscapedPath() || r.URL.RawQuery != u.RawQuery || len(encoding) > 1 || (len(encoding) == 1 && encoding[0] != "" && encoding[0] != "identity") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c := &serverConn{request: r, writer: w, controller: http.NewResponseController(w), local: raw.LocalAddr(), remote: http_proto.ApplyTrustedXForwardedFor(r.Header, trusted, raw.RemoteAddr()), done: make(chan struct{})}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	l.streams[c] = struct{}{}
	l.workers.Add(1)
	l.mu.Unlock()
	defer func() { c.Close(); l.mu.Lock(); delete(l.streams, c); l.mu.Unlock(); l.workers.Done() }()
	l.config.applyHeaders(w.Header())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Encoding", "identity")
	w.WriteHeader(http.StatusOK)
	if err := c.controller.Flush(); err != nil {
		return
	}
	l.handler(stat.Connection(c))
	select {
	case <-c.done:
	case <-r.Context().Done():
	case <-l.ctx.Done():
	}
}

// Clear the initial handshake deadline only after the complete H2 preface. No
// HTTP/1.1 upgrade/fallback parser is added to this prior-knowledge h2c listener.
type prefaceConn struct {
	net.Conn
	remaining int
}

type prefaceTLSConn struct {
	*prefaceConn
	state gotls.ConnectionState
}

func (c *prefaceTLSConn) ConnectionState() gotls.ConnectionState { return c.state }

func (c *prefaceConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.remaining > 0 {
		c.remaining -= min(c.remaining, n)
		if c.remaining == 0 {
			c.Conn.SetReadDeadline(time.Time{})
		}
	}
	return n, err
}

func (l *Listener) accept(trusted []string) {
	defer l.workers.Done()
	for {
		raw, err := l.listener.Accept()
		if err != nil {
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			raw.Close()
			return
		}
		l.connections[raw] = struct{}{}
		l.workers.Add(1)
		l.mu.Unlock()
		go func() {
			defer l.workers.Done()
			defer func() { raw.Close(); l.mu.Lock(); delete(l.connections, raw); l.mu.Unlock() }()
			raw.SetDeadline(time.Now().Add(4 * time.Second))
			conn := raw
			var tlsState *gotls.ConnectionState
			if l.tlsConfig != nil {
				secure := tls.Server(raw, l.tlsConfig).(tls.Interface)
				ctx, cancel := context.WithTimeout(l.ctx, 4*time.Second)
				err := secure.HandshakeContext(ctx)
				cancel()
				if err != nil || secure.NegotiatedProtocol() != http2.NextProtoTLS {
					return
				}
				conn = secure
				state := secure.(*tls.Conn).ConnectionState()
				tlsState = &state
			} else if l.realityConfig != nil {
				secure, err := goreality.Server(l.ctx, raw, l.realityConfig)
				if err != nil {
					return
				}
				conn = secure
				state := secure.ConnectionState()
				if !state.HandshakeComplete || !realityHTTP2ALPN(state.NegotiatedProtocol) {
					return
				}
				// x/net/http2 expects crypto/tls state, not REALITY's distinct type.
				// Expose actual negotiated values; never represent this as h2c.
				tlsState = &gotls.ConnectionState{Version: state.Version, HandshakeComplete: state.HandshakeComplete, CipherSuite: state.CipherSuite, NegotiatedProtocol: state.NegotiatedProtocol, NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual, ServerName: state.ServerName}
			}
			raw.SetWriteDeadline(time.Time{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.serveHTTP(w, r, raw, trusted) })
			server := &http2.Server{MaxConcurrentStreams: 128, MaxReadFrameSize: 16384, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096, MaxUploadBufferPerConnection: 1 << 20, MaxUploadBufferPerStream: 65536, IdleTimeout: 120 * time.Second, ReadIdleTimeout: time.Duration(l.config.IdleTimeout) * time.Second, PingTimeout: time.Duration(l.config.HealthCheckTimeout) * time.Second}
			preface := &prefaceConn{Conn: conn, remaining: len(http2.ClientPreface)}
			var h2conn net.Conn = preface
			if tlsState != nil {
				h2conn = &prefaceTLSConn{prefaceConn: preface, state: *tlsState}
			}
			server.ServeConn(h2conn, &http2.ServeConnOpts{Context: l.ctx, BaseConfig: &http.Server{MaxHeaderBytes: 8192}, Handler: handler})
		}()
	}
}

func Listen(ctx context.Context, address net.Address, port net.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if settings == nil {
		return nil, errors.New("missing legacy HTTP/2 stream settings")
	}
	config, ok := settings.ProtocolSettings.(*Config)
	if !ok {
		return nil, errors.New("invalid legacy HTTP/2 settings")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	security := tls.ConfigFromStreamSettings(settings)
	realitySecurity := reality.ConfigFromStreamSettings(settings)
	if (settings.SecuritySettings != nil || settings.SecurityType != "") && security == nil && realitySecurity == nil {
		return nil, errors.New("legacy HTTP/2 supports TLS, REALITY or explicit cleartext h2c, not this security type")
	}
	var tlsConfig *gotls.Config
	if security != nil {
		tlsConfig = security.GetTLSConfig(tls.WithNextProto(http2.NextProtoTLS))
		if !slices.Contains(tlsConfig.NextProtos, http2.NextProtoTLS) {
			return nil, errors.New("legacy HTTP/2 TLS requires h2 ALPN")
		}
	}
	var addr net.Addr
	if port == 0 {
		addr = &net.UnixAddr{Name: address.Domain(), Net: "unix"}
	} else {
		addr = &net.TCPAddr{IP: address.IP(), Port: int(port)}
	}
	var raw net.Listener
	var err error
	if settings.FinalMask != nil {
		raw, err = settings.FinalMask.Listen(ctx, addr)
	} else {
		raw, err = internet.ListenSystem(ctx, addr, settings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}
	listenCtx, cancel := context.WithCancel(ctx)
	l := &Listener{listener: raw, config: config, tlsConfig: tlsConfig, handler: handler, ctx: listenCtx, cancel: cancel, connections: make(map[net.Conn]struct{}), streams: make(map[*serverConn]struct{}), done: make(chan struct{})}
	if realitySecurity != nil {
		l.realityConfig = boundedRealityConfig(listenCtx, realitySecurity)
		if err := waitRealityTarget(listenCtx, l.realityConfig); err != nil {
			raw.Close()
			cancel()
			return nil, err
		}
	}
	var trusted []string
	if settings.SocketSettings != nil {
		trusted = slices.Clone(settings.SocketSettings.TrustedXForwardedFor)
	}
	l.workers.Add(1)
	stop := context.AfterFunc(ctx, func() { l.Close() })
	l.mu.Lock()
	if l.closed {
		stop()
	} else {
		l.stopParent = stop
	}
	l.mu.Unlock()
	go l.accept(trusted)
	return l, nil
}

func init() { common.Must(internet.RegisterTransportListener(protocolName, Listen)) }

var (
	_ net.Conn  = (*serverConn)(nil)
	_ io.Closer = (*Listener)(nil)
)
