package http

import (
	"context"
	"io"
	gonet "net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// clientConn owns one HTTP/2 connection, not a process-global idle-client cache.
// Two zero-buffer net.Pipes provide renewable per-direction deadlines and upload
// half-close without an extra upload copy or unbounded upload/download queue.
type clientConn struct {
	net.Conn
	upload, body, download, output net.Conn
	parent                         *http2.ClientConn
	cancel                         context.CancelFunc
	once                           sync.Once
	mu                             sync.Mutex
	err                            error
	done                           chan struct{}
	workerDone                     chan struct{}
}

func (c *clientConn) finish(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		c.cancel()
		c.Conn.Close()
		c.parent.Close()
		c.upload.Close()
		c.body.Close()
		c.output.Close()
		c.download.Close()
		close(c.done)
	})
}

func (c *clientConn) result(n int, err error) (int, error) {
	if err != nil && n == 0 {
		c.mu.Lock()
		cause := c.err
		c.mu.Unlock()
		if cause != nil {
			return n, cause
		}
	}
	return n, err
}

func (c *clientConn) Read(p []byte) (int, error)         { return c.result(c.download.Read(p)) }
func (c *clientConn) Write(p []byte) (int, error)        { return c.result(c.upload.Write(p)) }
func (c *clientConn) CloseWrite() error                  { return c.upload.Close() }
func (c *clientConn) Close() error                       { c.finish(gonet.ErrClosed); return nil }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.download.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return c.upload.SetWriteDeadline(t) }
func (c *clientConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func Dial(ctx context.Context, dest net.Destination, settings *internet.MemoryStreamConfig) (stat.Connection, error) {
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
	realitySecurity := reality.ConfigFromStreamSettings(settings)
	if (settings.SecuritySettings != nil || settings.SecurityType != "") && tls.ConfigFromStreamSettings(settings) == nil && realitySecurity == nil {
		return nil, errors.New("legacy HTTP/2 supports TLS, REALITY or explicit cleartext h2c, not this security type")
	}
	u, _ := config.requestURL()
	u.Scheme, u.Host = "http", dest.NetAddr()
	var raw net.Conn
	var err error
	dest.Network = net.Network_TCP
	handshake, cancelHandshake := context.WithTimeout(ctx, 4*time.Second)
	defer cancelHandshake()
	if settings.FinalMask != nil {
		raw, err = settings.FinalMask.DialTCP(handshake, dest)
	} else {
		raw, err = internet.DialSystem(handshake, dest, settings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			raw.Close()
		}
	}()
	if security := tls.ConfigFromStreamSettings(settings); security != nil {
		cfg := security.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto(http2.NextProtoTLS))
		if !slices.Contains(cfg.NextProtos, http2.NextProtoTLS) {
			return nil, errors.New("legacy HTTP/2 TLS requires h2 ALPN")
		}
		if fingerprint := tls.GetFingerprint(security.Fingerprint); fingerprint != nil {
			raw = tls.UClient(raw, cfg, fingerprint)
		} else {
			raw = tls.Client(raw, cfg)
		}
		secure := raw.(tls.Interface)
		if err := secure.HandshakeContext(handshake); err != nil {
			return nil, err
		}
		if secure.NegotiatedProtocol() != http2.NextProtoTLS {
			return nil, errors.New("legacy HTTP/2 TLS did not negotiate h2")
		}
		u.Scheme = "https"
	} else if realitySecurity != nil {
		// Keep the original REALITY authentication/fingerprint implementation.
		// Closing the underlying socket also bounds a stalled handshake on cancel.
		handshakeSocket := raw
		stop := context.AfterFunc(handshake, func() { handshakeSocket.Close() })
		defer stop()
		secure, err := reality.UClient(raw, realitySecurity, handshake, dest)
		if err != nil {
			return nil, err
		}
		raw = secure
		state, ok := secure.(*reality.UConn)
		if !ok || !state.Verified || !realityHTTP2ALPN(state.ConnectionState().NegotiatedProtocol) {
			return nil, errors.New("legacy HTTP/2 REALITY authentication or ALPN mismatch")
		}
		u.Scheme = "https"
	}
	// NewClientConn may write the preface; bound that I/O and honor cancellation.
	stopHandshake := context.AfterFunc(handshake, func() { raw.Close() })
	defer stopHandshake()
	transport := &http2.Transport{DisableCompression: true, AllowHTTP: true, ReadIdleTimeout: time.Duration(config.IdleTimeout) * time.Second, PingTimeout: time.Duration(config.HealthCheckTimeout) * time.Second, MaxHeaderListSize: 8192}
	parent, err := transport.NewClientConn(raw)
	if err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	upload, body := gonet.Pipe()
	download, output := gonet.Pipe()
	c := &clientConn{Conn: raw, upload: upload, body: body, download: download, output: output, parent: parent, cancel: cancel, done: make(chan struct{}), workerDone: make(chan struct{})}
	req, err := http.NewRequestWithContext(streamCtx, config.requestMethod(), u.String(), body)
	if err != nil {
		c.finish(err)
		return nil, err
	}
	if len(config.Host) != 0 {
		req.Host = config.Host[dice.Roll(len(config.Host))]
	}
	config.applyHeaders(req.Header)
	req.Header.Set("Accept-Encoding", "identity")
	stop := context.AfterFunc(ctx, func() { c.finish(ctx.Err()) })
	go func() {
		defer close(c.workerDone)
		defer stop()
		response, err := parent.RoundTrip(req)
		if err != nil {
			c.finish(err)
			return
		}
		defer response.Body.Close()
		encoding := response.Header.Values("Content-Encoding")
		if response.ProtoMajor != 2 || response.StatusCode != 200 || len(encoding) > 1 || (len(encoding) == 1 && encoding[0] != "" && encoding[0] != "identity") {
			c.finish(errors.New("invalid legacy HTTP/2 response: status ", response.StatusCode))
			return
		}
		_, err = io.Copy(output, response.Body)
		if err == nil {
			err = io.EOF
		}
		c.finish(err)
	}()
	owned = true
	return c, nil
}

func init() { common.Must(internet.RegisterTransportDialer(protocolName, Dial)) }
