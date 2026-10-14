package core

import (
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

func grpcServerPaths(service string) (string, string, error) {
	if service == "" {
		service = "GunService"
	}
	if !strings.HasPrefix(service, "/") {
		path := "/" + url.PathEscape(service) + "/"
		return path + "Tun", path + "TunMulti", nil
	}
	parts := strings.Split(service, "/")
	if len(parts) < 3 {
		return "", "", errors.New("GRPC_SERVER_SERVICE_INVALID")
	}
	methods := strings.Split(parts[len(parts)-1], "|")
	if len(methods) > 2 || methods[0] == "" {
		return "", "", errors.New("GRPC_SERVER_SERVICE_INVALID")
	}
	multi := "TunMulti"
	if len(methods) == 2 {
		if methods[1] == "" || methods[0] == methods[1] {
			return "", "", errors.New("GRPC_SERVER_SERVICE_INVALID")
		}
		multi = methods[1]
	}
	if methods[0] == multi {
		return "", "", errors.New("GRPC_SERVER_SERVICE_INVALID")
	}
	var segments []string
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			return "", "", errors.New("GRPC_SERVER_SERVICE_INVALID")
		}
		segments = append(segments, url.PathEscape(part))
	}
	path := "/" + strings.Join(segments, "/") + "/"
	return path + url.PathEscape(methods[0]), path + url.PathEscape(multi), nil
}

type grpcServerConn struct {
	request         *http.Request
	writer          http.ResponseWriter
	controller      *http.ResponseController
	local, remote   net.Addr
	readMu, writeMu sync.Mutex
	codec           grpcCodec
	buffer          [32768]byte
	pending         []byte
	readErr         error
	closed          atomic.Bool
	writeClosed     atomic.Bool
	once            sync.Once
}

func (c *grpcServerConn) LocalAddr() net.Addr  { return c.local }
func (c *grpcServerConn) RemoteAddr() net.Addr { return c.remote }
func (c *grpcServerConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *grpcServerConn) SetReadDeadline(t time.Time) error  { return c.controller.SetReadDeadline(t) }
func (c *grpcServerConn) SetWriteDeadline(t time.Time) error { return c.controller.SetWriteDeadline(t) }
func (c *grpcServerConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeClosed.Store(true)
	return nil
}
func (c *grpcServerConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		if !c.writeClosed.Load() {
			c.controller.SetWriteDeadline(time.Now())
		}
		c.request.Body.Close()
	})
	return nil
}
func (c *grpcServerConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		n, err := c.request.Body.Read(c.buffer[:])
		plain, decodeErr := c.codec.decode(c.buffer[:n])
		if decodeErr != nil {
			return 0, decodeErr
		}
		c.pending, c.readErr = plain, err
		if err == io.EOF && len(c.codec.input) > 0 {
			c.readErr = io.ErrUnexpectedEOF
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *grpcServerConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() || c.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), 8192)
		wire, err := c.codec.encode(b[:n])
		if err == nil {
			err = writeAll(c.writer, wire)
		}
		if err == nil {
			err = c.controller.Flush()
		}
		if err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// Keep the listener's setup deadline until the prior-knowledge preface is
// validated. Afterwards HTTP/2 owns stream deadlines and parent idle policy.
type serverH2PrefaceConn struct {
	net.Conn
	read int
}

func (c *serverH2PrefaceConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.read < len(http2.ClientPreface) {
		checked := min(n, len(http2.ClientPreface)-c.read)
		if string(b[:checked]) != http2.ClientPreface[c.read:c.read+checked] {
			return 0, errors.New("HTTP2_SERVER_PREFACE")
		}
		c.read += checked
		if c.read == len(http2.ClientPreface) {
			if deadlineErr := c.Conn.SetDeadline(time.Time{}); deadlineErr != nil {
				return n, deadlineErr
			}
		}
	}
	return n, err
}

func (e *Engine) serveGRPCServer(raw net.Conn, s serverSpec) {
	single, multi, _ := grpcServerPaths(s.transport.Service)
	// The connection and each protocol stream have separate shared admission.
	// Native HTTP/2 handles transport framing; protocol workers stay engine-owned.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		if e.closed || e.ctx.Err() != nil {
			e.mu.Unlock()
			return
		}
		e.workers.Add(1)
		e.mu.Unlock()
		defer e.workers.Done()
		path := r.URL.EscapedPath()
		isMulti := path == multi
		if s.transport.Service == "" && path == "//TunMulti" {
			isMulti = true
		}
		validPath := path == single || isMulti || s.transport.Service == "" && path == "//Tun"
		media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		validMedia := mediaErr == nil && (media == "application/grpc" || strings.HasPrefix(media, "application/grpc+") && len(media) > len("application/grpc+"))
		if r.Method != "POST" || r.ProtoMajor != 2 || !validPath || !serverHostMatches(r.Host, s.transport.Host) || !validMedia || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Grpc-Encoding")) > 1 || r.Header.Get("Grpc-Encoding") != "" && r.Header.Get("Grpc-Encoding") != "identity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !e.acquire() {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "8")
			w.WriteHeader(http.StatusOK)
			return
		}
		defer e.release()
		c := &grpcServerConn{request: r, writer: w, controller: http.NewResponseController(w), local: raw.LocalAddr(), remote: raw.RemoteAddr(), codec: grpcCodec{multi: isMulti}}
		if !e.track(c) {
			return
		}
		defer e.untrack(c)
		defer c.Close()
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Encoding", "identity")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		if err := c.controller.Flush(); err != nil {
			return
		}
		deadline := time.Now().Add(e.config.ConnectTimeout)
		if c.SetDeadline(deadline) != nil {
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(e.ctx, func() { cancel(); c.Close() })
		defer stop()
		// The native handler is already registered with the engine. Run the
		// protocol here instead of adding another worker and completion channel.
		conn := net.Conn(c)
		if s.encryption != nil {
			encrypted, err := s.encryption.handshake(ctx, c, deadline)
			if err != nil {
				return
			}
			conn = encrypted
		}
		e.serveServerContext(ctx, conn, s)
		if c.writeClosed.Load() {
			w.Header().Set("Grpc-Status", "0")
		} else {
			w.Header().Set("Grpc-Status", "7")
		}
	})
	h2 := &http2.Server{MaxConcurrentStreams: uint32(e.config.MaxConnections), MaxReadFrameSize: 16384, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096,
		MaxUploadBufferPerConnection: 1048576, MaxUploadBufferPerStream: 65536, IdleTimeout: e.config.IdleTimeout, WriteByteTimeout: e.config.ConnectTimeout}
	base := &http.Server{Handler: handler, MaxHeaderBytes: 8192, ReadTimeout: e.config.ConnectTimeout, WriteTimeout: e.config.ConnectTimeout, IdleTimeout: e.config.IdleTimeout}
	h2.ServeConn(&serverH2PrefaceConn{Conn: raw}, &http2.ServeConnOpts{Context: e.ctx, BaseConfig: base, Handler: handler})
}
