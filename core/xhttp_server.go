package core

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Native HTTP owns socket framing; admission and closure stay engine-owned.
type admittedHTTPListener struct {
	net.Listener
	owner *Engine
}
type admittedHTTPConn struct {
	net.Conn
	owner *Engine
	once  sync.Once
}

func (c *admittedHTTPConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.untrack(c)
		c.owner.release()
	})
	return err
}
func (l *admittedHTTPListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.owner.acquire() {
			conn.Close()
			continue
		}
		c := &admittedHTTPConn{Conn: conn, owner: l.owner}
		if !l.owner.track(c) {
			return nil, net.ErrClosed
		}
		l.owner.accepted.Add(1)
		return c, nil
	}
}

func (e *Engine) startXHTTPServer(s serverSpec) (net.Addr, error) {
	var listener net.Listener
	var packets *ssUDPServer
	var err error
	if s.ss != nil && s.ss.udp {
		listener, packets, err = e.listenSSServer(s.ss, s.config.Listen, net.Listen)
	} else {
		listener, err = net.Listen("tcp", s.config.Listen)
		if err == nil && !e.track(listener) {
			return nil, net.ErrClosed
		}
	}
	if err != nil {
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(s.transport.HTTPVersion != "h2")
	protocols.SetHTTP2(s.transport.HTTPVersion != "h1")
	protocols.SetUnencryptedHTTP2(s.transport.HTTPVersion != "h1")
	server := &http.Server{ReadHeaderTimeout: e.config.ConnectTimeout, ReadTimeout: e.config.ConnectTimeout, WriteTimeout: e.config.ConnectTimeout, IdleTimeout: e.config.IdleTimeout, MaxHeaderBytes: 8192, Protocols: protocols,
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: e.config.MaxConnections, MaxReadFrameSize: 16384, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096,
			MaxReceiveBufferPerConnection: 1048576, MaxReceiveBufferPerStream: 65536, WriteByteTimeout: e.config.ConnectTimeout},
		BaseContext: func(net.Listener) context.Context { return e.ctx }}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.ownHTTPHandler() {
			return
		}
		defer e.workers.Done()
		if r.Method != s.transport.Method || r.URL.Path != s.transport.Path || !serverHostMatches(r.Host, s.transport.Host) || r.Header.Get("X-Session") != "" || r.Header.Get("X-Seq") != "" || r.URL.Query().Get("x_session") != "" || r.URL.Query().Get("x_seq") != "" || len(r.Header.Values("Content-Encoding")) > 1 || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !e.acquire() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer e.release()
		controller := http.NewResponseController(w)
		if r.ProtoMajor == 1 && controller.EnableFullDuplex() != nil {
			return
		}
		remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		if err != nil {
			return
		}
		local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		c := &serverHTTP2Conn{request: r, writer: w, controller: controller, local: local, remote: remote}
		if !e.track(c) {
			return
		}
		defer e.untrack(c)
		defer c.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "identity")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("X-Padding", strings.Repeat("X", 100))
		w.WriteHeader(http.StatusOK)
		if controller.Flush() != nil {
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
		conn := net.Conn(c)
		if s.encryption != nil {
			encrypted, err := s.encryption.handshake(ctx, c, deadline)
			if err != nil {
				return
			}
			conn = encrypted
		}
		e.serveServerContext(ctx, conn, s)
	})
	if !e.track(server) || !e.spawn(func() {
		defer e.untrack(server)
		defer server.Close()
		defer e.untrack(listener)
		defer listener.Close()
		if packets != nil {
			defer packets.stop()
		}
		admitted := net.Listener(&admittedHTTPListener{Listener: listener, owner: e})
		if s.tls != nil {
			admitted = tls.NewListener(admitted, s.tls)
		}
		server.Serve(admitted)
	}) {
		server.Close()
		listener.Close()
		e.untrack(listener)
		e.untrack(server)
		if packets != nil {
			packets.stop()
		}
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return listener.Addr(), nil
}
