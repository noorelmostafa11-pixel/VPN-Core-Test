package core

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
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
	var sessions *xServerSessions
	if s.transport.Mode != "stream-one" {
		sessions = &xServerSessions{e: e}
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.serveXHTTP(w, r, s, sessions) })
	if sessions != nil && !e.track(sessions) || !e.track(server) || !e.spawn(func() {
		if sessions != nil {
			defer e.untrack(sessions)
			defer sessions.Close()
		}
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
		if sessions != nil {
			sessions.Close()
			e.untrack(sessions)
		}
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
