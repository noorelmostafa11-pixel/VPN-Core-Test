package core

import (
	"net"
	"net/http"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type xHTTP3Peer struct{ conn *quic.Conn }

func (p *xHTTP3Peer) Close() error { return p.conn.CloseWithError(0, "") }

func (e *Engine) startXHTTP3Server(s serverSpec) (net.Addr, error) {
	packet, err := net.ListenPacket("udp", s.config.Listen)
	if err != nil {
		return nil, err
	}
	configureDatagramBuffers(packet)
	transport := &quic.Transport{Conn: packet}
	config := &quic.Config{HandshakeIdleTimeout: e.config.ConnectTimeout, MaxIdleTimeout: e.config.IdleTimeout,
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true,
		InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 65536,
		InitialConnectionReceiveWindow: 1048576, MaxConnectionReceiveWindow: 1048576,
		MaxIncomingStreams: int64(min(e.config.MaxConnections, 128)), MaxIncomingUniStreams: 8}
	listener, err := transport.Listen(s.tls, config)
	if err != nil {
		transport.Close()
		packet.Close()
		return nil, err
	}
	var sessions *xServerSessions
	if s.transport.Mode != "stream-one" {
		sessions = &xServerSessions{e: e}
	}
	server := &http3.Server{MaxHeaderBytes: 8192, ReadHeaderTimeout: e.config.ConnectTimeout, IdleTimeout: e.config.IdleTimeout,
		RequestStreamAdmission: func() (func(), bool) {
			if e.ctx.Err() != nil || !e.acquire() {
				return nil, false
			}
			return e.release, true
		}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.serveXHTTP(w, r, s, sessions) })}
	cleanup := func() {
		listener.Close()
		transport.Close()
		packet.Close()
		server.Close()
		if sessions != nil {
			sessions.Close()
			e.untrack(sessions)
		}
		e.untrack(listener)
		e.untrack(transport)
		e.untrack(packet)
		e.untrack(server)
	}
	if !e.track(packet) || !e.track(transport) || !e.track(listener) || !e.track(server) || sessions != nil && !e.track(sessions) || !e.spawn(func() {
		defer cleanup()
		for {
			conn, err := listener.Accept(e.ctx)
			if err != nil {
				return
			}
			if !e.acquire() {
				conn.CloseWithError(1, "")
				continue
			}
			peer := &xHTTP3Peer{conn}
			if !e.track(peer) {
				e.release()
				return
			}
			e.accepted.Add(1)
			if !e.spawn(func() {
				defer e.release()
				defer e.untrack(peer)
				defer peer.Close()
				server.ServeQUICConn(conn)
			}) {
				peer.Close()
				e.untrack(peer)
				e.release()
				return
			}
		}
	}) {
		cleanup()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return packet.LocalAddr(), nil
}
