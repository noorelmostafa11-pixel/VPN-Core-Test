package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

func validateAnyServer(c ServerConfig) error {
	for k := range c.Options {
		if k != "padding-scheme" {
			return errors.New("ANYTLS_SERVER_OPTION_UNSUPPORTED")
		}
	}
	_, err := parseAnyPadding(option(c.Options, anyDefaultPadding, "padding-scheme"))
	return err
}
func (e *Engine) startAnyServer(s serverSpec) (net.Addr, error) {
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return nil, err
	}
	if !e.track(listener) {
		return nil, net.ErrClosed
	}
	limit := e.config.MaxConnections
	if limit > 64 {
		limit = 64
	}
	slots := make(chan struct{}, limit)
	if !e.spawn(func() {
		defer listener.Close()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			if !e.track(raw) {
				<-slots
				return
			}
			if !e.spawn(func() {
				defer func() { <-slots }()
				defer e.untrack(raw)
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
				conn := tls.Server(raw, s.tls)
				if conn.HandshakeContext(e.ctx) == nil {
					e.serveAnyServer(conn, s)
				}
			}) {
				raw.Close()
				<-slots
				return
			}
		}
	}) {
		listener.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return listener.Addr(), nil
}
func (e *Engine) serveAnyServer(conn net.Conn, spec serverSpec) {
	var auth [34]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		return
	}
	want := sha256.Sum256([]byte(spec.config.Password))
	if subtle.ConstantTimeCompare(auth[:32], want[:]) != 1 {
		return
	}
	size := int(binary.BigEndian.Uint16(auth[32:]))
	if size > 16384 {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
		return
	}
	scheme, _ := parseAnyPadding(option(spec.config.Options, anyDefaultPadding, "padding-scheme"))
	session := newAnySession(conn, scheme)
	gotSettings := false
	var lastID uint32
	version := 1
	session.handle = func(command byte, id uint32, data []byte) error {
		bad := errors.New("ANYTLS_FRAME_INVALID")
		switch command {
		case anyWaste:
			return nil
		case anySettings:
			if id != 0 || gotSettings {
				return bad
			}
			settings, err := parseAnySettings(data)
			if err != nil {
				return err
			}
			gotSettings = true
			if settings["v"] == "2" {
				version = 2
				if err = session.send(anyFrame(anyServerSettings, 0, []byte("v=2")), time.Now().Add(e.config.ConnectTimeout)); err != nil {
					return err
				}
			}
			if settings["padding-md5"] != scheme.hash {
				return session.send(anyFrame(anyPadding, 0, []byte(scheme.text)), time.Now().Add(e.config.ConnectTimeout))
			}
			return nil
		case anySYN:
			if !gotSettings || id == 0 || id <= lastID || len(data) != 0 {
				return bad
			}
			lastID = id
			if !e.acquire() {
				return session.send(anyFrame(anySYNACK, id, []byte("CONNECTION_LIMIT")), time.Now().Add(time.Second))
			}
			stream := newAnyStream(session, id)
			session.mu.Lock()
			session.streams[id] = stream
			session.mu.Unlock()
			if !e.track(stream) {
				e.release()
				return net.ErrClosed
			}
			if !e.spawn(func() {
				defer e.release()
				defer e.untrack(stream)
				defer stream.Close()
				e.accepted.Add(1)
				e.serveAnyStream(stream, version)
			}) {
				stream.Close()
				e.release()
				return net.ErrClosed
			}
			return nil
		case anyPSH:
			if !gotSettings || id == 0 {
				return bad
			}
			session.mu.Lock()
			stream := session.streams[id]
			session.mu.Unlock()
			if stream != nil && !stream.push(data) {
				stream.Close()
			}
			return nil
		case anyFIN:
			if len(data) != 0 {
				return bad
			}
			session.mu.Lock()
			stream := session.streams[id]
			session.mu.Unlock()
			if stream != nil {
				stream.finish(io.EOF)
			}
			return nil
		case anyHeartRequest:
			if len(data) != 0 {
				return bad
			}
			return session.send(anyFrame(anyHeartResponse, id, nil), time.Now().Add(time.Second))
		case anyHeartResponse:
			if len(data) != 0 {
				return bad
			}
			return nil
		default:
			return bad
		}
	}
	conn.SetDeadline(time.Time{})
	session.readLoop()
}
func (e *Engine) serveAnyStream(stream *anyStream, version int) {
	stream.SetReadDeadline(time.Now().Add(e.config.ConnectTimeout))
	address, err := readAddress(stream)
	if err != nil {
		return
	}
	// The published UOT marker commonly uses port zero. It is a protocol
	// marker, not a network destination; normal proxy ports remain validated.
	if len(address) > 4 && address[0] == 3 && string(address[2:len(address)-2]) == uotV2Host && getWord(address, len(address)-2) == 0 {
		address[len(address)-1] = 1
	}
	host, port, err := decodeAddress(address)
	if err != nil {
		return
	}
	acknowledge := func(err error) error {
		if version < 2 {
			return nil
		}
		var data []byte
		if err != nil {
			data = []byte(reasonCode(err))
		}
		return stream.session.send(anyFrame(anySYNACK, stream.id, data), time.Now().Add(e.config.ConnectTimeout))
	}
	stream.SetDeadline(time.Time{})
	if host == uotV2Host {
		if acknowledge(nil) == nil {
			e.serveUOT(stream)
		}
		return
	}
	ctx := e.flowContext(e.ctx, stream.RemoteAddr(), host)
	upstream, err := e.dialTCP(ctx, host, port)
	if err != nil {
		acknowledge(err)
		return
	}
	if !e.track(upstream) {
		return
	}
	defer e.untrack(upstream)
	defer upstream.Close()
	if acknowledge(nil) != nil {
		return
	}
	e.relayAny(stream, upstream)
}
func (e *Engine) relayAny(client, remote net.Conn) {
	// FIN closes a protocol stream, not one direction. Close both relay sides
	// after either completes, then join the other worker.
	done := make(chan struct{})
	go func() { defer close(done); e.copyAny(remote, client, true); remote.Close(); client.Close() }()
	e.copyAny(client, remote, false)
	client.Close()
	remote.Close()
	<-done
}
func (e *Engine) copyAny(dst net.Conn, src net.Conn, upload bool) {
	buf := make([]byte, 32768)
	for {
		src.SetReadDeadline(time.Now().Add(e.config.IdleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(e.config.IdleTimeout))
			if writeAll(dst, buf[:n]) != nil {
				return
			}
			if upload {
				e.up.Add(uint64(n))
			} else {
				e.down.Add(uint64(n))
			}
		}
		if err != nil {
			return
		}
	}
}
