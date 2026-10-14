package core

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"strings"
	"time"

	hc "github.com/apernet/hysteria/core/v2/client"
	quic "github.com/apernet/quic-go"
)

func (e *Engine) startHy1Server(spec serverSpec) (net.Addr, error) {
	packet, err := net.ListenPacket("udp", spec.config.Listen)
	if err != nil {
		return nil, err
	}
	configureDatagramBuffers(packet)
	packet = wrapHy1Packet(packet, spec.config.Options)
	t := &quic.Transport{Conn: packet}
	tls := spec.tls.Clone()
	tls.NextProtos = strings.Split(option(spec.config.Options, "hysteria", "alpn"), ",")
	l, err := t.Listen(tls, hy1QUICConfig(e.config.ConnectTimeout))
	if err != nil {
		t.Close()
		packet.Close()
		return nil, err
	}
	if !e.track(packet) {
		l.Close()
		t.Close()
		return nil, net.ErrClosed
	}
	if !e.track(t) {
		l.Close()
		e.untrack(packet)
		packet.Close()
		return nil, net.ErrClosed
	}
	if !e.track(l) {
		e.untrack(t)
		t.Close()
		e.untrack(packet)
		packet.Close()
		return nil, net.ErrClosed
	}
	slots := make(chan struct{}, 64)
	if !e.spawn(func() {
		defer e.untrack(l)
		defer l.Close()
		defer e.untrack(t)
		defer t.Close()
		defer e.untrack(packet)
		defer packet.Close()
		for {
			q, err := l.Accept(e.ctx)
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				q.CloseWithError(1, "")
				continue
			}
			p := newHy1Peer(q, e, e.config.ConnectTimeout)
			if !e.track(p) {
				<-slots
				return
			}
			if !e.spawn(func() {
				defer func() { <-slots }()
				defer e.untrack(p)
				defer p.Close()
				if p.authenticate(spec.config) != nil {
					return
				}
				p.start()
				p.spawn(func() { p.acceptRequests(truth(spec.config.Options["disable-udp"])) })
				<-p.ctx.Done()
			}) {
				p.Close()
				<-slots
				return
			}
		}
	}) {
		l.Close()
		t.Close()
		packet.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return packet.LocalAddr(), nil
}
func (p *hy1Peer) authenticate(c ServerConfig) error {
	ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
	defer cancel()
	s, err := p.conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	p.control = s
	s.SetDeadline(time.Now().Add(p.timeout))
	version, tx, rx, password, err := hy1ReadHello(s)
	if err != nil || version != 3 {
		return errHy1Wire
	}
	stx, srx := min(rx, hy1Rate(c.Options, "upmbps")), min(tx, hy1Rate(c.Options, "downmbps"))
	ok := byte(0)
	if subtle.ConstantTimeCompare([]byte(password), []byte(c.Password)) == 1 {
		ok = 1
	}
	if err = writeAll(s, hy1Hello(ok, stx, srx, "")); err != nil {
		return err
	}
	if ok == 0 {
		return errors.New("HYSTERIA1_AUTHENTICATION_FAILED")
	}
	hc.ProjectUseBrutal(p.conn, stx)
	s.SetDeadline(time.Time{})
	return nil
}
func (p *hy1Peer) acceptRequests(disableUDP bool) {
	for {
		s, err := p.conn.AcceptStream(p.ctx)
		if err != nil {
			return
		}
		if !p.server.acquire() {
			s.CancelRead(1)
			s.CancelWrite(1)
			continue
		}
		if !p.spawn(func() {
			defer p.server.release()
			conn := &hy1Conn{Stream: s, peer: p}
			defer conn.Close()
			s.SetDeadline(time.Now().Add(p.timeout))
			udp, host, port, err := hy1ReadRequest(s)
			if err != nil {
				return
			}
			if udp {
				if disableUDP {
					writeAll(s, hy1Response(false, 0, "UDP disabled"))
					return
				}
				p.mu.Lock()
				if p.next == ^uint32(0) {
					p.mu.Unlock()
					return
				}
				p.next++
				id := p.next
				p.mu.Unlock()
				a, err := p.addAssociation(id, s, nil)
				if err != nil {
					writeAll(s, hy1Response(false, 0, "Session limit"))
					return
				}
				defer a.Close()
				if writeAll(s, hy1Response(true, id, "")) != nil {
					return
				}
				s.SetDeadline(time.Time{})
				<-a.ctx.Done()
				return
			}
			ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
			defer cancel()
			ctx = p.server.flowContext(ctx, conn.RemoteAddr(), host)
			remote, err := p.server.dialTCP(ctx, host, port)
			if err != nil {
				writeAll(s, hy1Response(false, 0, "Destination rejected"))
				return
			}
			if !p.server.track(remote) {
				return
			}
			defer p.server.untrack(remote)
			defer remote.Close()
			done := make(chan struct{})
			stop := context.AfterFunc(p.ctx, func() { remote.Close(); close(done) })
			defer func() {
				if !stop() {
					<-done
				}
			}()
			if writeAll(s, hy1Response(true, 0, "")) != nil {
				return
			}
			s.SetDeadline(time.Time{})
			p.server.accepted.Add(1)
			p.server.relay(conn, remote)
		}) {
			p.server.release()
			s.CancelRead(1)
			s.CancelWrite(1)
			return
		}
	}
}
