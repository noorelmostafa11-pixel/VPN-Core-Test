package core

import (
	"errors"
	"net"
	"strings"

	quic "github.com/quic-go/quic-go"
)

func validateTUICServer(c ServerConfig) error {
	if len(c.UUIDs) == 0 || len(c.UUIDs) > 128 || c.Password == "" || len(c.Password) > 4096 || c.Cipher != "" {
		return errors.New("TUIC_SERVER_CONFIGURATION")
	}
	seen := map[[16]byte]bool{}
	for _, id := range c.UUIDs {
		u, err := tuicUUID(id)
		if err != nil || u == [16]byte{} || seen[u] {
			return errors.New("SERVER_USERS_INVALID")
		}
		seen[u] = true
	}
	for k, v := range c.Options {
		if k != "alpn" {
			return errors.New("TUIC_SERVER_OPTION_UNSUPPORTED")
		}
		p := strings.Split(v, ",")
		if len(p) > 8 {
			return errors.New("TUIC_ALPN_INVALID")
		}
		for _, v := range p {
			if len(v) == 0 || len(v) > 255 {
				return errors.New("TUIC_ALPN_INVALID")
			}
		}
	}
	return nil
}
func (e *Engine) startTUICServer(s serverSpec) (net.Addr, error) {
	packet, err := net.ListenPacket("udp", s.config.Listen)
	if err != nil {
		return nil, err
	}
	configureDatagramBuffers(packet)
	t := &quic.Transport{Conn: packet}
	tls := s.tls.Clone()
	tls.NextProtos = strings.Split(option(s.config.Options, "h3", "alpn"), ",")
	l, err := t.Listen(tls, tuicQUICConfig(e.config.ConnectTimeout))
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
	users := map[[16]byte]string{}
	for _, v := range s.config.UUIDs {
		id, _ := tuicUUID(v)
		users[id] = s.config.Password
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
			p := newTUICPeer(q, e, users, e.config.ConnectTimeout)
			if !e.track(p) {
				<-slots
				return
			}
			p.start()
			if !e.spawn(func() { defer func() { <-slots }(); defer e.untrack(p); defer p.Close(); <-p.ctx.Done() }) {
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

// TUIC has no authentication or destination response command. QUIC handshake
// completion alone is not advertised as successful application connectivity.
