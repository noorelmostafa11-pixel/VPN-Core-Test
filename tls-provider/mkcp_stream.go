package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"
)

func (s *xSession) runMKCP(c xSettings) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		cancel()
		return
	}
	s.cancel = cancel
	s.mu.Unlock()
	defer cancel()
	handshake, done := context.WithTimeout(ctx, time.Duration(c.TLS.TimeoutMS)*time.Millisecond)
	raw, err := dialMKCP(handshake, net.JoinHostPort(c.Server, strconv.Itoa(c.Port)), c.KCP)
	if err != nil {
		done()
		s.fail(err)
		return
	}
	defer raw.Close()
	conn := net.Conn(raw)
	if c.TLS.Security != "none" {
		_ = raw.SetDeadline(time.Now().Add(time.Duration(c.TLS.TimeoutMS) * time.Millisecond))
		u, _, e := configuredTLS(handshake, raw, c.TLS)
		if e != nil {
			done()
			s.fail(e)
			return
		}
		state := u.ConnectionState()
		conn = &tlsHTTPConn{u, state.Version, state.NegotiatedProtocol}
		_ = raw.SetDeadline(time.Time{})
	}
	done()
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return
	}
	s.closers = append(s.closers, raw)
	s.mu.Unlock()
	s.metadata(conn)
	go func() {
		_, e := io.CopyBuffer(conn, s.up, make([]byte, 16384))
		if e == nil {
			if c.TLS.Security == "none" {
				e = raw.CloseWrite()
			} else if close, ok := conn.(*tlsHTTPConn).Conn.(interface{ CloseWrite() error }); ok {
				e = close.CloseWrite()
			}
		}
		if e != nil {
			s.fail(e)
		}
	}()
	_, err = io.CopyBuffer(s.down, conn, make([]byte, 16384))
	if err != nil {
		s.fail(err)
		return
	}
	s.mu.Lock()
	if s.state >= 0 {
		s.state = 2
	}
	s.mu.Unlock()
	s.down.close(nil)
}
