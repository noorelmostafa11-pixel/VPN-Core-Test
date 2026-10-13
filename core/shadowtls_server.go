package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"net"
	"strings"
	"sync"
	"time"
)

func compileShadowServer(c ServerConfig) (serverSpec, error) {
	s := serverSpec{config: c}
	if c.CertFile != "" || c.KeyFile != "" || len(c.UUIDs) != 0 || c.WireGuard != nil || len(c.Password) == 0 || len(c.Password) > 4096 {
		return s, errors.New("SHADOWTLS_SERVER_CONFIGURATION")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil {
		return s, errors.New("SERVER_LISTEN_INVALID")
	}
	if _, err = number(port, 0, 65535); err != nil {
		return s, err
	}
	for k := range c.Options {
		if !contains([]string{"version", "handshake", "data-server", "ss-password", "uot"}, k) {
			return s, errors.New("SHADOWTLS_SERVER_OPTION_UNSUPPORTED")
		}
	}
	if v := option(c.Options, "3", "version"); v != "2" && v != "3" {
		return s, errors.New("SHADOWTLS_VERSION_UNSUPPORTED")
	}
	if _, _, err = splitProtocolTarget(c.Options["handshake"]); err != nil {
		return s, errors.New("SHADOWTLS_HANDSHAKE_ADDRESS_INVALID")
	}
	if target := c.Options["data-server"]; target != "" {
		if _, _, err = splitProtocolTarget(target); err != nil {
			return s, errors.New("SHADOWTLS_DATA_ADDRESS_INVALID")
		}
		if c.Cipher != "" || c.Options["ss-password"] != "" || c.Options["uot"] != "" {
			return s, errors.New("SHADOWTLS_SERVER_CONFIGURATION")
		}
	} else {
		if strings.HasPrefix(c.Cipher, "2022-") {
			return s, errors.New("SERVER_SS_METHOD_UNSUPPORTED")
		}
		s.client = defaults()
		s.client.Protocol, s.client.Security, s.client.Transport = "ss", "none", "raw"
		s.client.Cipher, s.client.Password = c.Cipher, c.Options["ss-password"]
		s.client.Server, s.client.Port = "127.0.0.1", 1
		if s.client.Password == "" {
			return s, errors.New("SERVER_PASSWORD_INVALID")
		}
		if err = s.client.Validate(); err != nil {
			return s, err
		}
		if v := c.Options["uot"]; v != "" && v != "2" {
			return s, errors.New("SHADOWTLS_UOT_UNSUPPORTED")
		}
	}
	return s, nil
}
func (e *Engine) startShadowServer(s serverSpec) (net.Addr, error) {
	l, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return nil, err
	}
	if !e.track(l) {
		return nil, net.ErrClosed
	}
	if !e.spawn(func() {
		defer l.Close()
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			if !e.acquire() {
				raw.Close()
				continue
			}
			if !e.track(raw) {
				e.release()
				return
			}
			if !e.spawn(func() {
				defer e.release()
				defer e.untrack(raw)
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
				e.serveShadow(raw, s)
			}) {
				e.release()
				raw.Close()
				return
			}
		}
	}) {
		l.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return l.Addr(), nil
}

type shadowForwardState struct {
	mu        sync.Mutex
	stopped   bool
	random    []byte
	challenge hash.Hash
	history   [][]byte
}

func (e *Engine) serveShadow(raw net.Conn, s serverSpec) {
	first, err := readShadowRecord(raw)
	if err != nil || first[0] != 22 || len(first) < 6 || first[5] != 1 {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, e.config.ConnectTimeout)
	defer cancel()
	backend, err := outboundDial(ctx, "tcp", s.config.Options["handshake"], e.config.ConnectTimeout)
	if err != nil {
		return
	}
	defer backend.Close()
	if !e.track(backend) {
		return
	}
	defer e.untrack(backend)
	backend.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
	if writeAll(backend, first) != nil {
		return
	}
	version := 3
	if s.config.Options["version"] == "2" {
		version = 2
	}
	if version == 3 && !shadowVerifyHello(first, s.config.Password) {
		raw.SetDeadline(time.Time{})
		backend.SetDeadline(time.Time{})
		e.relay(raw, backend)
		return
	}
	state := &shadowForwardState{challenge: shadowMAC(s.config.Password)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			state.mu.Lock()
			stopped := state.stopped
			state.mu.Unlock()
			if !stopped {
				raw.Close()
			}
		}()
		var serverMAC hash.Hash
		var key [32]byte
		for {
			frame, err := readShadowRecord(backend)
			if err != nil {
				return
			}
			if version == 3 {
				if sr := shadowRandom(frame); sr != nil {
					state.mu.Lock()
					state.random = sr
					state.mu.Unlock()
					serverMAC = shadowMAC(s.config.Password, sr)
					key = sha256.Sum256(append([]byte(s.config.Password), sr...))
				}
				if frame[0] == 23 && serverMAC != nil {
					body := append([]byte(nil), frame[5:]...)
					for i := range body {
						body[i] ^= key[i%32]
					}
					tag := shadowTag(serverMAC, body, false)
					frame = shadowRecord(23, append(append([]byte(nil), tag...), body...))
				}
			} else {
				state.mu.Lock()
				state.challenge.Write(frame)
				tag := append([]byte(nil), state.challenge.Sum(nil)[:8]...)
				state.history = append(state.history, tag)
				if len(state.history) > 10 {
					state.history = state.history[1:]
				}
				state.mu.Unlock()
			}
			if writeAll(raw, frame) != nil {
				return
			}
		}
	}()
	// Closing the backend interrupts its reader; joining preserves every already
	// started TLS frame before the data server begins writing to the same socket.
	stop := func() { state.mu.Lock(); state.stopped = true; state.mu.Unlock(); backend.Close(); <-done }
	var pure []byte
	var readMAC hash.Hash
	var sr []byte
	for count := 0; count < 128; count++ {
		frame, err := readShadowRecord(raw)
		if err != nil {
			stop()
			return
		}
		if frame[0] == 23 {
			if version == 3 && len(frame) > 9 {
				state.mu.Lock()
				sr = append([]byte(nil), state.random...)
				state.mu.Unlock()
				if len(sr) == 32 {
					candidate := shadowMAC(s.config.Password, sr, []byte("C"))
					tag := shadowTag(candidate, frame[9:], true)
					if hmac.Equal(tag, frame[5:9]) {
						readMAC = candidate
						pure = frame[9:]
						break
					}
				}
			} else if version == 2 && len(frame) >= 13 {
				state.mu.Lock()
				matched := false
				for _, tag := range state.history {
					matched = matched || hmac.Equal(tag, frame[5:13])
				}
				state.mu.Unlock()
				if matched {
					pure = frame[13:]
					break
				}
			}
		}
		if writeAll(backend, frame) != nil {
			stop()
			return
		}
	}
	stop()
	if pure == nil {
		return
	}
	raw.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
	conn := &shadowConn{Conn: raw, version: version, initial: pure, readMAC: readMAC}
	if version == 3 {
		conn.writeMAC = shadowMAC(s.config.Password, sr, []byte("S"))
	}
	e.accepted.Add(1)
	if target := s.config.Options["data-server"]; target != "" {
		host, port, _ := splitProtocolTarget(target)
		ctx := e.flowContext(e.ctx, raw.RemoteAddr(), host)
		remote, err := e.dialTCP(ctx, host, port)
		if err != nil {
			return
		}
		if !e.track(remote) {
			return
		}
		defer e.untrack(remote)
		defer remote.Close()
		e.relay(conn, remote)
		return
	}
	client, a, err := serverSSConn(conn, s.client)
	if err != nil {
		return
	}
	if len(a) > 4 && a[0] == 3 && string(a[2:len(a)-2]) == uotV2Host && getWord(a, len(a)-2) == 0 {
		a[len(a)-1] = 1
	}
	host, port, err := decodeAddress(a)
	if err != nil {
		return
	}
	if host == uotV2Host {
		if s.config.Options["uot"] == "2" {
			e.serveUOT(client)
		}
		return
	}
	ctx = e.flowContext(e.ctx, raw.RemoteAddr(), host)
	remote, err := e.dialTCP(ctx, host, port)
	if err != nil {
		return
	}
	if !e.track(remote) {
		return
	}
	defer e.untrack(remote)
	defer remote.Close()
	e.relay(client, remote)
}
