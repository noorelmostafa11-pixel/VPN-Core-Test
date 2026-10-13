package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func parseAnyTLSURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "anytls", "raw", "tls"
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return c, errors.New("ANYTLS_CONFIGURATION")
	}
	c.Password = u.User.Username()
	if p, ok := u.User.Password(); ok {
		c.Password += ":" + p
	}
	c.Server, c.ServerName, c.Port = u.Hostname(), u.Hostname(), 443
	if u.Port() != "" {
		c.Port, err = number(u.Port(), 1, 65535)
		if err != nil {
			return c, err
		}
	}
	if u.Path != "" && u.Path != "/" {
		return c, errors.New("ANYTLS_CONFIGURATION")
	}
	c.Options = map[string]string{}
	for k, vs := range u.Query() {
		if len(vs) != 1 {
			return c, errors.New("ANYTLS_CONFIGURATION")
		}
		c.Options[strings.ToLower(k)] = vs[0]
	}
	c.ServerName = option(c.Options, c.Server, "sni", "peer")
	c.Fingerprint = option(c.Options, "native", "fp", "fingerprint")
	c.ECH = c.Options["ech"]
	c.InsecureRequested = truth(option(c.Options, "", "insecure", "allowinsecure"))
	return c, c.Validate()
}
func validateAnyTLS(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || c.Password == "" || len(c.Password) > 4096 || c.Security != "tls" || c.Transport != "raw" {
		return errors.New("ANYTLS_CONFIGURATION")
	}
	for k := range c.Options {
		if !contains([]string{"sni", "peer", "fp", "fingerprint", "ech", "insecure", "allowinsecure", "pinsha256", "pcs", "vcn"}, k) {
			return errors.New("ANYTLS_OPTION_UNSUPPORTED")
		}
	}
	_, err := c.tlsSettings()
	return err
}

type anyClient struct {
	config   Config
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	reaping  bool
	opening  int
	sessions map[*anySession]bool
	next     uint64
	scheme   *anyPadScheme
	workers  sync.WaitGroup
	once     sync.Once
}

func newAnyClient(ctx context.Context, c Config) *anyClient {
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	scheme, _ := parseAnyPadding(anyDefaultPadding)
	return &anyClient{config: c, ctx: life, cancel: cancel, sessions: map[*anySession]bool{}, scheme: scheme}
}
func (c *anyClient) IsClosed() bool { return c.ctx.Err() != nil }
func (c *anyClient) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		c.closed = true
		list := make([]*anySession, 0, len(c.sessions))
		for s := range c.sessions {
			list = append(list, s)
		}
		c.mu.Unlock()
		for _, s := range list {
			s.shutdown(net.ErrClosed)
		}
		c.workers.Wait()
	})
	return nil
}
func (c *anyClient) open(ctx context.Context, address []byte) (*anyStream, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.ConnectTimeout)
	defer cancel()
	stopOwner := context.AfterFunc(c.ctx, cancel)
	defer stopOwner()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !c.reaping {
		c.reaping = true
		c.workers.Add(1)
		go c.reap()
	}
	var idle *anySession
	var retire []*anySession
	for s, busy := range c.sessions {
		if !busy {
			if time.Since(s.idle) > 30*time.Second {
				delete(c.sessions, s)
				retire = append(retire, s)
			} else if idle == nil || s.sequence > idle.sequence {
				idle = s
			}
		}
	}
	if idle != nil {
		c.sessions[idle] = true
		c.mu.Unlock()
		for _, s := range retire {
			s.shutdown(net.ErrClosed)
		}
		return idle.open(ctx, address, false)
	}
	if len(c.sessions)+c.opening >= 128 {
		c.mu.Unlock()
		return nil, errors.New("ANYTLS_SESSION_LIMIT")
	}
	c.workers.Add(1)
	c.opening++
	c.next++
	sequence, scheme := c.next, c.scheme
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.opening--; c.mu.Unlock(); c.workers.Done() }()
	for _, s := range retire {
		s.shutdown(net.ErrClosed)
	}
	conn, err := proxySocket(ctx, c.config)
	if err != nil {
		return nil, err
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()); conn.Close(); close(stopped) })
	detached := false
	detach := func() {
		if !detached {
			if !stop() {
				<-stopped
			}
			detached = true
		}
	}
	defer detach()
	auth := sha256.Sum256([]byte(c.config.Password))
	padding := scheme.authPadding()
	wire := make([]byte, 34+len(padding))
	copy(wire, auth[:])
	binary.BigEndian.PutUint16(wire[32:], uint16(len(padding)))
	copy(wire[34:], padding)
	if err = writeAll(conn, wire); err != nil {
		conn.Close()
		return nil, err
	}
	session := newAnySession(conn, scheme)
	session.client = c
	session.sequence = sequence
	session.idle = time.Now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		session.shutdown(net.ErrClosed)
		return nil, net.ErrClosed
	}
	c.sessions[session] = true
	c.workers.Add(1)
	c.mu.Unlock()
	go func() { defer c.workers.Done(); session.readLoop() }()
	stream, err := session.open(ctx, address, true)
	detach()
	if err != nil || ctx.Err() != nil {
		session.shutdown(err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return stream, nil
}
func (c *anyClient) reap() {
	defer c.workers.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			var list []*anySession
			for s, busy := range c.sessions {
				if !busy && time.Since(s.idle) >= 30*time.Second {
					delete(c.sessions, s)
					list = append(list, s)
				}
			}
			c.mu.Unlock()
			for _, s := range list {
				s.shutdown(net.ErrClosed)
			}
		}
	}
}

type anySession struct {
	handle    func(byte, uint32, []byte) error
	conn      net.Conn
	scheme    *anyPadScheme
	client    *anyClient
	mu        sync.Mutex
	closed    bool
	streams   map[uint32]*anyStream
	next      uint32
	sequence  uint64
	idle      time.Time
	version   int
	writeMu   sync.Mutex
	packet    int
	done      chan struct{}
	closeOnce sync.Once
}

func newAnySession(conn net.Conn, scheme *anyPadScheme) *anySession {
	return &anySession{conn: conn, scheme: scheme, streams: map[uint32]*anyStream{}, next: 1, packet: 1, done: make(chan struct{}), version: 1}
}
func (s *anySession) send(data []byte, deadline time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	s.conn.SetWriteDeadline(deadline)
	err := s.scheme.write(s.conn, s.packet, data)
	s.packet++
	if err != nil {
		s.shutdown(err)
	}
	return err
}
func (s *anySession) open(ctx context.Context, address []byte, first bool) (*anyStream, error) {
	s.mu.Lock()
	if s.closed || s.next == 0 {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	id := s.next
	s.next++
	stream := newAnyStream(s, id)
	s.streams[id] = stream
	s.mu.Unlock()
	frames := []byte{}
	if first {
		settings := []byte("v=2\nclient=vpn-core/" + Version + "\npadding-md5=" + s.scheme.hash)
		frames = append(frames, anyFrame(anySettings, 0, settings)...)
	}
	frames = append(frames, anyFrame(anySYN, id, nil)...)
	frames = append(frames, anyFrame(anyPSH, id, address)...)
	deadline, _ := ctx.Deadline()
	if err := s.send(frames, deadline); err != nil {
		stream.Close()
		return nil, err
	}
	legacy := time.NewTimer(100 * time.Millisecond)
	defer legacy.Stop()
	for {
		select {
		case err := <-stream.ack:
			if err != nil {
				stream.Close()
				return nil, err
			}
			return stream, nil
		case <-legacy.C:
			s.mu.Lock()
			version := s.version
			s.mu.Unlock()
			if version < 2 {
				return stream, nil
			}
		case <-ctx.Done():
			stream.Close()
			s.shutdown(ctx.Err())
			return nil, ctx.Err()
		case <-s.done:
			stream.Close()
			return nil, errors.New("ANYTLS_SESSION_CLOSED")
		}
	}
}
func (s *anySession) shutdown(err error) {
	s.closeOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.mu.Lock()
		s.closed = true
		list := make([]*anyStream, 0, len(s.streams))
		for _, stream := range s.streams {
			list = append(list, stream)
		}
		s.mu.Unlock()
		s.conn.SetDeadline(time.Now())
		s.conn.Close()
		close(s.done)
		for _, stream := range list {
			stream.finish(err)
		}
		if s.client != nil {
			s.client.mu.Lock()
			delete(s.client.sessions, s)
			s.client.mu.Unlock()
		}
	})
}
func (s *anySession) readLoop() {
	defer s.shutdown(io.EOF)
	for {
		var h [7]byte
		if _, err := io.ReadFull(s.conn, h[:]); err != nil {
			return
		}
		command, id, n := h[0], binary.BigEndian.Uint32(h[1:5]), int(binary.BigEndian.Uint16(h[5:]))
		data := make([]byte, n)
		if _, err := io.ReadFull(s.conn, data); err != nil {
			return
		}
		if s.handle != nil {
			if s.handle(command, id, data) != nil {
				return
			}
			continue
		}
		s.mu.Lock()
		stream := s.streams[id]
		s.mu.Unlock()
		switch command {
		case anyWaste:
		case anyPSH:
			if stream != nil {
				if !stream.push(data) {
					stream.Close()
				}
			}
		case anyFIN:
			if n != 0 {
				return
			}
			if stream != nil {
				stream.finish(io.EOF)
			}
		case anySYNACK:
			if stream != nil {
				var err error
				if n > 0 {
					err = errors.New("ANYTLS_REMOTE_DIAL_FAILED")
				}
				select {
				case stream.ack <- err:
				default:
				}
			}
		case anyHeartRequest:
			if n != 0 {
				return
			}
			if s.send(anyFrame(anyHeartResponse, id, nil), time.Now().Add(5*time.Second)) != nil {
				return
			}
		case anyHeartResponse:
			if n != 0 {
				return
			}
		case anyServerSettings:
			if id != 0 {
				return
			}
			settings, err := parseAnySettings(data)
			if err != nil {
				return
			}
			s.mu.Lock()
			if settings["v"] == "2" {
				s.version = 2
			}
			s.mu.Unlock()
		case anyPadding:
			if id != 0 {
				return
			}
			scheme, err := parseAnyPadding(string(data))
			if err != nil {
				return
			}
			if s.client != nil {
				s.client.mu.Lock()
				s.client.scheme = scheme
				s.client.mu.Unlock()
			}
		case anyAlert:
			return
		default:
			return
		}
	}
}

type anyStream struct {
	session                     *anySession
	id                          uint32
	mu                          sync.Mutex
	readMu                      sync.Mutex
	writeMu                     sync.Mutex
	queue                       [][]byte
	bytes                       int
	err                         error
	readDeadline, writeDeadline time.Time
	wake                        chan struct{}
	space                       chan struct{}
	ack                         chan error
	once                        sync.Once
}

func newAnyStream(s *anySession, id uint32) *anyStream {
	return &anyStream{session: s, id: id, wake: make(chan struct{}, 1), space: make(chan struct{}, 1), ack: make(chan error, 1)}
}
func (s *anyStream) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *anyStream) push(data []byte) bool {
	for {
		s.mu.Lock()
		if s.err != nil {
			s.mu.Unlock()
			return true
		}
		if len(s.queue) < 8 && s.bytes+len(data) <= 131072 {
			s.queue = append(s.queue, data)
			s.bytes += len(data)
			s.mu.Unlock()
			s.signal()
			return true
		}
		s.mu.Unlock()
		select {
		case <-s.space:
		case <-s.session.done:
			return false
		}
	}
}
func (s *anyStream) signalSpace() {
	select {
	case s.space <- struct{}{}:
	default:
	}
}
func (s *anyStream) finish(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.signal()
	s.signalSpace()
}
func (s *anyStream) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			n := copy(buf, s.queue[0])
			s.queue[0] = s.queue[0][n:]
			s.bytes -= n
			if len(s.queue[0]) == 0 {
				s.queue = s.queue[1:]
			}
			s.mu.Unlock()
			s.signalSpace()
			return n, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		deadline := s.readDeadline
		s.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if time.Until(deadline) <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-s.wake:
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
func (s *anyStream) Write(buf []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	sent := 0
	for len(buf) > 0 {
		s.mu.Lock()
		err, deadline := s.err, s.writeDeadline
		s.mu.Unlock()
		if err != nil {
			return sent, err
		}
		if deadline.IsZero() {
			deadline = time.Now().Add(60 * time.Second)
		}
		n := len(buf)
		if n > 16384 {
			n = 16384
		}
		if err := s.session.send(anyFrame(anyPSH, s.id, buf[:n]), deadline); err != nil {
			return sent, err
		}
		sent += n
		buf = buf[n:]
	}
	return sent, nil
}
func (s *anyStream) Close() error {
	s.once.Do(func() {
		s.finish(net.ErrClosed)
		s.mu.Lock()
		s.queue = nil
		s.bytes = 0
		s.err = net.ErrClosed
		s.mu.Unlock()
		s.session.mu.Lock()
		delete(s.session.streams, s.id)
		closed := s.session.closed
		empty := len(s.session.streams) == 0
		s.session.mu.Unlock()
		if !closed {
			s.session.send(anyFrame(anyFIN, s.id, nil), time.Now().Add(time.Second))
		}
		if c := s.session.client; c != nil && empty {
			c.mu.Lock()
			if _, ok := c.sessions[s.session]; ok {
				s.session.idle = time.Now()
				c.sessions[s.session] = false
			}
			c.mu.Unlock()
		}
	})
	return nil
}
func (s *anyStream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *anyStream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }
func (s *anyStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline, s.writeDeadline = t, t
	s.mu.Unlock()
	s.signal()
	return nil
}
func (s *anyStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	s.signal()
	return nil
}
func (s *anyStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	return nil
}

func getAnyTLS(ctx context.Context, c Config) (*anyClient, io.Closer, error) {
	b, _ := json.Marshal(c)
	hash := sha256.Sum256(b)
	key := "anytls:" + hex.EncodeToString(hash[:])
	if route, ok := ctx.Value(routeReuseKey{}).(routeReuse); ok {
		key += fmt.Sprintf(":%p:%s", route.table, route.tag)
	}
	if cache := engineClientCache(ctx); cache != nil {
		lease, err := cache.get(ctx, key, func(ctx context.Context) (io.Closer, error) { return newAnyClient(ctx, c), nil })
		if err != nil {
			return nil, nil, err
		}
		return lease.entry.client.(*anyClient), lease, nil
	}
	client := newAnyClient(ctx, c)
	return client, client, nil
}
func dialAnyTLS(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	address, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	client, owner, err := getAnyTLS(ctx, c)
	if err != nil {
		return nil, err
	}
	stream, err := client.open(ctx, address)
	if err != nil {
		owner.Close()
		return nil, err
	}
	return &hyLeaseConn{Conn: stream, owner: owner}, nil
}
