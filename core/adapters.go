package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// queueConn adapts the existing bounded Go transport queues directly to net.Conn.
type queueConn struct {
	version               uint16
	alpn                  string
	metaConn              net.Conn
	up, down              *byteQueue
	closeFn               func()
	once                  sync.Once
	deadlineMu            sync.Mutex
	readTimer, writeTimer *time.Timer
}

func (c *queueConn) Read(b []byte) (int, error)  { return c.down.Read(b) }
func (c *queueConn) Write(b []byte) (int, error) { return c.up.Write(b) }
func (c *queueConn) CloseWrite() error           { c.up.close(nil); return nil }
func (c *queueConn) Close() error {
	c.once.Do(func() {
		c.deadlineMu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.deadlineMu.Unlock()
		c.up.close(net.ErrClosed)
		c.down.close(net.ErrClosed)
		c.closeFn()
	})
	return nil
}
func (c *queueConn) LocalAddr() net.Addr  { return address("core") }
func (c *queueConn) RemoteAddr() net.Addr { return address("proxy") }
func (c *queueConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *queueConn) timer(t time.Time, read bool) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	p := &c.writeTimer
	q := c.up
	if read {
		p = &c.readTimer
		q = c.down
	}
	if *p != nil {
		(*p).Stop()
		*p = nil
	}
	if !t.IsZero() {
		*p = time.AfterFunc(time.Until(t), func() { q.close(os.ErrDeadlineExceeded) })
	}
	return nil
}
func (c *queueConn) SetReadDeadline(t time.Time) error  { return c.timer(t, true) }
func (c *queueConn) SetWriteDeadline(t time.Time) error { return c.timer(t, false) }
func (s *xSession) parentContext() context.Context {
	if s.parent != nil {
		return s.parent
	}
	return context.Background()
}
func openX(ctx context.Context, c Config, initial []byte) (net.Conn, error) {
	x, e := c.xSettings()
	if e != nil {
		return nil, e
	}
	s := &xSession{up: newByteQueue(), down: newByteQueue(), parent: ctx, done: make(chan struct{}), workerDone: make(chan struct{})}
	conn := &queueConn{up: s.up, down: s.down}
	conn.closeFn = func() {
		close(s.done)
		s.mu.Lock()
		s.released = true
		if s.cancel != nil {
			s.cancel()
		}
		closers := append([]io.Closer{}, s.closers...)
		s.mu.Unlock()
		for _, closer := range closers {
			closer.Close()
		}
		<-s.workerDone
		s.uploads.Wait()
	}
	if _, e = s.up.Write(initial); e != nil {
		return nil, e
	}
	go func() { defer close(s.workerDone); s.run(x) }()
	deadline := time.NewTimer(c.ConnectTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		state, code := s.state, s.code
		conn.version, conn.alpn = s.version, s.alpn
		s.mu.Unlock()
		if state < 0 {
			conn.Close()
			return nil, providerError(code)
		}
		if state > 0 {
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-s.doneSignal():
				}
			}()
			return conn, nil
		}
		select {
		case <-ctx.Done():
			conn.Close()
			return nil, ctx.Err()
		case <-deadline.C:
			conn.Close()
			return nil, context.DeadlineExceeded
		case <-tick.C:
		}
	}
}

// doneSignal is owned by the session wrapper, independent of queue occupancy.
func (s *xSession) doneSignal() <-chan struct{} { return s.done }
func openEncryption(ctx context.Context, raw net.Conn, c Config) (net.Conn, error) {
	cfg, e := parseEncryption(c.Encryption)
	if e != nil {
		return nil, e
	}
	s := &encryptionSession{wire: raw, up: newByteQueue(), down: newByteQueue(), config: cfg, cacheID: sha256.Sum256([]byte(c.Encryption))}
	s.deadline = time.Now().Add(c.ConnectTimeout)
	raw.SetDeadline(s.deadline)
	if e = s.handshake(); e != nil {
		raw.Close()
		return nil, e
	}
	raw.SetDeadline(time.Time{})
	s.state = 1
	conn := &queueConn{up: s.up, down: s.down, closeFn: func() { raw.Close() }}
	go func() {
		if e := s.upload(); e != nil {
			s.fail(e)
		}
	}()
	go func() {
		e := s.download()
		if errors.Is(e, io.EOF) {
			s.down.close(nil)
		} else if e != nil {
			s.fail(e)
		}
	}()
	return conn, nil
}

// recordBoundedConn prevents TLS read-ahead across Vision/legacy raw boundaries.
type recordBoundedConn struct {
	net.Conn
	header               [5]byte
	headerPos, remaining int
}

func (c *recordBoundedConn) Read(b []byte) (int, error) {
	if c.remaining == 0 {
		n := min(len(b), 5-c.headerPos)
		count, e := c.Conn.Read(b[:n])
		copy(c.header[c.headerPos:], b[:count])
		c.headerPos += count
		if c.headerPos == 5 {
			c.remaining = getWord(c.header[:], 3)
			c.headerPos = 0
		}
		return count, e
	}
	n, e := c.Conn.Read(b[:min(len(b), c.remaining)])
	c.remaining -= n
	return n, e
}

type directConn struct {
	net.Conn
	raw    net.Conn
	direct atomic.Bool
}

func (c *directConn) Read(b []byte) (int, error) {
	if c.direct.Load() {
		return c.raw.Read(b)
	}
	return c.Conn.Read(b)
}
func (c *directConn) Write(b []byte) (int, error) { return c.Conn.Write(b) }
func (c *directConn) switchDirectRead()           { c.direct.Store(true) }
func (c *directConn) CloseWrite() error {
	target := c.Conn
	if c.direct.Load() {
		target = c.raw
	}
	if w, ok := target.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
