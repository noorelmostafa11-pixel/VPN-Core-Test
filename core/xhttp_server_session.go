package core

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const xServerPostLimit = 1048576
const xServerBufferedPosts = 30
const xServerSessionBuffer = 2 * (xServerPostLimit + 1)
const xServerTotalBuffer = 8 * (xServerPostLimit + 1)

var errXServerAdmission = errors.New("XHTTP_SESSION_LIMIT")
var errXServerPost = errors.New("XHTTP_POST_CONFLICT")

// The engine owns this optional manager, which owns every session and buffer.
// No session or timer exists until a split request arrives.
type xServerSessions struct {
	e        *Engine
	mu       sync.Mutex
	closed   bool
	items    map[string]*xServerSession
	buffered atomic.Int64
}

func (m *xServerSessions) reserve(n int) bool {
	for {
		used := m.buffered.Load()
		if n < 0 || int64(n) > xServerTotalBuffer-used {
			return false
		}
		if m.buffered.CompareAndSwap(used, used+int64(n)) {
			return true
		}
	}
}
func (m *xServerSessions) session(id string) (*xServerSession, error) {
	m.mu.Lock()
	if m.closed || m.e.ctx.Err() != nil {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	if current := m.items[id]; current != nil {
		m.mu.Unlock()
		return current, nil
	}
	if !m.e.acquire() {
		m.mu.Unlock()
		return nil, errXServerAdmission
	}
	ctx, cancel := context.WithCancel(m.e.ctx)
	s := &xServerSession{manager: m, id: id, ctx: ctx, cancel: cancel, attached: make(chan struct{}), changed: make(chan struct{}), deadline: time.Now().Add(m.e.config.ConnectTimeout), packets: map[uint64]xServerPacket{}}
	if m.items == nil {
		m.items = map[string]*xServerSession{}
	}
	m.items[id] = s
	// Register before releasing the manager lock so its Close sees all owners.
	started := m.e.spawn(func() {
		timer := time.NewTimer(m.e.config.ConnectTimeout)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-s.attached:
		case <-timer.C:
			s.Close()
		}
	})
	m.mu.Unlock()
	if !started {
		s.Close()
		return nil, net.ErrClosed
	}
	return s, nil
}
func (m *xServerSessions) Close() error {
	m.mu.Lock()
	m.closed = true
	list := make([]*xServerSession, 0, len(m.items))
	for _, session := range m.items {
		list = append(list, session)
	}
	m.mu.Unlock()
	for _, session := range list {
		session.Close()
	}
	return nil
}

type xServerPacket struct {
	body []byte
	cost int // Entire backing allocation, including already consumed bytes.
}
type xServerSession struct {
	manager    *xServerSessions
	id         string
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
	mu, readMu sync.Mutex
	attached   chan struct{}
	changed    chan struct{}
	closed     bool
	down       *serverHTTP2Conn
	upload     *serverHTTP2Conn
	uploadErr  error
	uploadDone chan struct{}
	uploadOnce sync.Once
	packets    map[uint64]xServerPacket
	pending    xServerPacket
	next       uint64
	bytes      int
	deadline   time.Time
}

func (s *xServerSession) signal() { close(s.changed); s.changed = make(chan struct{}) }
func (s *xServerSession) attachDown(c *serverHTTP2Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.down != nil {
		return false
	}
	s.down = c
	close(s.attached)
	return true
}
func (s *xServerSession) attachUpload(c *serverHTTP2Conn) (<-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.upload != nil || s.next != 0 || len(s.packets) != 0 {
		return nil, errXServerPost
	}
	if err := c.SetReadDeadline(s.deadline); err != nil {
		return nil, err
	}
	s.upload, s.uploadDone = c, make(chan struct{})
	s.signal()
	return s.uploadDone, nil
}

// The caller transfers its already reserved backing allocation on success.
func (s *xServerSession) push(seq uint64, packet xServerPacket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, duplicate := s.packets[seq]
	count := len(s.packets)
	if s.pending.cost > 0 {
		count++
	}
	if s.closed || s.upload != nil || seq == ^uint64(0) || seq < s.next || seq-s.next >= xServerBufferedPosts || duplicate || count >= xServerBufferedPosts || packet.cost < len(packet.body) || packet.cost > xServerSessionBuffer-s.bytes {
		return errXServerPost
	}
	s.packets[seq] = packet
	s.bytes += packet.cost
	s.signal()
	return nil
}
func (s *xServerSession) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.deadline = t
	s.signal()
	if s.upload != nil && s.uploadErr == nil {
		// Serialize with upload completion: its controller belongs only to
		// the still-running HTTP handler.
		return s.upload.SetReadDeadline(t)
	}
	return nil
}
func (s *xServerSession) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, net.ErrClosed
		}
		if !s.deadline.IsZero() && !s.deadline.After(time.Now()) {
			s.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if s.upload != nil {
			if s.uploadErr != nil {
				err := s.uploadErr
				s.mu.Unlock()
				return 0, err
			}
			upload := s.upload
			s.mu.Unlock()
			n, err := upload.Read(b)
			if err != nil {
				s.mu.Lock()
				s.uploadErr = err
				s.mu.Unlock()
				if err == io.EOF {
					upload.CloseWrite()
				}
				s.uploadOnce.Do(func() { close(s.uploadDone) })
			}
			return n, err
		}
		if s.next == ^uint64(0) {
			s.mu.Unlock()
			return 0, errors.New("XHTTP_SEQUENCE_EXHAUSTED")
		}
		if len(s.pending.body) == 0 {
			if packet, ok := s.packets[s.next]; ok {
				delete(s.packets, s.next)
				s.next++
				s.pending = packet
				if len(packet.body) == 0 {
					s.manager.buffered.Add(-int64(packet.cost))
					s.bytes -= packet.cost
					s.pending = xServerPacket{}
					s.mu.Unlock()
					continue
				}
			}
		}
		if len(s.pending.body) > 0 {
			n := copy(b, s.pending.body)
			s.pending.body = s.pending.body[n:]
			if len(s.pending.body) == 0 {
				s.manager.buffered.Add(-int64(s.pending.cost))
				s.bytes -= s.pending.cost
				s.pending = xServerPacket{}
			}
			s.mu.Unlock()
			return n, nil
		}
		changed, deadline := s.changed, s.deadline
		s.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-s.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
func (s *xServerSession) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.mu.Lock()
		s.closed = true
		s.manager.buffered.Add(-int64(s.bytes))
		s.bytes = 0
		s.packets, s.pending = nil, xServerPacket{}
		down, upload := s.down, s.upload
		s.signal()
		s.mu.Unlock()
		if upload != nil {
			upload.Close()
		}
		if down != nil {
			down.Close()
		}
		s.manager.mu.Lock()
		if s.manager.items[s.id] == s {
			delete(s.manager.items, s.id)
		}
		s.manager.mu.Unlock()
		s.manager.e.release()
	})
	return nil
}

type xServerSplitConn struct {
	*serverHTTP2Conn
	session *xServerSession
}

func (c *xServerSplitConn) Read(b []byte) (int, error) { return c.session.Read(b) }
func (c *xServerSplitConn) SetReadDeadline(t time.Time) error {
	return c.session.SetReadDeadline(t)
}
func (c *xServerSplitConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *xServerSplitConn) Close() error { return c.session.Close() }
