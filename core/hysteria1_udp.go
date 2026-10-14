package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/apernet/quic-go"
)

type hy1Association struct {
	peer     *hy1Peer
	id       uint32
	stream   *quic.Stream
	address  []byte
	queue    chan Datagram
	ctx      context.Context
	cancel   context.CancelFunc
	bridge   *tuicRelay
	defrag   hy1Defrag
	writeMu  sync.Mutex
	packetID uint16
	last     time.Time // peer.mu
	mu       sync.Mutex
	deadline time.Time
	wake     chan struct{}
	once     sync.Once
}
type hy1PacketLease struct {
	PacketStream
	owner interface{ Close() error }
	once  sync.Once
}

func (l *hy1PacketLease) Close() error {
	l.once.Do(func() { l.PacketStream.Close(); l.owner.Close() })
	return nil
}
func (p *hy1Peer) addAssociation(id uint32, s *quic.Stream, address []byte) (*hy1Association, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if len(p.assocs) >= 64 || p.assocs[id] != nil {
		return nil, errors.New("HYSTERIA1_ASSOCIATION_LIMIT")
	}
	ctx, cancel := context.WithCancel(p.ctx)
	a := &hy1Association{peer: p, id: id, stream: s, address: address, queue: make(chan Datagram, 8), ctx: ctx, cancel: cancel, last: time.Now(), wake: make(chan struct{}, 1)}
	if p.server != nil {
		a.bridge = newTUICRelay(ctx, p.server, p.conn.RemoteAddr())
	}
	p.assocs[id] = a
	// Add under peer.mu so Close cannot Wait before a new worker is admitted.
	p.workers.Add(1)
	go func() { defer p.workers.Done(); defer a.Close(); var b [1]byte; s.Read(b[:]) }()
	if p.server != nil {
		p.workers.Add(2)
		go func() { defer p.workers.Done(); defer a.Close(); a.serverWrites() }()
		go func() { defer p.workers.Done(); defer a.Close(); a.serverReads() }()
	}
	return a, nil
}
func (a *hy1Association) Close() error {
	a.once.Do(func() {
		a.cancel()
		a.stream.CancelRead(0)
		a.stream.Close()
		if a.bridge != nil {
			a.bridge.Close()
		}
		p := a.peer
		p.mu.Lock()
		if p.assocs[a.id] == a {
			delete(p.assocs, a.id)
		}
		p.mu.Unlock()
	})
	return nil
}
func (a *hy1Association) send(address, body []byte) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.ctx.Err() != nil {
		return net.ErrClosed
	}
	a.mu.Lock()
	deadline := a.deadline
	a.mu.Unlock()
	if !deadline.IsZero() && time.Until(deadline) <= 0 {
		return context.DeadlineExceeded
	}
	a.peer.mu.Lock()
	a.last = time.Now()
	a.peer.mu.Unlock()
	a.packetID++
	if a.packetID == 0 {
		a.packetID++
	}
	frames, err := hy1Frames(a.id, a.packetID, address, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, a.peer.timeout)
	defer cancel()
	if !deadline.IsZero() {
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, deadline)
		defer stop()
	}
	for _, f := range frames {
		if err := a.peer.conn.ProjectSendDatagramContext(ctx, f); err != nil {
			return err
		}
	}
	return nil
}
func (a *hy1Association) WritePacket(body []byte) error { return a.send(a.address, body) }
func (a *hy1Association) ReadPacket() (Datagram, error) {
	for {
		a.mu.Lock()
		deadline := a.deadline
		a.mu.Unlock()
		var timer *time.Timer
		var expires <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expires = timer.C
		}
		stop := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case <-a.ctx.Done():
			stop()
			return Datagram{}, net.ErrClosed
		case d := <-a.queue:
			stop()
			return d, nil
		case <-expires:
			return Datagram{}, context.DeadlineExceeded
		case <-a.wake:
			stop()
		}
	}
}
func (a *hy1Association) SetDeadline(t time.Time) error {
	a.mu.Lock()
	a.deadline = t
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return nil
}
func (a *hy1Association) serverWrites() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case d := <-a.queue:
			h, p, err := decodeAddress(d.Address)
			if err != nil {
				return
			}
			if _, err = a.bridge.WriteTo(d.Payload, net.JoinHostPort(h, itoa(p))); err != nil {
				return
			}
		}
	}
}
func (a *hy1Association) serverReads() {
	buf := make([]byte, 65507)
	for {
		n, addr, err := a.bridge.ReadFrom(buf)
		if err != nil {
			return
		}
		h, p, err := splitProtocolTarget(addr)
		if err != nil {
			return
		}
		address, err := Address(h, p)
		if err != nil || a.send(address, buf[:n]) != nil {
			return
		}
	}
}
func dialHy1Packet(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	address, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	p, lease, err := getHy1(ctx, c)
	if err != nil {
		return nil, err
	}
	s, id, err := p.request(ctx, true, host, port)
	if err != nil {
		lease.Close()
		return nil, err
	}
	a, err := p.addAssociation(id, s, address)
	if err != nil {
		s.CancelRead(1)
		s.CancelWrite(1)
		lease.Close()
		return nil, err
	}
	return &hy1PacketLease{PacketStream: a, owner: lease}, nil
}
