package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type tuicAssociation struct {
	peer     *tuicPeer
	id       uint16
	native   bool
	address  []byte
	queue    chan Datagram
	ctx      context.Context
	cancel   context.CancelFunc
	defrag   tuicDefrag
	bridge   *tuicRelay
	writeMu  sync.Mutex
	packetID uint16
	last     time.Time // peer.mu
	mu       sync.Mutex
	deadline time.Time
	wake     chan struct{}
	once     sync.Once
}

func (p *tuicPeer) association(id uint16, native bool, create bool) (*tuicAssociation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if a := p.assocs[id]; a != nil {
		if a.native != native {
			return nil, errTUICWire
		}
		a.last = time.Now()
		return a, nil
	}
	if !create || p.retired[id/8]&(1<<uint(id%8)) != 0 {
		return nil, nil
	}
	if len(p.assocs) >= 64 {
		return nil, errors.New("TUIC_ASSOCIATION_LIMIT")
	}
	if p.server != nil && !p.server.acquire() {
		return nil, errors.New("CONNECTION_LIMIT")
	}
	ctx, cancel := context.WithCancel(p.ctx)
	a := &tuicAssociation{peer: p, id: id, native: native, queue: make(chan Datagram, 8), ctx: ctx, cancel: cancel, last: time.Now(), wake: make(chan struct{}, 1)}
	if p.server != nil {
		a.bridge = newTUICRelay(ctx, p.server, p.conn.RemoteAddr())
		p.workers.Add(2)
		go func() { defer p.workers.Done(); defer a.Close(); a.serverWrites() }()
		go func() { defer p.workers.Done(); defer a.Close(); a.serverReads() }()
	}
	p.assocs[id] = a
	return a, nil
}
func (p *tuicPeer) deliver(f tuicFragment, native bool) error {
	a, err := p.association(f.assoc, native, p.server != nil)
	if err != nil || a == nil {
		return err
	}
	d, ready, err := a.defrag.add(f)
	if err != nil || !ready {
		return err
	}
	select {
	case a.queue <- d:
	case <-a.ctx.Done():
	default: /* UDP drops under backpressure instead of blocking the QUIC dispatcher. */
	}
	return nil
}
func (a *tuicAssociation) finish() {
	a.once.Do(func() {
		a.cancel()
		if a.bridge != nil {
			a.bridge.Close()
			a.peer.server.release()
		}
	})
}
func (a *tuicAssociation) Close() error {
	a.finish()
	p := a.peer
	p.mu.Lock()
	if p.assocs[a.id] == a {
		delete(p.assocs, a.id)
		p.retired[a.id/8] |= 1 << uint(a.id%8)
	}
	p.mu.Unlock()
	return nil
}
func (a *tuicAssociation) send(address, body []byte) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.ctx.Err() != nil {
		return net.ErrClosed
	}
	p := a.peer
	p.mu.Lock()
	a.last = time.Now()
	p.mu.Unlock()
	a.packetID++
	frames, err := tuicPacketFrames(a.id, a.packetID, address, body, a.native)
	if err != nil {
		return err
	}
	a.mu.Lock()
	deadline := a.deadline
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(a.ctx, p.timeout)
	defer cancel()
	if !deadline.IsZero() {
		if time.Until(deadline) <= 0 {
			return context.DeadlineExceeded
		}
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, deadline)
		defer stop()
	}
	for _, frame := range frames {
		if a.native {
			err = p.conn.SendDatagram(frame)
		} else {
			err = p.sendControl(ctx, frame)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (a *tuicAssociation) WritePacket(body []byte) error { return a.send(a.address, body) }
func (a *tuicAssociation) ReadPacket() (Datagram, error) {
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
func (a *tuicAssociation) SetDeadline(t time.Time) error {
	a.mu.Lock()
	a.deadline = t
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return nil
}
func (a *tuicAssociation) serverWrites() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case d := <-a.queue:
			host, port, err := decodeAddress(d.Address)
			if err != nil {
				return
			}
			if _, err = a.bridge.WriteTo(d.Payload, net.JoinHostPort(host, itoa(port))); err != nil {
				return
			}
		}
	}
}
func (a *tuicAssociation) serverReads() {
	buf := make([]byte, 65507)
	for {
		n, addr, err := a.bridge.ReadFrom(buf)
		if err != nil {
			return
		}
		host, port, err := splitProtocolTarget(addr)
		if err != nil {
			return
		}
		address, err := Address(host, port)
		if err != nil {
			return
		}
		if a.send(address, buf[:n]) != nil {
			return
		}
	}
}

type tuicPacketLease struct {
	*tuicAssociation
	owner interface{ Close() error }
	once  sync.Once
}

func (a *tuicPacketLease) Close() error {
	a.once.Do(func() {
		a.tuicAssociation.Close()
		ctx, cancel := context.WithTimeout(a.peer.ctx, time.Second)
		defer cancel()
		a.peer.sendControl(ctx, []byte{5, 3, byte(a.id >> 8), byte(a.id)})
		a.owner.Close()
	})
	return nil
}
func dialTUICPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	address, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	p, owner, err := getTUIC(ctx, c)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.next > 65535 {
		p.mu.Unlock()
		owner.Close()
		return nil, errors.New("TUIC_ASSOCIATION_ID_EXHAUSTED")
	}
	id := uint16(p.next)
	p.next++
	p.mu.Unlock()
	a, err := p.association(id, option(c.Options, "native", "udp-relay-mode", "udp_relay_mode") == "native", true)
	if err != nil || a == nil {
		owner.Close()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
	a.address = address
	return &tuicPacketLease{tuicAssociation: a, owner: owner}, nil
}
