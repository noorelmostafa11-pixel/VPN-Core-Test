package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errMuxFrame = errors.New("MUX_FRAME_INVALID")

type muxFrame struct {
	id                       uint16
	status, options, network byte
	address, body            []byte
}

func readMuxFrame(r io.Reader) (muxFrame, error) {
	var f muxFrame
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return f, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 4 || n > 512 {
		return f, errMuxFrame
	}
	meta := make([]byte, n)
	if _, err := io.ReadFull(r, meta); err != nil {
		return f, err
	}
	f.id, f.status, f.options = binary.BigEndian.Uint16(meta), meta[2], meta[3]
	if f.status < 1 || f.status > 4 || f.options&^byte(3) != 0 {
		return f, errMuxFrame
	}
	if f.status == 1 || (f.status == 2 && len(meta) > 4) {
		if len(meta) < 8 || (meta[4] != 1 && meta[4] != 2) || (f.status == 2 && meta[4] != 2) {
			return f, errMuxFrame
		}
		f.network = meta[4]
		reader := bytes.NewReader(meta[5:])
		var err error
		f.address, err = mappedServerAddress(reader)
		if err != nil {
			return f, err
		}
		// XUDP's optional global ID is accepted as metadata. It does not grant
		// a source identity or an automatic cross-connection migration privilege.
		if reader.Len() != 0 && !(f.status == 1 && f.network == 2 && reader.Len() == 8) {
			return f, errMuxFrame
		}
	} else if len(meta) != 4 {
		return f, errMuxFrame
	}
	if f.options&1 != 0 {
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return f, err
		}
		n = int(binary.BigEndian.Uint16(length[:]))
		if n > 65507 {
			return f, errMuxFrame
		}
		f.body = make([]byte, n)
		if _, err := io.ReadFull(r, f.body); err != nil {
			return f, err
		}
	}
	return f, nil
}
func encodeMuxFrame(f muxFrame) ([]byte, error) {
	if len(f.body) > 65507 {
		return nil, errMuxFrame
	}
	meta := binary.BigEndian.AppendUint16(nil, f.id)
	meta = append(meta, f.status, f.options)
	if f.address != nil {
		if _, _, err := decodeAddress(f.address); err != nil {
			return nil, err
		}
		meta = append(meta, f.network)
		meta = append(meta, mappedAddress(f.address)...)
	}
	wire := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	wire = append(wire, meta...)
	if f.options&1 != 0 {
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(f.body)))
		wire = append(wire, f.body...)
	}
	return wire, nil
}

type muxServer struct {
	e       *Engine
	conn    net.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	udpOnly bool
	flows   map[uint16]*muxServerFlow
	workers sync.WaitGroup
	writeMu sync.Mutex
	last    atomic.Int64
}
type muxServerFlow struct {
	peer     *muxServer
	id       uint16
	udp      bool
	address  []byte
	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan Datagram
	last     atomic.Int64
	failed   atomic.Bool
	mu       sync.Mutex
	upstream net.Conn
	bridge   *tuicRelay
}

func (e *Engine) serveMux(conn net.Conn) {
	e.serveMuxPolicy(conn, false)
}
func (e *Engine) serveMuxPolicy(conn net.Conn, udpOnly bool) {
	ctx, cancel := context.WithCancel(e.ctx)
	p := &muxServer{e: e, conn: conn, ctx: ctx, cancel: cancel, flows: map[uint16]*muxServerFlow{}, udpOnly: udpOnly}
	p.last.Store(time.Now().UnixNano())
	conn.SetDeadline(time.Time{})
	ownerDone := make(chan struct{})
	stopOwner := context.AfterFunc(ctx, func() { conn.Close(); close(ownerDone) })
	defer func() {
		p.close()
		if !stopOwner() {
			<-ownerDone
		}
	}()
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if time.Since(time.Unix(0, p.last.Load())) >= e.config.IdleTimeout {
					p.cancel()
					conn.Close()
					return
				}
				p.mu.Lock()
				var expired []*muxServerFlow
				for _, f := range p.flows {
					if f.udp && time.Since(time.Unix(0, f.last.Load())) > 30*time.Second {
						expired = append(expired, f)
					}
				}
				p.mu.Unlock()
				for _, f := range expired {
					f.closeIO()
				}
			}
		}
	}()
	for {
		frame, err := readMuxFrame(conn)
		if err != nil {
			return
		}
		p.last.Store(time.Now().UnixNano())
		if frame.status == 4 {
			continue
		}
		p.mu.Lock()
		flow := p.flows[frame.id]
		p.mu.Unlock()
		if frame.status == 1 {
			if flow != nil {
				return
			}
			flow, err = p.start(frame)
			if err != nil {
				if p.send(muxFrame{id: frame.id, status: 3, options: 2}) != nil {
					return
				}
				continue
			}
		}
		if frame.status == 3 {
			if flow != nil {
				flow.closeIO()
			}
			continue
		}
		if flow == nil {
			if p.send(muxFrame{id: frame.id, status: 3, options: 2}) != nil {
				return
			}
			continue
		}
		if frame.options&2 != 0 {
			return
		}
		if frame.options&1 == 0 {
			continue
		}
		address := frame.address
		if address == nil {
			address = flow.address
		}
		if frame.network != 0 && (frame.network == 2) != flow.udp {
			return
		}
		flow.last.Store(time.Now().UnixNano())
		select {
		case flow.queue <- Datagram{Address: address, Payload: frame.body}:
		case <-flow.ctx.Done():
		default:
			if flow.udp {
				// UDP may shed excess datagrams; queues and workers stay bounded.
				continue
			}
			// Apply bounded backpressure to TCP rather than dropping bytes when
			// the destination is slower than the encrypted parent stream.
			timer := time.NewTimer(e.config.ConnectTimeout)
			select {
			case flow.queue <- Datagram{Address: address, Payload: frame.body}:
			case <-flow.ctx.Done():
			case <-timer.C:
				flow.failed.Store(true)
				flow.closeIO()
			}
			timer.Stop()
		}
	}
}
func (p *muxServer) send(f muxFrame) error {
	wire, err := encodeMuxFrame(f)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	p.conn.SetWriteDeadline(time.Now().Add(p.e.config.ConnectTimeout))
	err = writeAll(p.conn, wire)
	p.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		p.cancel()
		p.conn.Close()
	} else {
		p.last.Store(time.Now().UnixNano())
	}
	return err
}
func (p *muxServer) start(frame muxFrame) (*muxServerFlow, error) {
	if p.udpOnly && frame.network != 2 {
		p.e.rejected.Add(1)
		return nil, errors.New("VLESS_VISION_MUX_TCP_REJECTED")
	}
	if _, _, err := decodeAddress(frame.address); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.flows) >= 128 {
		return nil, errors.New("MUX_SESSION_LIMIT")
	}
	if !p.e.acquire() {
		return nil, errors.New("CONNECTION_LIMIT")
	}
	ctx, cancel := context.WithCancel(p.ctx)
	f := &muxServerFlow{peer: p, id: frame.id, udp: frame.network == 2, address: frame.address, ctx: ctx, cancel: cancel, queue: make(chan Datagram, 8)}
	f.last.Store(time.Now().UnixNano())
	p.flows[f.id] = f
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		defer p.e.release()
		defer func() {
			f.closeIO()
			options := byte(0)
			if f.failed.Load() {
				options = 2
			}
			p.send(muxFrame{id: f.id, status: 3, options: options})
			p.mu.Lock()
			if p.flows[f.id] == f {
				delete(p.flows, f.id)
			}
			p.mu.Unlock()
		}()
		if f.udp {
			f.runUDP()
		} else {
			f.runTCP()
		}
	}()
	return f, nil
}
func (p *muxServer) close() {
	p.mu.Lock()
	p.closed = true
	var flows []*muxServerFlow
	for _, f := range p.flows {
		flows = append(flows, f)
	}
	p.mu.Unlock()
	p.cancel()
	p.conn.Close()
	for _, f := range flows {
		f.closeIO()
	}
	p.workers.Wait()
}
func (f *muxServerFlow) closeIO() {
	f.cancel()
	f.mu.Lock()
	up, bridge := f.upstream, f.bridge
	f.mu.Unlock()
	if up != nil {
		up.Close()
	}
	if bridge != nil {
		bridge.Close()
	}
}
func (f *muxServerFlow) runTCP() {
	h, p, _ := decodeAddress(f.address)
	ctx, cancel := context.WithTimeout(f.ctx, f.peer.e.config.ConnectTimeout)
	defer cancel()
	ctx = f.peer.e.flowContext(ctx, f.peer.conn.RemoteAddr(), h)
	remote, err := f.peer.e.dialTCP(ctx, h, p)
	if err != nil {
		f.failed.Store(true)
		return
	}
	if !f.peer.e.track(remote) {
		return
	}
	defer f.peer.e.untrack(remote)
	defer remote.Close()
	f.mu.Lock()
	f.upstream = remote
	closed := f.ctx.Err() != nil
	f.mu.Unlock()
	if closed {
		return
	}
	f.peer.e.accepted.Add(1)
	f.peer.e.relay(&muxFlowConn{flow: f}, remote)
}
func (f *muxServerFlow) runUDP() {
	bridge := newTUICRelay(f.ctx, f.peer.e, f.peer.conn.RemoteAddr())
	f.mu.Lock()
	f.bridge = bridge
	closed := f.ctx.Err() != nil
	f.mu.Unlock()
	defer bridge.Close()
	if closed {
		return
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer f.closeIO()
		for {
			select {
			case <-f.ctx.Done():
				return
			case d := <-f.queue:
				h, p, err := decodeAddress(d.Address)
				if err != nil {
					return
				}
				if _, err = bridge.WriteTo(d.Payload, net.JoinHostPort(h, itoa(p))); err != nil {
					f.failed.Store(true)
					return
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer f.closeIO()
		buf := make([]byte, 65507)
		for {
			n, addr, err := bridge.ReadFrom(buf)
			if err != nil {
				return
			}
			h, p, err := splitProtocolTarget(addr)
			if err != nil {
				return
			}
			a, err := Address(h, p)
			if err != nil {
				return
			}
			if f.ctx.Err() != nil {
				return
			}
			f.last.Store(time.Now().UnixNano())
			if f.peer.send(muxFrame{id: f.id, status: 2, options: 1, network: 2, address: a, body: buf[:n]}) != nil {
				return
			}
		}
	}()
	<-f.ctx.Done()
	f.closeIO()
	workers.Wait()
}

type muxFlowConn struct {
	flow    *muxServerFlow
	pending []byte
}

func (c *muxFlowConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		select {
		case <-c.flow.ctx.Done():
			return 0, io.EOF
		case d := <-c.flow.queue:
			c.pending = d.Payload
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *muxFlowConn) Write(b []byte) (int, error) {
	if c.flow.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), 16000)
		if err := c.flow.peer.send(muxFrame{id: c.flow.id, status: 2, options: 1, body: b[:n]}); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	c.flow.last.Store(time.Now().UnixNano())
	return total, nil
}
func (c *muxFlowConn) Close() error         { c.flow.closeIO(); return nil }
func (c *muxFlowConn) CloseWrite() error    { c.flow.closeIO(); return nil }
func (c *muxFlowConn) LocalAddr() net.Addr  { return c.flow.peer.conn.LocalAddr() }
func (c *muxFlowConn) RemoteAddr() net.Addr { return c.flow.peer.conn.RemoteAddr() }

// Flow inactivity is enforced by Engine.relay, without changing deadlines on
// the shared parent socket and inadvertently interrupting other sessions.
func (c *muxFlowConn) SetDeadline(t time.Time) error      { return muxFlowDeadline(t) }
func (c *muxFlowConn) SetReadDeadline(t time.Time) error  { return muxFlowDeadline(t) }
func (c *muxFlowConn) SetWriteDeadline(t time.Time) error { return muxFlowDeadline(t) }
func muxFlowDeadline(t time.Time) error {
	if !t.IsZero() {
		return errors.New("MUX_FLOW_DEADLINE_UNSUPPORTED")
	}
	return nil
}
