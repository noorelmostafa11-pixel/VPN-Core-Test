package core

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Direct relay traffic shares an unconnected UDP socket per family. That keeps
// the source port stable across destinations and permits Full Cone replies.
// Every new request still evaluates the current routing policy. Proxy and block
// decisions retain packetBridge's protected, per-destination routed path.
type tuicRelay struct {
	e       *Engine
	ctx     context.Context
	cancel  context.CancelFunc
	source  net.Addr
	proxy   *packetBridge
	mu      sync.Mutex
	closed  bool
	sockets map[string]net.PacketConn
	queue   chan bridgeResult
	workers sync.WaitGroup
	once    sync.Once
}

func newTUICRelay(ctx context.Context, e *Engine, source net.Addr) *tuicRelay {
	ctx, cancel := context.WithCancel(ctx)
	pctx, pcancel := context.WithCancel(ctx)
	b := &tuicRelay{e: e, ctx: ctx, cancel: cancel, source: source, sockets: map[string]net.PacketConn{}, queue: make(chan bridgeResult, 8), proxy: &packetBridge{e: e, ctx: pctx, cancel: pcancel, peers: map[string]*bridgePeer{}, queue: make(chan bridgeResult, 8)}}
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		buf := make([]byte, 65507)
		for {
			n, addr, err := b.proxy.ReadFrom(buf)
			if err != nil {
				return
			}
			r := bridgeResult{payload: append([]byte(nil), buf[:n]...), addr: addr}
			select {
			case b.queue <- r:
			case <-ctx.Done():
				return
			}
		}
	}()
	return b
}
func (b *tuicRelay) direct(ctx context.Context, host string, port int) bool {
	if b.e.router == nil {
		return b.e.config.Protocol == "direct"
	}
	t := b.e.router.table.Load()
	tag := t.target(ctx, "udp", host, port)
	o, ok := t.outbounds[tag]
	return ok && o.config.Protocol == "direct" && o.detour == ""
}
func (b *tuicRelay) socket(ctx context.Context, network string) (net.PacketConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, net.ErrClosed
	}
	if s := b.sockets[network]; s != nil {
		return s, nil
	}
	if !b.e.acquire() {
		return nil, errors.New("CONNECTION_LIMIT")
	}
	local := "0.0.0.0:0"
	if network == "udp6" {
		local = "[::]:0"
	}
	s, err := outboundPacket(ctx, network, local)
	if err != nil {
		b.e.release()
		return nil, err
	}
	configureDatagramBuffers(s)
	b.sockets[network] = s
	b.e.accepted.Add(1)
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		defer b.e.release()
		buf := make([]byte, 65507)
		for {
			n, addr, err := s.ReadFrom(buf)
			if err != nil {
				return
			}
			host, port, err := splitProtocolTarget(addr.String())
			if err != nil {
				continue
			}
			ctx := b.e.flowContext(b.ctx, b.source, host)
			if !b.direct(ctx, host, port) {
				continue
			}
			b.e.down.Add(uint64(n))
			r := bridgeResult{payload: append([]byte(nil), buf[:n]...), addr: addr.String()}
			select {
			case b.queue <- r:
			case <-b.ctx.Done():
				return
			default:
			}
		}
	}()
	return s, nil
}
func (b *tuicRelay) WriteTo(body []byte, addr string) (int, error) {
	if len(body) > 65507 {
		return 0, errors.New("UDP_DATAGRAM_LENGTH")
	}
	host, port, err := splitProtocolTarget(addr)
	if err != nil {
		return 0, err
	}
	if b.e.dns != nil {
		if name := b.e.dns.fakeName(host); name != "" {
			host = name
			addr = net.JoinHostPort(host, itoa(port))
		}
	}
	ctx, cancel := context.WithTimeout(b.ctx, b.e.config.ConnectTimeout)
	defer cancel()
	ctx = b.e.flowContext(ctx, b.source, host)
	if !b.direct(ctx, host, port) {
		return b.proxy.WriteTo(body, addr)
	}
	ips, err := bootstrapIPs(ctx, host)
	if err != nil {
		return 0, err
	}
	if len(ips) == 0 {
		return 0, errors.New("BOOTSTRAP_DNS_FAILED")
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.IP.To4() != nil {
			ip = candidate
			break
		}
	}
	network := "udp4"
	if ip.IP.To4() == nil {
		network = "udp6"
	}
	s, err := b.socket(ctx, network)
	if err != nil {
		return 0, err
	}
	n, err := s.WriteTo(body, &net.UDPAddr{IP: ip.IP, Zone: ip.Zone, Port: port})
	if err == nil {
		b.e.up.Add(uint64(n))
	}
	return n, err
}
func (b *tuicRelay) ReadFrom(buf []byte) (int, string, error) {
	select {
	case <-b.ctx.Done():
		return 0, "", net.ErrClosed
	case r := <-b.queue:
		if len(buf) < len(r.payload) {
			return 0, "", errors.New("UDP_BUFFER_SHORT")
		}
		return copy(buf, r.payload), r.addr, r.err
	}
}
func (b *tuicRelay) Close() error {
	b.once.Do(func() {
		b.cancel()
		b.mu.Lock()
		b.closed = true
		for _, s := range b.sockets {
			s.Close()
		}
		b.mu.Unlock()
		b.proxy.Close()
		b.workers.Wait()
	})
	return nil
}
