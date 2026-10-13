package core

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	hs "github.com/apernet/hysteria/core/v2/server"
)

func validateHysteriaServer(c ServerConfig) error {
	if err := validateHysteriaObfs(c.Options); err != nil {
		return err
	}
	for k, v := range c.Options {
		switch k {
		case "congestion":
			if !contains([]string{"bbr", "reno"}, v) {
				return errors.New("HYSTERIA_CONGESTION_INVALID")
			}
		case "upmbps", "downmbps":
			if _, err := number(v, 1, 100000); err != nil {
				return errors.New("HYSTERIA_BANDWIDTH_INVALID")
			}
		case "disable-udp":
			if v != "true" && v != "false" {
				return errors.New("HYSTERIA_CONFIGURATION")
			}
		case "obfs", "obfs-password", "obfs_password":
		default:
			return errors.New("HYSTERIA_SERVER_OPTION_UNSUPPORTED")
		}
	}
	return nil
}

type hyAuth struct{ password string }

func (a hyAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return subtle.ConstantTimeCompare([]byte(auth), []byte(a.password)) == 1, "user"
}

func (e *Engine) startHysteriaServer(s serverSpec) (net.Addr, error) {
	packet, err := net.ListenPacket("udp", s.config.Listen)
	if err != nil {
		return nil, err
	}
	configureDatagramBuffers(packet)
	packet, err = wrapHysteriaPacket(packet, s.config.Options)
	if err != nil {
		return nil, err
	}
	limit := e.config.MaxConnections
	if limit > 128 {
		limit = 128
	}
	cfg := hs.Config{Conn: packet, TLSConfig: hs.TLSConfig{Certificates: s.tls.Certificates}, Authenticator: hyAuth{s.config.Password}, Outbound: &hyServerOutbound{e}, UDPIdleTimeout: 30 * time.Second, MaxConnections: limit, TCPRequestTimeout: e.config.ConnectTimeout,
		QUICConfig: hs.QUICConfig{InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 262144, InitialConnectionReceiveWindow: 262144, MaxConnectionReceiveWindow: 1048576, MaxIncomingStreams: int64(e.config.MaxConnections), MaxIdleTimeout: 30 * time.Second}, CongestionConfig: hs.CongestionConfig{Type: option(s.config.Options, "bbr", "congestion")}, DisableUDP: truth(s.config.Options["disable-udp"])}
	if cfg.QUICConfig.MaxIncomingStreams < 8 {
		cfg.QUICConfig.MaxIncomingStreams = 8
	}
	for key, target := range map[string]*uint64{"upmbps": &cfg.BandwidthConfig.MaxTx, "downmbps": &cfg.BandwidthConfig.MaxRx} {
		if v := s.config.Options[key]; v != "" {
			n, _ := strconv.ParseUint(v, 10, 64)
			*target = n * 125000
		}
	}
	server, err := hs.NewServer(&cfg)
	if err != nil {
		packet.Close()
		return nil, err
	}
	if !e.track(packet) {
		server.Close()
		return nil, net.ErrClosed
	}
	if !e.track(server) {
		e.untrack(packet)
		return nil, net.ErrClosed
	}
	if !e.spawn(func() { server.Serve(); server.Close(); e.untrack(server); e.untrack(packet) }) {
		server.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return packet.LocalAddr(), nil
}

type hyServerOutbound struct{ e *Engine }

func (o *hyServerOutbound) TCP(addr string) (net.Conn, error) {
	return o.e.DialContext(o.e.ctx, "tcp", addr)
}
func (o *hyServerOutbound) CheckUDP(addr string) error {
	_, _, err := splitProtocolTarget(addr)
	return err
}
func (o *hyServerOutbound) UDP(addr string) (hs.UDPConn, error) {
	ctx, cancel := context.WithCancel(o.e.ctx)
	b := &packetBridge{e: o.e, ctx: ctx, cancel: cancel, peers: map[string]*bridgePeer{}, queue: make(chan bridgeResult, 64)}
	if _, err := b.peer(addr); err != nil {
		b.Close()
		return nil, err
	}
	if !o.e.track(b) {
		return nil, net.ErrClosed
	}
	return b, nil
}
func splitProtocolTarget(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, errors.New("UDP_ADDRESS")
	}
	n, err := number(p, 1, 65535)
	if err != nil {
		return "", 0, err
	}
	_, err = Address(h, n)
	return h, n, err
}

// packetBridge routes every destination through the engine rather than a raw
// server UDP socket. Each peer consumes the shared flow budget, including peers
// reached over proxy outbounds. Queues and peer counts are bounded.
type bridgeResult struct {
	payload []byte
	addr    string
	err     error
}
type bridgePeer struct {
	stream  PacketStream
	once    sync.Once
	e       *Engine
	writeMu sync.Mutex
}

func (p *bridgePeer) close() { p.once.Do(func() { p.stream.Close(); p.e.release() }) }

type packetBridge struct {
	e       *Engine
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	peers   map[string]*bridgePeer
	queue   chan bridgeResult
	workers sync.WaitGroup
	once    sync.Once
}

func (b *packetBridge) peer(addr string) (*bridgePeer, error) {
	host, port, err := splitProtocolTarget(addr)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, net.ErrClosed
	}
	if p := b.peers[addr]; p != nil {
		return p, nil
	}
	if len(b.peers) >= 16 {
		return nil, errors.New("UDP_ASSOCIATION_PEER_LIMIT")
	}
	if !b.e.acquire() {
		return nil, errors.New("CONNECTION_LIMIT")
	}
	ctx, cancel := context.WithTimeout(b.ctx, b.e.config.ConnectTimeout)
	stream, err := b.e.dialPacket(ctx, host, port)
	cancel()
	if err != nil {
		b.e.release()
		return nil, err
	}
	p := &bridgePeer{stream: stream, e: b.e}
	b.peers[addr] = p
	b.e.accepted.Add(1)
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		defer p.close()
		for {
			packet, err := stream.ReadPacket()
			r := bridgeResult{err: err}
			if err == nil {
				h, n, x := decodeAddress(packet.Address)
				if x != nil {
					r.err = x
				} else {
					r.payload = packet.Payload
					r.addr = net.JoinHostPort(h, strconv.Itoa(n))
				}
			}
			select {
			case b.queue <- r:
			case <-b.ctx.Done():
				return
			}
			if r.err != nil {
				return
			}
		}
	}()
	return p, nil
}
func (b *packetBridge) WriteTo(payload []byte, addr string) (int, error) {
	if len(payload) > 65507 {
		return 0, errors.New("UDP_DATAGRAM_LENGTH")
	}
	p, err := b.peer(addr)
	if err != nil {
		return 0, err
	}
	p.writeMu.Lock()
	err = p.stream.WritePacket(payload)
	p.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	b.e.up.Add(uint64(len(payload)))
	return len(payload), nil
}
func (b *packetBridge) ReadFrom(buf []byte) (int, string, error) {
	select {
	case <-b.ctx.Done():
		return 0, "", net.ErrClosed
	case r := <-b.queue:
		if r.err != nil {
			return 0, "", r.err
		}
		if len(buf) < len(r.payload) {
			return 0, "", errors.New("UDP_BUFFER_SHORT")
		}
		n := copy(buf, r.payload)
		b.e.down.Add(uint64(n))
		return n, r.addr, nil
	}
}
func (b *packetBridge) Close() error {
	b.cancel()
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		list := make([]*bridgePeer, 0, len(b.peers))
		for _, p := range b.peers {
			list = append(list, p)
		}
		b.mu.Unlock()
		for _, p := range list {
			p.close()
		}
		b.workers.Wait()
		b.e.untrack(b)
	})
	return nil
}
