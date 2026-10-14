package core

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"lukechampine.com/blake3"
)

type ssServerPacket struct {
	Datagram
	clientID [8]byte
	packetID uint64
}

// Authentication and semantic validation precede both replay-window mutation
// and peer admission, so corrupt traffic cannot allocate relay workers.
func (s *ssServerState) decodeUDP(wire []byte) (ssServerPacket, error) {
	c := s.codec
	var packet ssServerPacket
	if len(wire) > 65507 {
		return packet, errors.New("UDP_DATAGRAM_LENGTH")
	}
	if !c.modern {
		d, err := c.decode(wire)
		if err != nil {
			return packet, err
		}
		if !c.spec.stream && c.c.Cipher != "none" && c.c.Cipher != "plain" {
			if err = s.rememberSalt(wire[:c.spec.key]); err != nil {
				return packet, err
			}
		}
		packet.Datagram = d
		return packet, nil
	}
	var separate, body []byte
	var err error
	if c.method() == "chacha20-poly1305" {
		if len(wire) < 40 {
			return packet, errors.New("SS_UDP_TRUNCATED")
		}
		plain, err := c.open(c.master, wire[:24], wire[24:], "xchacha20-ietf-poly1305")
		if err != nil {
			return packet, err
		}
		if len(plain) < 27 {
			return packet, errors.New("SS_UDP_TRUNCATED")
		}
		separate, body = plain[:16], plain[16:]
	} else {
		if len(wire) < 32+16*(len(c.keys)-1) {
			return packet, errors.New("SS_UDP_TRUNCATED")
		}
		separate, err = aesECB(c.keys[0], wire[:16], true)
		if err != nil {
			return packet, err
		}
		pos := 16
		for i := 0; i+1 < len(c.keys); i++ {
			identity, err := aesECB(c.keys[i], wire[pos:pos+16], true)
			if err != nil {
				return packet, err
			}
			for j := range identity {
				identity[j] ^= separate[j]
			}
			expected := blake3.Sum256(c.keys[i+1])
			if !bytesEqual(identity, expected[:16]) {
				return packet, errors.New("SS2022_SERVER_IDENTITY")
			}
			pos += 16
		}
		key, err := subkey(c.master, separate[:8], c.spec.key, true)
		if err != nil {
			return packet, err
		}
		body, err = c.open(key, separate[4:], wire[pos:], c.method())
		if err != nil {
			return packet, err
		}
	}
	if len(body) < 11 || body[0] != 0 {
		return packet, errors.New("SS2022_SERVER_UDP_TYPE")
	}
	stamp, now := int64(binary.BigEndian.Uint64(body[1:9])), time.Now().Unix()
	if stamp < now-30 || stamp > now+30 {
		return packet, errors.New("SS2022_SERVER_TIMESTAMP")
	}
	padding := getWord(body, 9)
	if padding > len(body)-11 {
		return packet, errors.New("SS_UDP_TRUNCATED")
	}
	body = body[11+padding:]
	n, err := addressSize(body)
	if err != nil || n == 0 {
		return packet, errors.New("SS_UDP_ADDRESS")
	}
	if _, _, err = decodeAddress(body[:n]); err != nil {
		return packet, err
	}
	copy(packet.clientID[:], separate[:8])
	packet.packetID = binary.BigEndian.Uint64(separate[8:])
	packet.Datagram = Datagram{append([]byte(nil), body[:n]...), append([]byte(nil), body[n:]...)}
	return packet, nil
}

type ssUDPServer struct {
	e       *Engine
	state   *ssServerState
	conn    net.PacketConn
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	peers   map[string]*ssUDPServerPeer
	workers sync.WaitGroup
	done    chan struct{}
}
type ssUDPServerPeer struct {
	server   *ssUDPServer
	ctx      context.Context
	cancel   context.CancelFunc
	bridge   *tuicRelay
	queue    chan ssServerDelivery
	address  atomic.Pointer[net.UDPAddr]
	last     atomic.Int64
	replay   replayWindow // guarded by server.mu
	clientID [8]byte
	serverID []byte
	counter  uint64 // only the reply worker writes it
}
type ssServerDelivery struct {
	Datagram
	source *net.UDPAddr
}

func (e *Engine) listenSSServer(state *ssServerState, address string, listenTCP func(string, string) (net.Listener, error)) (net.Listener, *ssUDPServer, error) {
	_, port, _ := net.SplitHostPort(address)
	n, _ := number(port, 0, 65535)
	attempts := 1
	if n == 0 {
		// TCP and UDP have separate ephemeral-port allocators. Retry only an
		// automatically chosen port, with no workers on failed UDP binds.
		attempts = 8
	}
	var err error
	for i := 0; i < attempts; i++ {
		if e.ctx.Err() != nil {
			return nil, nil, net.ErrClosed
		}
		listener, bindErr := listenTCP("tcp", address)
		if bindErr != nil {
			return nil, nil, bindErr
		}
		if !e.track(listener) {
			return nil, nil, net.ErrClosed
		}
		var packets *ssUDPServer
		packets, err = e.startSSUDP(state, listener.Addr())
		if err == nil {
			return listener, packets, nil
		}
		listener.Close()
		e.untrack(listener)
		if errors.Is(err, net.ErrClosed) {
			break
		}
	}
	return nil, nil, err
}

func (e *Engine) startSSUDP(state *ssServerState, addr net.Addr) (*ssUDPServer, error) {
	conn, err := net.ListenPacket("udp", addr.String())
	if err != nil {
		return nil, err
	}
	configureDatagramBuffers(conn)
	if !e.track(conn) {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(e.ctx)
	p := &ssUDPServer{e: e, state: state, conn: conn, ctx: ctx, cancel: cancel, peers: map[string]*ssUDPServerPeer{}, done: make(chan struct{})}
	if !e.spawn(func() { defer close(p.done); defer e.untrack(conn); p.run() }) {
		cancel()
		conn.Close()
		e.untrack(conn)
		return nil, net.ErrClosed
	}
	return p, nil
}
func (p *ssUDPServer) stop() { p.cancel(); p.conn.Close(); <-p.done }
func (p *ssUDPServer) run() {
	defer func() {
		p.cancel()
		p.conn.Close()
		p.mu.Lock()
		p.closed = true
		for _, peer := range p.peers {
			peer.cancel()
		}
		p.mu.Unlock()
		p.workers.Wait()
	}()
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case now := <-tick.C:
				p.expire(now)
			}
		}
	}()
	wire := make([]byte, 65536)
	for {
		n, addr, err := p.conn.ReadFrom(wire)
		if err != nil {
			return
		}
		packet, err := p.state.decodeUDP(wire[:n])
		if err != nil {
			p.e.rejected.Add(1)
			continue
		}
		if err = p.admit(packet, addr); err != nil {
			p.e.rejected.Add(1)
		}
	}
}
func (p *ssUDPServer) expire(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, peer := range p.peers {
		// Retain modern replay state longer than the complete +/-30s timestamp
		// validity horizon, including errors and network changes.
		if now.Sub(time.Unix(0, peer.last.Load())) >= 65*time.Second {
			delete(p.peers, key)
			peer.cancel()
		}
	}
}
func (p *ssUDPServer) admit(packet ssServerPacket, addr net.Addr) error {
	source, ok := addr.(*net.UDPAddr)
	if !ok {
		return errors.New("SS_SERVER_SOURCE")
	}
	copyAddr := *source
	copyAddr.IP = append(net.IP(nil), source.IP...)
	key := source.String()
	if p.state.codec.modern {
		key = string(packet.clientID[:])
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return net.ErrClosed
	}
	peer := p.peers[key]
	if peer != nil && peer.ctx.Err() != nil {
		// Keep its replay tombstone until expiry, but do not let new traffic
		// keep a stopped relay alive or change its authenticated return address.
		return net.ErrClosed
	}
	if peer == nil {
		if len(p.peers) >= 128 {
			return errors.New("SS_SERVER_SESSION_LIMIT")
		}
		if !p.e.acquire() {
			return errors.New("CONNECTION_LIMIT")
		}
		ctx, cancel := context.WithCancel(p.ctx)
		peer = &ssUDPServerPeer{server: p, ctx: ctx, cancel: cancel, clientID: packet.clientID, queue: make(chan ssServerDelivery, 8)}
		peer.address.Store(&copyAddr)
		peer.serverID = randomBytes(8)
		for bytesEqual(peer.serverID, peer.clientID[:]) {
			peer.serverID = randomBytes(8)
		}
		peer.bridge = newTUICRelaySource(ctx, p.e, func() net.Addr { return peer.address.Load() })
		p.peers[key] = peer
		p.workers.Add(1)
		go peer.run()
		p.e.accepted.Add(1)
	}
	if p.state.codec.modern {
		if err := peer.replay.accept(packet.packetID); err != nil {
			return err
		}
	}
	peer.address.Store(&copyAddr)
	peer.last.Store(time.Now().UnixNano())
	select {
	case peer.queue <- ssServerDelivery{packet.Datagram, &copyAddr}:
	case <-peer.ctx.Done():
		return net.ErrClosed
	default:
	}
	return nil
}
func (p *ssUDPServerPeer) run() {
	defer p.server.workers.Done()
	defer p.server.e.release()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-p.ctx.Done():
				return
			case d := <-p.queue:
				h, port, err := decodeAddress(d.Address)
				if err == nil {
					_, err = p.bridge.writeToSource(d.Payload, net.JoinHostPort(h, itoa(port)), d.source)
				}
				if err != nil {
					p.server.e.rejected.Add(1)
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer p.cancel()
		buf := make([]byte, 65507)
		for {
			n, addr, err := p.bridge.ReadFrom(buf)
			if err != nil {
				return
			}
			h, port, err := splitProtocolTarget(addr)
			if err != nil {
				continue
			}
			address, err := Address(h, port)
			if err != nil {
				continue
			}
			wire, err := p.encode(Datagram{address, buf[:n]})
			if err != nil {
				continue
			}
			if _, err = p.server.conn.WriteTo(wire, p.address.Load()); err != nil && p.ctx.Err() != nil {
				return
			}
		}
	}()
	<-p.ctx.Done()
	p.bridge.Close()
	workers.Wait()
}
func (p *ssUDPServerPeer) encode(packet Datagram) ([]byte, error) {
	c := p.server.state.codec
	if !c.modern {
		return c.encode(packet)
	}
	if p.counter == ^uint64(0) {
		return nil, errors.New("SS_UDP_COUNTER")
	}
	separate := join(p.serverID, wide(p.counter))
	p.counter++
	body := join([]byte{1}, wide(uint64(time.Now().Unix())), p.clientID[:], []byte{0, 0}, packet.Address, packet.Payload)
	var wire []byte
	if c.method() == "chacha20-poly1305" {
		nonce := randomBytes(24)
		sealed, err := c.seal(c.master, nonce, join(separate, body), "xchacha20-ietf-poly1305")
		if err != nil {
			return nil, err
		}
		wire = append(nonce, sealed...)
	} else {
		header, err := aesECB(c.master, separate, false)
		if err != nil {
			return nil, err
		}
		key, err := subkey(c.master, p.serverID, c.spec.key, true)
		if err != nil {
			return nil, err
		}
		sealed, err := c.seal(key, separate[4:], body, c.method())
		if err != nil {
			return nil, err
		}
		wire = append(header, sealed...)
	}
	if len(wire) > 65507 {
		return nil, errors.New("UDP_DATAGRAM_LENGTH")
	}
	return wire, nil
}
