package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	hc "github.com/apernet/hysteria/core/v2/client"
	quic "github.com/apernet/quic-go"
)

func hy1QUICConfig(timeout time.Duration) *quic.Config {
	// Old peers fragment using the advertised frame size alone. Keep it below
	// the minimum QUIC path size, including xplus's additional 16 bytes.
	return &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: timeout, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, InitialPacketSize: 1200, DisablePathMTUDiscovery: true, EnableDatagrams: true, MaxDatagramFrameSize: 1000,
		InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 262144, InitialConnectionReceiveWindow: 262144, MaxConnectionReceiveWindow: 1048576, MaxIncomingStreams: 128, MaxIncomingUniStreams: -1}
}
func hy1Rate(options map[string]string, name string) uint64 {
	n, _ := strconv.ParseUint(options[name], 10, 64)
	return n * 125000
}

type hy1Peer struct {
	conn      *quic.Conn
	transport *quic.Transport
	packet    net.PacketConn
	control   *quic.Stream
	ctx       context.Context
	cancel    context.CancelFunc
	server    *Engine
	timeout   time.Duration
	mu        sync.Mutex
	closed    bool
	assocs    map[uint32]*hy1Association
	next      uint32
	workers   sync.WaitGroup
	once      sync.Once
}

func newHy1Peer(q *quic.Conn, e *Engine, timeout time.Duration) *hy1Peer {
	base := q.Context()
	if e != nil {
		base = e.ctx
	}
	ctx, cancel := context.WithCancel(base)
	return &hy1Peer{conn: q, ctx: ctx, cancel: cancel, server: e, timeout: timeout, assocs: map[uint32]*hy1Association{}}
}
func (p *hy1Peer) spawn(fn func()) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.workers.Add(1)
	go func() { defer p.workers.Done(); fn() }()
	return true
}
func (p *hy1Peer) shutdown()      { p.cancel(); p.conn.CloseWithError(1, "") }
func (p *hy1Peer) IsClosed() bool { return p.ctx.Err() != nil || p.conn.Context().Err() != nil }
func (p *hy1Peer) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		list := make([]*hy1Association, 0, len(p.assocs))
		for _, a := range p.assocs {
			list = append(list, a)
		}
		p.mu.Unlock()
		p.shutdown()
		for _, a := range list {
			a.Close()
		}
		if p.transport != nil {
			p.transport.Close()
		}
		if p.packet != nil {
			p.packet.Close()
		}
		p.workers.Wait()
	})
	return nil
}
func (p *hy1Peer) start() {
	p.spawn(p.readDatagrams)
	p.spawn(func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-tick.C:
				p.mu.Lock()
				var old []*hy1Association
				for _, a := range p.assocs {
					if time.Since(a.last) > 30*time.Second {
						old = append(old, a)
					}
				}
				p.mu.Unlock()
				for _, a := range old {
					a.Close()
				}
			}
		}
	})
	if p.server != nil {
		p.spawn(func() {
			select {
			case <-p.conn.Context().Done():
				p.cancel()
			case <-p.ctx.Done():
			}
		})
	}
	// A closed control stream signals owner loss. Unexpected control data is invalid.
	p.spawn(func() { var b [1]byte; p.control.Read(b[:]); p.shutdown() })
}
func (p *hy1Peer) readDatagrams() {
	for {
		b, err := p.conn.ReceiveDatagram(p.ctx)
		if err != nil {
			return
		}
		f, err := hy1ReadFragment(b)
		if err != nil {
			continue
		}
		p.mu.Lock()
		a := p.assocs[f.session]
		if a != nil {
			a.last = time.Now()
		}
		p.mu.Unlock()
		if a == nil {
			continue
		}
		d, ready, err := a.defrag.add(f)
		if err != nil || !ready {
			continue
		}
		select {
		case a.queue <- d:
		case <-a.ctx.Done():
		default:
		}
	}
}

type hy1Conn struct {
	*quic.Stream
	peer *hy1Peer
	once sync.Once
}

func (c *hy1Conn) LocalAddr() net.Addr  { return c.peer.conn.LocalAddr() }
func (c *hy1Conn) RemoteAddr() net.Addr { return c.peer.conn.RemoteAddr() }
func (c *hy1Conn) CloseWrite() error    { return c.Stream.Close() }
func (c *hy1Conn) Close() error {
	c.once.Do(func() { c.Stream.CancelRead(0); c.Stream.Close() })
	return nil
}

func newHy1Client(ctx context.Context, c Config) (io.Closer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	s, err := c.tlsSettings()
	if err != nil {
		return nil, err
	}
	roots, err := tlsRoots(s)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{ServerName: c.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: c.ALPN}
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"hysteria"}
	}
	if len(s.Pins) > 0 || len(s.Names) > 0 {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = verifyConfigured(s, roots)
	}
	if c.ECH != "" {
		tlsConfig.EncryptedClientHelloConfigList, err = resolveECH(ctx, c.ECH, c.ServerName, roots)
		if err != nil {
			return nil, err
		}
	}
	ips, err := bootstrapIPs(ctx, c.Server)
	if err != nil {
		return nil, err
	}
	return raceProtocolClients(ctx, ips, func(attempt context.Context, ip net.IPAddr) (io.Closer, error) {
		network, local := "udp4", "0.0.0.0:0"
		if ip.IP.To4() == nil {
			network, local = "udp6", "[::]:0"
		}
		socket, err := outboundPacket(attempt, network, local)
		if err != nil {
			return nil, err
		}
		configureDatagramBuffers(socket)
		socket = wrapHy1Packet(socket, c.Options)
		t := &quic.Transport{Conn: socket}
		q, err := t.Dial(attempt, &net.UDPAddr{IP: ip.IP, Zone: ip.Zone, Port: c.Port}, tlsConfig, hy1QUICConfig(c.ConnectTimeout))
		if err != nil {
			t.Close()
			socket.Close()
			return nil, errors.Join(errors.New("HYSTERIA1_HANDSHAKE_FAILED"), err)
		}
		p := newHy1Peer(q, nil, c.ConnectTimeout)
		p.transport, p.packet = t, socket
		stream, err := q.OpenStreamSync(attempt)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.control = stream
		if d, ok := attempt.Deadline(); ok {
			stream.SetDeadline(d)
		}
		done := make(chan struct{})
		stop := context.AfterFunc(attempt, func() { p.shutdown(); close(done) })
		tx, rx := hy1Rate(c.Options, "upmbps"), hy1Rate(c.Options, "downmbps")
		err = writeAll(stream, hy1Hello(3, tx, rx, c.Password))
		if err == nil {
			var ok byte
			var stx, srx uint64
			ok, stx, srx, _, err = hy1ReadHello(stream)
			if err == nil {
				if ok != 1 {
					err = errors.New("HYSTERIA1_AUTHENTICATION_FAILED")
				} else if stx > rx || srx > tx {
					err = errHy1Wire
				} else {
					hc.ProjectUseBrutal(q, srx)
				}
			}
		}
		if !stop() {
			<-done
		}
		if err == nil {
			err = attempt.Err()
		}
		if err != nil {
			p.Close()
			return nil, err
		}
		stream.SetDeadline(time.Time{})
		p.start()
		return p, nil
	})
}
func getHy1(ctx context.Context, c Config) (*hy1Peer, io.Closer, error) {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	key := "hysteria1:" + hex.EncodeToString(sum[:])
	if r, ok := ctx.Value(routeReuseKey{}).(routeReuse); ok {
		key += fmt.Sprintf(":%p:%s", r.table, r.tag)
	}
	if cache := engineClientCache(ctx); cache != nil {
		lease, err := cache.get(ctx, key, func(ctx context.Context) (io.Closer, error) { return newHy1Client(ctx, c) })
		if err != nil {
			return nil, nil, err
		}
		return lease.entry.client.(*hy1Peer), lease, nil
	}
	v, err := newHy1Client(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	return v.(*hy1Peer), v, nil
}
func (p *hy1Peer) request(ctx context.Context, udp bool, host string, port int) (*quic.Stream, uint32, error) {
	b, err := hy1Request(udp, host, port)
	if err != nil {
		return nil, 0, err
	}
	s, err := p.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, 0, err
	}
	if d, ok := ctx.Deadline(); ok {
		s.SetDeadline(d)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { s.CancelRead(1); s.CancelWrite(1); close(done) })
	err = writeAll(s, b)
	var id uint32
	if err == nil {
		id, err = hy1ReadResponse(s)
	}
	if !stop() {
		<-done
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		s.CancelRead(1)
		s.CancelWrite(1)
		return nil, 0, err
	}
	s.SetDeadline(time.Time{})
	return s, id, nil
}
func dialHy1(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	p, lease, err := getHy1(ctx, c)
	if err != nil {
		return nil, err
	}
	s, _, err := p.request(ctx, false, host, port)
	if err != nil {
		lease.Close()
		return nil, err
	}
	return &hyLeaseConn{Conn: &hy1Conn{Stream: s, peer: p}, owner: lease}, nil
}
