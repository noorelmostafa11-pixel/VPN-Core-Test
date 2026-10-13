package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

func parseTUICURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "tuic", "quic", "tls"
	u, err := url.Parse(uri)
	if err != nil || u.User == nil || (u.Path != "" && u.Path != "/") {
		return c, errors.New("TUIC_CONFIGURATION")
	}
	c.UUID, err = tuicUUID(u.User.Username())
	if err != nil {
		return c, err
	}
	c.Password, _ = u.User.Password()
	c.Server, c.ServerName, c.Port = u.Hostname(), u.Hostname(), 443
	if u.Port() != "" {
		c.Port, err = number(u.Port(), 1, 65535)
		if err != nil {
			return c, err
		}
	}
	c.Options = map[string]string{}
	for k, v := range u.Query() {
		if len(v) != 1 {
			return c, errors.New("TUIC_CONFIGURATION")
		}
		c.Options[strings.ToLower(k)] = v[0]
	}
	c.ServerName = option(c.Options, c.Server, "sni", "peer")
	c.Fingerprint = option(c.Options, "native", "fp", "fingerprint")
	c.ECH = c.Options["ech"]
	c.ALPN = strings.Split(option(c.Options, "h3", "alpn"), ",")
	c.InsecureRequested = truth(option(c.Options, "", "insecure", "allowinsecure"))
	return c, c.Validate()
}
func tuicUUID(text string) ([16]byte, error) {
	var id [16]byte
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return id, errors.New("TUIC_UUID_INVALID")
	}
	b, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(b) != 16 {
		return id, errors.New("TUIC_UUID_INVALID")
	}
	copy(id[:], b)
	return id, nil
}
func validateTUIC(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || c.Password == "" || len(c.Password) > 4096 || c.UUID == [16]byte{} || c.Security != "tls" || c.Transport != "quic" {
		return errors.New("TUIC_CONFIGURATION")
	}
	for k := range c.Options {
		if !contains([]string{"sni", "peer", "alpn", "fp", "fingerprint", "ech", "insecure", "allowinsecure", "pinsha256", "pcs", "vcn", "udp-relay-mode", "udp_relay_mode"}, k) {
			return errors.New("TUIC_OPTION_UNSUPPORTED")
		}
	}
	if c.Fingerprint != "" && c.Fingerprint != "native" {
		return errors.New("TUIC_FINGERPRINT_UNSUPPORTED")
	}
	if !contains([]string{"native", "quic"}, option(c.Options, "native", "udp-relay-mode", "udp_relay_mode")) {
		return errors.New("TUIC_UDP_MODE_INVALID")
	}
	if len(c.ALPN) > 8 {
		return errors.New("TUIC_ALPN_INVALID")
	}
	for _, p := range c.ALPN {
		if len(p) == 0 || len(p) > 255 {
			return errors.New("TUIC_ALPN_INVALID")
		}
	}
	_, err := c.tlsSettings()
	return err
}
func tuicQUICConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: 30 * time.Second, InitialPacketSize: 1200, DisablePathMTUDiscovery: true, EnableDatagrams: true,
		InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 262144, InitialConnectionReceiveWindow: 262144, MaxConnectionReceiveWindow: 1048576, MaxIncomingStreams: 128, MaxIncomingUniStreams: 64}
}

type tuicPeer struct {
	conn      *quic.Conn
	transport *quic.Transport
	packet    net.PacketConn
	ctx       context.Context
	cancel    context.CancelFunc
	server    *Engine
	users     map[[16]byte]string
	auth      chan struct{}
	authOnce  sync.Once
	mu        sync.Mutex
	closed    bool
	assocs    map[uint16]*tuicAssociation
	next      uint32
	retired   [8192]byte
	workers   sync.WaitGroup
	commands  chan struct{}
	closeOnce sync.Once
	timeout   time.Duration
}

func newTUICPeer(q *quic.Conn, e *Engine, users map[[16]byte]string, timeout time.Duration) *tuicPeer {
	base := q.Context()
	if e != nil {
		base = e.ctx
	}
	ctx, cancel := context.WithCancel(base)
	p := &tuicPeer{conn: q, ctx: ctx, cancel: cancel, server: e, users: users, auth: make(chan struct{}), assocs: map[uint16]*tuicAssociation{}, commands: make(chan struct{}, 32), timeout: timeout}
	if e == nil {
		close(p.auth)
	}
	return p
}
func (p *tuicPeer) spawn(fn func()) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.workers.Add(1)
	go func() { defer p.workers.Done(); fn() }()
	return true
}
func (p *tuicPeer) start() {
	p.spawn(p.readUni)
	p.spawn(p.readDatagrams)
	p.spawn(p.maintenance)
	if p.server != nil {
		p.spawn(p.readTCP)
		p.spawn(func() {
			select {
			case <-p.conn.Context().Done():
				p.cancel()
			case <-p.ctx.Done():
			}
		})
	}
}
func (p *tuicPeer) shutdown()      { p.cancel(); p.conn.CloseWithError(1, "") }
func (p *tuicPeer) IsClosed() bool { return p.ctx.Err() != nil }
func (p *tuicPeer) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		list := make([]*tuicAssociation, 0, len(p.assocs))
		for _, a := range p.assocs {
			list = append(list, a)
		}
		p.mu.Unlock()
		p.shutdown()
		for _, a := range list {
			a.finish()
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
func (p *tuicPeer) waitAuth() bool {
	select {
	case <-p.auth:
		return p.ctx.Err() == nil
	case <-p.ctx.Done():
		return false
	}
}
func (p *tuicPeer) maintenance() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	authDeadline := time.NewTimer(p.timeout)
	defer authDeadline.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-authDeadline.C:
			if p.server != nil {
				select {
				case <-p.auth:
				default:
					p.shutdown()
					return
				}
			}
		case <-ticker.C:
			p.mu.Lock()
			var expired []*tuicAssociation
			active := len(p.assocs) > 0
			for _, a := range p.assocs {
				if time.Since(a.last) > 30*time.Second {
					expired = append(expired, a)
				}
			}
			p.mu.Unlock()
			for _, a := range expired {
				a.Close()
			}
			if p.server == nil && (active || p.conn.ConnectionState().SupportsDatagrams.Remote) {
				p.conn.SendDatagram([]byte{5, 4})
			}
		}
	}
}
func (p *tuicPeer) readUni() {
	for {
		s, err := p.conn.AcceptUniStream(p.ctx)
		if err != nil {
			return
		}
		select {
		case p.commands <- struct{}{}:
		default:
			s.CancelRead(1)
			continue
		}
		if !p.spawn(func() {
			defer func() { <-p.commands }()
			defer s.CancelRead(0)
			s.SetReadDeadline(time.Now().Add(p.timeout))
			if p.handleUni(s) != nil {
				p.shutdown()
			}
		}) {
			s.CancelRead(1)
			<-p.commands
			return
		}
	}
}
func (p *tuicPeer) handleUni(s *quic.ReceiveStream) error {
	var h [2]byte
	if _, err := io.ReadFull(s, h[:]); err != nil {
		return err
	}
	if h[0] != 5 {
		return errTUICWire
	}
	if h[1] == 0 && p.server != nil {
		var auth [48]byte
		if _, err := io.ReadFull(s, auth[:]); err != nil {
			return err
		}
		var id [16]byte
		copy(id[:], auth[:16])
		password, ok := p.users[id]
		if !ok {
			return errors.New("TUIC_AUTHENTICATION_FAILED")
		}
		state := p.conn.ConnectionState().TLS
		token, err := state.ExportKeyingMaterial(string(id[:]), []byte(password), 32)
		if err != nil || subtle.ConstantTimeCompare(token, auth[16:]) != 1 {
			return errors.New("TUIC_AUTHENTICATION_FAILED")
		}
		duplicate := true
		p.authOnce.Do(func() { duplicate = false; close(p.auth) })
		if duplicate {
			return errTUICWire
		}
		return nil
	}
	if h[1] == 3 && p.server != nil {
		var id [2]byte
		if _, err := io.ReadFull(s, id[:]); err != nil {
			return err
		}
		if !p.waitAuth() {
			return net.ErrClosed
		}
		p.mu.Lock()
		a := p.assocs[binary.BigEndian.Uint16(id[:])]
		p.mu.Unlock()
		if a != nil {
			a.Close()
		}
		return nil
	}
	if h[1] != 2 {
		return errTUICWire
	}
	// Authenticate before accepting a payload allocation from an unknown peer.
	if !p.waitAuth() {
		return net.ErrClosed
	}
	f, err := readTUICFragment(s)
	if err != nil {
		return err
	}
	var extra [1]byte
	n, err := s.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return errTUICWire
	}
	return p.deliver(f, false)
}
func (p *tuicPeer) readDatagrams() {
	for {
		wire, err := p.conn.ReceiveDatagram(p.ctx)
		if err != nil {
			return
		}
		if len(wire) < 2 || wire[0] != 5 {
			continue
		}
		if wire[1] == 4 && len(wire) == 2 {
			continue
		}
		if wire[1] != 2 || !p.waitAuth() {
			continue
		}
		r := bytes.NewReader(wire[2:])
		f, err := readTUICFragment(r)
		if err == nil && r.Len() == 0 {
			p.deliver(f, true)
		}
	}
}
func (p *tuicPeer) readTCP() {
	for {
		s, err := p.conn.AcceptStream(p.ctx)
		if err != nil {
			return
		}
		if !p.server.acquire() {
			s.CancelRead(1)
			s.CancelWrite(1)
			continue
		}
		if !p.spawn(func() {
			defer p.server.release()
			c := &tuicConn{Stream: s, peer: p}
			defer c.Close()
			s.SetDeadline(time.Now().Add(p.timeout))
			var h [2]byte
			if _, err := io.ReadFull(s, h[:]); err != nil || h != [2]byte{5, 1} {
				return
			}
			a, err := readTUICAddress(s, false)
			if err != nil || !p.waitAuth() {
				return
			}
			host, port, err := decodeAddress(a)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
			defer cancel()
			ctx = p.server.flowContext(ctx, c.RemoteAddr(), host)
			remote, err := p.server.dialTCP(ctx, host, port)
			if err != nil {
				return
			}
			if !p.server.track(remote) {
				return
			}
			defer p.server.untrack(remote)
			defer remote.Close()
			finished := make(chan struct{})
			stopOwner := context.AfterFunc(p.ctx, func() { remote.Close(); close(finished) })
			defer func() {
				if !stopOwner() {
					<-finished
				}
			}()
			s.SetDeadline(time.Time{})
			p.server.accepted.Add(1)
			p.server.relay(c, remote)
		}) {
			p.server.release()
			s.CancelRead(1)
			s.CancelWrite(1)
			return
		}
	}
}

type tuicConn struct {
	*quic.Stream
	peer *tuicPeer
	once sync.Once
}

func (c *tuicConn) LocalAddr() net.Addr  { return c.peer.conn.LocalAddr() }
func (c *tuicConn) RemoteAddr() net.Addr { return c.peer.conn.RemoteAddr() }
func (c *tuicConn) CloseWrite() error    { return c.Stream.Close() }
func (c *tuicConn) Close() error {
	c.once.Do(func() { c.Stream.CancelRead(0); c.Stream.Close() })
	return nil
}

func newTUICClient(ctx context.Context, c Config) (io.Closer, error) {
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
		tlsConfig.NextProtos = []string{"h3"}
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
	return raceProtocolClients(ctx, ips, func(ctx context.Context, ip net.IPAddr) (io.Closer, error) {
		network, local := "udp4", "0.0.0.0:0"
		if ip.IP.To4() == nil {
			network, local = "udp6", "[::]:0"
		}
		socket, err := outboundPacket(ctx, network, local)
		if err != nil {
			return nil, err
		}
		configureDatagramBuffers(socket)
		t := &quic.Transport{Conn: socket}
		q, err := t.Dial(ctx, &net.UDPAddr{IP: ip.IP, Zone: ip.Zone, Port: c.Port}, tlsConfig, tuicQUICConfig(c.ConnectTimeout))
		if err != nil {
			t.Close()
			socket.Close()
			return nil, errors.Join(errors.New("TUIC_HANDSHAKE_FAILED"), err)
		}
		p := newTUICPeer(q, nil, nil, c.ConnectTimeout)
		p.transport, p.packet = t, socket
		state := q.ConnectionState().TLS
		token, err := state.ExportKeyingMaterial(string(c.UUID[:]), []byte(c.Password), 32)
		if err == nil {
			err = p.sendControl(ctx, append(append([]byte{5, 0}, c.UUID[:]...), token...))
		}
		if err != nil {
			p.Close()
			return nil, err
		}
		p.start()
		return p, nil
	})
}
func (p *tuicPeer) sendControl(ctx context.Context, b []byte) error {
	s, err := p.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok {
		s.SetWriteDeadline(d)
	}
	if err = writeAll(s, b); err != nil {
		s.CancelWrite(1)
		return err
	}
	return s.Close()
}
func getTUIC(ctx context.Context, c Config) (*tuicPeer, io.Closer, error) {
	b, _ := json.Marshal(c)
	hash := sha256.Sum256(b)
	key := "tuic:" + hex.EncodeToString(hash[:])
	if route, ok := ctx.Value(routeReuseKey{}).(routeReuse); ok {
		key += fmt.Sprintf(":%p:%s", route.table, route.tag)
	}
	if cache := engineClientCache(ctx); cache != nil {
		l, err := cache.get(ctx, key, func(ctx context.Context) (io.Closer, error) { return newTUICClient(ctx, c) })
		if err != nil {
			return nil, nil, err
		}
		return l.entry.client.(*tuicPeer), l, nil
	}
	v, err := newTUICClient(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	return v.(*tuicPeer), v, nil
}
func dialTUIC(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	a, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	a, err = tuicAddress(a)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	p, owner, err := getTUIC(ctx, c)
	if err != nil {
		return nil, err
	}
	s, err := p.conn.OpenStreamSync(ctx)
	if err == nil {
		s.SetWriteDeadline(time.Now().Add(c.ConnectTimeout))
		finished := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { s.CancelWrite(1); s.CancelRead(1); close(finished) })
		err = writeAll(s, append([]byte{5, 1}, a...))
		if !stop() {
			<-finished
		}
		if err == nil {
			err = ctx.Err()
		}
		s.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		if s != nil {
			s.CancelRead(1)
			s.CancelWrite(1)
		}
		owner.Close()
		return nil, err
	}
	return &hyLeaseConn{Conn: &tuicConn{Stream: s, peer: p}, owner: owner}, nil
}
