package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "0.5.7-go"

type Event struct {
	Protocol     string `json:"protocol,omitempty"`
	Transport    string `json:"transport,omitempty"`
	Active       uint64 `json:"active_connections"`
	Limit        int    `json:"connection_limit"`
	Uploaded     uint64 `json:"uploaded_bytes,omitempty"`
	Downloaded   uint64 `json:"downloaded_bytes,omitempty"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	NativeStatus uint32 `json:"native_status,omitempty"`
	Timestamp    int64  `json:"timestamp_unix_ms"`
	Phase        string `json:"phase,omitempty"`
	TLSVersion   string `json:"tls_version,omitempty"`
	ALPN         string `json:"alpn,omitempty"`
	Event        string `json:"event"`
	ConnectionID uint64 `json:"connection_id,omitempty"`
	ReasonCode   string `json:"reason_code,omitempty"`
	TunnelReady  bool   `json:"tunnel_ready,omitempty"`
}
type Stats struct{ Uploaded, Downloaded, Accepted, Rejected, Active uint64 }

// Engine owns its optional routing policy and a bounded set of connections. Close cancels and joins
// all workers before returning; host hook resources can then be released.
type Engine struct {
	config                                     Config
	ctx                                        context.Context
	cancel                                     context.CancelFunc
	mu                                         sync.Mutex
	closed                                     bool
	acceptingStopped                           bool
	closeDone                                  chan struct{}
	closers                                    map[io.Closer]bool
	workers                                    sync.WaitGroup
	slots                                      chan struct{}
	events                                     chan Event
	dns                                        *dnsRelay
	router                                     *Router
	clients                                    *clientCache
	sniffBudget                                time.Duration
	next, up, down, accepted, rejected, active atomic.Uint64
}

func NewEngine(parent context.Context, c Config, h Hooks) (*Engine, error) {
	base := c
	base.Routing = nil
	if e := base.Validate(); e != nil {
		return nil, e
	}
	var routing *routeTable
	if c.Routing != nil {
		var err error
		routing, err = compileRoutes(*c.Routing)
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(WithHooks(parent, h))
	e := &Engine{config: c, ctx: ctx, cancel: cancel, closeDone: make(chan struct{}), closers: map[io.Closer]bool{}, slots: make(chan struct{}, c.MaxConnections), events: make(chan Event, 256), sniffBudget: 150 * time.Millisecond}
	e.ctx = context.WithValue(e.ctx, runtimeKey{}, e)
	if routing != nil {
		e.router = &Router{listenPort: c.ListenPort, maxConnections: c.MaxConnections}
		e.router.table.Store(routing)
	}
	if c.NativeDNS {
		e.dns = newDNSRelay(e)
		e.track(e.dns)
		if c.Routing != nil && c.Routing.DNS != nil {
			if err := e.ConfigureDNS(*c.Routing.DNS); err != nil {
				e.Close()
				return nil, err
			}
		}
	}
	return e, nil
}
func (e *Engine) Events() <-chan Event { return e.events }
func (e *Engine) emit(v Event) {
	v.Timestamp = time.Now().UnixMilli()
	v.Protocol, v.Transport = e.config.Protocol, e.config.Transport
	if e.router != nil {
		v.Protocol, v.Transport = "routing", "policy"
	}
	v.Active, v.Limit = e.active.Load(), e.config.MaxConnections
	select {
	case e.events <- v:
	default:
	}
}
func (e *Engine) Stats() Stats {
	return Stats{e.up.Load(), e.down.Load(), e.accepted.Load(), e.rejected.Load(), e.active.Load()}
}
func (e *Engine) track(c io.Closer) bool {
	e.mu.Lock()
	_, listener := c.(net.Listener)
	_, packetListener := c.(net.PacketConn)
	listener = listener || packetListener
	if e.closed || e.ctx.Err() != nil || (listener && e.acceptingStopped) {
		e.mu.Unlock()
		c.Close()
		return false
	}
	e.closers[c] = true
	e.mu.Unlock()
	return true
}
func (e *Engine) untrack(c io.Closer) { e.mu.Lock(); delete(e.closers, c); e.mu.Unlock() }
func (e *Engine) spawn(fn func()) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return false
	}
	e.workers.Add(1)
	go func() { defer e.workers.Done(); fn() }()
	return true
}
func (e *Engine) acquire() bool {
	select {
	case e.slots <- struct{}{}:
		e.active.Add(1)
		return true
	default:
		e.rejected.Add(1)
		e.emit(Event{Event: "failure", ConnectionID: e.next.Add(1), ReasonCode: "CONNECTION_LIMIT", Phase: "ADMISSION_FAILED"})
		return false
	}
}
func (e *Engine) release() { <-e.slots; e.active.Add(^uint64(0)) }

// StopAccepting synchronously closes listeners without waiting for host hooks
// to return. A reported zero listen port must mean the socket is already closed.
func (e *Engine) StopAccepting() {
	e.mu.Lock()
	e.acceptingStopped = true
	var listeners []io.Closer
	for c := range e.closers {
		if l, ok := c.(net.Listener); ok {
			listeners = append(listeners, l)
		} else if p, ok := c.(net.PacketConn); ok {
			listeners = append(listeners, p)
		}
	}
	e.mu.Unlock()
	for _, l := range listeners {
		l.Close()
	}
}
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		<-e.closeDone
		return nil
	}
	e.closed = true
	e.cancel()
	list := make([]io.Closer, 0, len(e.closers))
	for c := range e.closers {
		list = append(list, c)
	}
	e.mu.Unlock()
	// Unlisten first. Slow TLS close-notify or a blocked host hook must not
	// delay revoking listeners or closing other independently owned sockets.
	for _, c := range list {
		if l, ok := c.(net.Listener); ok {
			l.Close()
		} else if p, ok := c.(net.PacketConn); ok {
			p.Close()
		}
	}
	var closed sync.WaitGroup
	for _, c := range list {
		if _, ok := c.(net.Listener); ok {
			continue
		}
		if _, ok := c.(net.PacketConn); ok {
			continue
		}
		closed.Add(1)
		go func(c io.Closer) { defer closed.Done(); c.Close() }(c)
	}
	closed.Wait()
	e.workers.Wait()
	close(e.closeDone)
	return nil
}
func (e *Engine) StartSOCKS() (net.Addr, error) {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(e.config.ListenPort)))
	if err != nil {
		return nil, err
	}
	if !e.track(l) {
		return nil, net.ErrClosed
	}
	if !e.spawn(func() {
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if !e.acquire() {
				c.Close()
				continue
			}
			if !e.track(c) {
				e.release()
				return
			}
			if !e.spawn(func() { defer e.release(); defer e.untrack(c); defer c.Close(); e.handleSOCKS(c) }) {
				e.release()
				c.Close()
				return
			}
		}
	}) {
		l.Close()
		return nil, net.ErrClosed
	}
	if e.config.ReadyFile != "" {
		b, _ := json.Marshal(map[string]any{"port": l.Addr().(*net.TCPAddr).Port, "listen_port": l.Addr().(*net.TCPAddr).Port, "version": Version, "pid": os.Getpid()})
		if err := writeReady(e.config.ReadyFile, b); err != nil {
			e.Close()
			return nil, err
		}
	}
	e.emit(Event{Event: "ready"})
	return l.Addr(), nil
}
func socksReply(c net.Conn, code byte, a net.Addr) error {
	address := []byte{1, 127, 0, 0, 1, 0, 0}
	if u, ok := a.(*net.UDPAddr); ok {
		address, _ = Address(u.IP.String(), u.Port)
	}
	return writeAll(c, join([]byte{5, code, 0}, address))
}
func (e *Engine) handleSOCKS(c net.Conn) {
	id := e.next.Add(1)
	e.accepted.Add(1)
	c.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] == 0 {
		return
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	allowed := false
	for _, m := range methods {
		allowed = allowed || m == 0
	}
	if !allowed {
		writeAll(c, []byte{5, 255})
		return
	}
	if writeAll(c, []byte{5, 0}) != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	if request[1] != 1 && request[1] != 3 {
		socksReply(c, 7, nil)
		return
	}
	address, err := readAddress(io.MultiReader(bytes.NewReader(request[3:]), c))
	if err != nil {
		socksReply(c, 8, nil)
		return
	}
	if request[1] == 3 {
		c.SetDeadline(time.Time{})
		err = e.serveUDP(c, address)
		if err != nil {
			e.emit(Event{Event: "failure", ConnectionID: id, ReasonCode: reasonCode(err), Phase: "PROTOCOL_FAILED"})
		}
		return
	}
	if request[1] != 1 {
		socksReply(c, 7, nil)
		return
	}
	host, port, err := decodeAddress(address)
	if err != nil {
		socksReply(c, 8, nil)
		return
	}
	client := c
	flowCtx := e.flowContext(e.ctx, c.RemoteAddr(), host)
	earlyReply := e.config.Sniffing && sniffEligible(host, port)
	if earlyReply {
		// A SOCKS client sends its HTTP/TLS prefix only after acceptance.
		// This is admission, not a claim that the upstream is negotiated.
		if socksReply(c, 0, nil) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		client, host = e.destination(c, host, port)
	}
	upstream, err := e.dialTCP(flowCtx, host, port)
	if err != nil {
		c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if !earlyReply {
			socksReply(c, 1, nil)
		}
		e.emit(dialFailure(id, err))
		return
	}
	if !e.track(upstream) {
		return
	}
	defer e.untrack(upstream)
	defer upstream.Close()
	if !earlyReply && socksReply(c, 0, nil) != nil {
		return
	}
	version, alpn := connectionMeta(upstream)
	e.emit(Event{Event: "negotiated", ConnectionID: id, TunnelReady: true, TLSVersion: version, ALPN: alpn})
	c.SetDeadline(time.Time{})
	err, transferred := e.relayWithMetrics(client, upstream)
	if err != nil && !errors.Is(err, errIdleTimeout) && reasonCode(err) != "CANCELLED" {
		e.emit(Event{Event: "failure", ConnectionID: id, ReasonCode: reasonCode(err), TunnelReady: true, Phase: "PROTOCOL_FAILED"})
	}
	closed := Event{Event: "closed", ConnectionID: id, TunnelReady: true, Uploaded: transferred.uploaded, Downloaded: transferred.downloaded, DurationMS: transferred.duration.Milliseconds()}
	if errors.Is(err, errIdleTimeout) {
		closed.ReasonCode = "IDLE_TIMEOUT"
	}
	e.emit(closed)
}
func reasonCode(err error) string {
	for _, code := range []string{"SOCKET_PROTECTION_FAILED", "BOOTSTRAP_DNS_TIMEOUT", "BOOTSTRAP_DNS_FAILED", "DNS_CALLBACK_BUSY"} {
		if strings.Contains(err.Error(), code) {
			return code
		}
	}
	var pe providerError
	if errors.As(err, &pe) {
		if code, ok := componentReasons[int(pe)]; ok {
			return code
		}
		return "COMPONENT_" + itoa(int(pe))
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return "CANCELLED"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "TIMEOUT"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "TIMEOUT"
	}
	s := err.Error()
	if len(s) <= 80 && s != "" && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" {
		return s
	}
	return "CONNECTION_FAILED"
}
func (e *Engine) relay(client, server net.Conn) error {
	err, _ := e.relayWithMetrics(client, server)
	return err
}

var errIdleTimeout = errors.New("IDLE_TIMEOUT")

type relayMetrics struct {
	uploaded, downloaded uint64
	duration             time.Duration
}

func (e *Engine) relayWithMetrics(client, server net.Conn) (error, relayMetrics) {
	start := time.Now()
	var uploaded, downloaded, lastActivity atomic.Uint64
	var expired atomic.Bool
	finished := make(chan struct{})
	watchDone := make(chan struct{})
	// One timer per flow, rather than resetting four OS deadlines on every
	// chunk. Activity in either direction keeps a bidirectional stream alive.
	client.SetDeadline(time.Time{})
	server.SetDeadline(time.Time{})
	go func() {
		defer close(watchDone)
		timer := time.NewTimer(e.config.IdleTimeout)
		defer timer.Stop()
		for {
			select {
			case <-finished:
				return
			case <-timer.C:
				idle := time.Since(start) - time.Duration(lastActivity.Load())
				if idle >= e.config.IdleTimeout {
					expired.Store(true)
					client.Close()
					server.Close()
					return
				}
				timer.Reset(e.config.IdleTimeout - idle)
			}
		}
	}()
	done := make(chan error, 1)
	copyDirection := func(dst, src net.Conn, counter, flow *atomic.Uint64) error {
		b := make([]byte, 32768)
		for {
			n, err := src.Read(b)
			if n > 0 {
				lastActivity.Store(uint64(time.Since(start)))
				if ew := writeAll(dst, b[:n]); ew != nil {
					return ew
				}
				counter.Add(uint64(n))
				flow.Add(uint64(n))
				lastActivity.Store(uint64(time.Since(start)))
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						return cw.CloseWrite()
					}
					return nil
				}
				return err
			}
		}
	}
	go func() {
		err := copyDirection(server, client, &e.up, &uploaded)
		if err != nil {
			server.Close()
			client.Close()
		}
		done <- err
	}()
	err := copyDirection(client, server, &e.down, &downloaded)
	if err != nil {
		server.Close()
	}
	client.Close()
	server.Close()
	uploadErr := <-done
	close(finished)
	<-watchDone
	metrics := relayMetrics{uploaded.Load(), downloaded.Load(), time.Since(start)}
	if expired.Load() {
		return errIdleTimeout, metrics
	}
	if err != nil {
		return err, metrics
	}
	return uploadErr, metrics
}

func (e *Engine) serveUDP(control net.Conn, requested []byte) error {
	ip := control.RemoteAddr().(*net.TCPAddr).IP
	requestedPort := getWord(requested, len(requested)-2)
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	if !e.track(u) {
		return net.ErrClosed
	}
	defer e.untrack(u)
	defer u.Close()
	if err = socksReply(control, 0, u.LocalAddr()); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	var mu sync.Mutex
	streams := map[string]PacketStream{}
	var readers sync.WaitGroup
	closed := make(chan struct{})
	go func() { io.Copy(io.Discard, control); cancel(); u.Close(); close(closed) }()
	defer func() {
		cancel()
		control.Close()
		mu.Lock()
		for _, s := range streams {
			s.Close()
		}
		mu.Unlock()
		readers.Wait()
		<-closed
	}()
	var peer *net.UDPAddr
	b := make([]byte, 65536)
	for {
		n, from, err := u.ReadFromUDP(b)
		if err != nil {
			return nil
		}
		if !from.IP.Equal(ip) || requestedPort != 0 && requestedPort != from.Port {
			continue
		}
		if peer == nil {
			peer = from
		} else if from.Port != peer.Port {
			continue
		}
		if n < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
			continue
		}
		size, err := addressSize(b[3:n])
		if err != nil || size == 0 {
			continue
		}
		a := append([]byte{}, b[3:3+size]...)
		host, port, err := decodeAddress(a)
		if err != nil {
			continue
		}
		key := string(a)
		mu.Lock()
		s := streams[key]
		if s == nil && len(streams) >= e.config.MaxConnections {
			mu.Unlock()
			continue
		}
		mu.Unlock()
		if s == nil {
			s, err = e.dialPacket(e.flowContext(ctx, control.RemoteAddr(), host), host, port)
			if err != nil {
				e.emit(dialFailure(e.next.Add(1), err))
				continue
			}
			mu.Lock()
			streams[key] = s
			mu.Unlock()
			readers.Add(1)
			destination := *peer
			go func(key string, s PacketStream) {
				defer readers.Done()
				defer s.Close()
				defer func() {
					mu.Lock()
					if streams[key] == s {
						delete(streams, key)
					}
					mu.Unlock()
				}()
				for {
					wait := e.config.IdleTimeout
					if e.config.UDPTimeout > 0 {
						wait = e.config.UDPTimeout
					}
					s.SetDeadline(time.Now().Add(wait))
					packet, err := s.ReadPacket()
					if err != nil {
						if reasonCode(err) != "CANCELLED" {
							reason := reasonCode(err)
							if reason == "TIMEOUT" && e.config.UDPTimeout > 0 {
								reason = "UDP_NO_RESPONSE"
							}
							e.emit(Event{Event: "udp_diagnostic", ReasonCode: reason})
						}
						if isPacketRejected(err) {
							continue
						}
						return
					}
					if len(packet.Address)+len(packet.Payload) > 65504 {
						continue
					}
					wire := join([]byte{0, 0, 0}, packet.Address, packet.Payload)
					if _, err = u.WriteToUDP(wire, &destination); err != nil {
						return
					}
					e.down.Add(uint64(len(packet.Payload)))
				}
			}(key, s)
		}
		s.SetDeadline(time.Now().Add(e.config.IdleTimeout))
		if err = s.WritePacket(b[3+size : n]); err != nil {
			s.Close()
			continue
		}
		e.up.Add(uint64(n - 3 - size))
	}
}
