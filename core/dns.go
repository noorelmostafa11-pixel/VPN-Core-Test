package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// One pooled HTTPS transport per engine; bounded concurrency and cache. It
// always dials through the configured node, never through the physical network.
type dnsRelay struct {
	engine     *Engine
	http       *http.Client
	transport  *http.Transport
	servers    []string
	slots      chan struct{}
	mu         sync.Mutex
	cache      map[string]dnsEntry
	names      map[string]dnsName
	policy     atomic.Pointer[dnsPolicy]
	policyID   atomic.Uint64
	fakeNames  map[string]string
	fakeIPs    map[string]string
	fakeNext   uint32
	fakeActive atomic.Bool
}
type dnsEntry struct {
	wire   []byte
	until  time.Time
	stored time.Time
}
type dnsName struct {
	name      string
	until     time.Time
	ambiguous bool
}
type dnsTrackedConn struct {
	net.Conn
	e    *Engine
	once sync.Once
}

func (c *dnsTrackedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.e.untrack(c) })
	return err
}

func newDNSRelay(e *Engine) *dnsRelay {
	d := &dnsRelay{engine: e, servers: []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"}, slots: make(chan struct{}, 16), cache: map[string]dnsEntry{}, names: map[string]dnsName{}}
	d.transport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, MaxConnsPerHost: 8, MaxIdleConns: 16, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 4 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	d.transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		p, err := number(port, 1, 65535)
		if err != nil {
			return nil, err
		}
		c, err := e.dialTCP(ctx, host, p)
		if err != nil {
			return nil, err
		}
		tracked := &dnsTrackedConn{Conn: c, e: e}
		if !e.track(tracked) {
			return nil, net.ErrClosed
		}
		return tracked, nil
	}
	d.http = &http.Client{Transport: d.transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return d
}
func (d *dnsRelay) Close() error { d.transport.CloseIdleConnections(); return nil }
func parseDNSQuestion(query []byte) (dnsmessage.Header, dnsmessage.Question, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response || h.OpCode != 0 {
		return h, dnsmessage.Question{}, errors.New("DNS_QUERY_INVALID")
	}
	q, err := p.Question()
	if err != nil {
		return h, q, err
	}
	_, err = p.Question()
	if err != dnsmessage.ErrSectionDone {
		return h, q, errors.New("DNS_QUESTION_COUNT")
	}
	return h, q, nil
}
func dnsEmpty(h dnsmessage.Header, q dnsmessage.Question, code dnsmessage.RCode) []byte {
	h.Response = true
	h.RecursionAvailable = true
	h.RCode = code
	h.AuthenticData = false
	h.Truncated = false
	b := dnsmessage.NewBuilder(nil, h)
	b.StartQuestions()
	b.Question(q)
	wire, _ := b.Finish()
	return wire
}
func (d *dnsRelay) exchange(ctx context.Context, query []byte) ([]byte, error) {
	var last error
	servers := d.servers
	if policy, ok := ctx.Value(dnsPolicyKey{}).(*dnsPolicy); ok && policy != nil {
		_, q, err := parseDNSQuestion(query)
		if err != nil {
			return nil, err
		}
		servers = policy.serversFor(strings.TrimSuffix(q.Name.String(), "."))
	}
	for _, server := range servers {
		request, err := http.NewRequestWithContext(ctx, "POST", server, bytes.NewReader(query))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, err := d.http.Do(request)
		if err != nil {
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		wire, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || len(wire) < 12 || len(wire) > 65535 {
			last = errors.New("DNS_UPSTREAM_INVALID")
			continue
		}
		var p dnsmessage.Parser
		h, err := p.Start(wire)
		if err != nil || !h.Response || h.RCode == dnsmessage.RCodeServerFailure || h.RCode == dnsmessage.RCodeRefused {
			last = errors.New("DNS_UPSTREAM_FAILED")
			continue
		}
		_, original, err := parseDNSQuestion(query)
		if err != nil {
			return nil, err
		}
		answered, err := p.Question()
		if err != nil || answered != original {
			last = errors.New("DNS_ANSWER_MISMATCH")
			continue
		}
		wire[0], wire[1] = query[0], query[1]
		return wire, nil
	}
	return nil, last
}
func (d *dnsRelay) answer(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > 4096 {
		return nil, errors.New("DNS_QUERY_SIZE")
	}
	h, q, err := parseDNSQuestion(query)
	if err != nil {
		return nil, err
	}
	if policy := d.policy.Load(); policy != nil {
		ctx = context.WithValue(ctx, dnsPolicyKey{}, policy)
		name := strings.TrimSuffix(q.Name.String(), ".")
		if action := policy.actionFor(name); action == "block" {
			return dnsEmpty(h, q, dnsmessage.RCodeNameError), nil
		} else if action == "fakeip" && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA) {
			return d.fakeAnswer(h, q)
		}
	}
	select {
	case d.slots <- struct{}{}:
		defer func() { <-d.slots }()
	default:
		return dnsEmpty(h, q, dnsmessage.RCodeServerFailure), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	// Binding records can advertise QUIC/ECH/IP hints outside the requested A/
	// AAAA policy. Like v2rayN's default, return a valid empty answer in TCP mode.
	if d.engine.config.PreferTCP && (q.Type == 64 || q.Type == 65) {
		return dnsEmpty(h, q, 0), nil
	}
	if d.engine.config.PreferIPv4 && q.Type == dnsmessage.TypeAAAA {
		check := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, RecursionDesired: true})
		check.StartQuestions()
		a := q
		a.Type = dnsmessage.TypeA
		check.Question(a)
		wire, _ := check.Finish()
		v4, err := d.cached(ctx, wire)
		if err == nil {
			var p dnsmessage.Parser
			_, err = p.Start(v4)
			if err == nil {
				p.SkipAllQuestions()
				answers, _ := p.AllAnswers()
				for _, r := range answers {
					if _, ok := r.Body.(*dnsmessage.AResource); ok {
						return dnsEmpty(h, q, 0), nil
					}
				}
			}
		}
	}
	wire, err := d.cached(ctx, query)
	if err != nil {
		d.engine.emit(Event{Event: "dns_failure", ReasonCode: reasonCode(err), Phase: "DNS_FAILED"})
		return dnsEmpty(h, q, dnsmessage.RCodeServerFailure), nil
	}
	return wire, nil
}
func (d *dnsRelay) cached(ctx context.Context, query []byte) ([]byte, error) {
	key := string(query[2:])
	if p, ok := ctx.Value(dnsPolicyKey{}).(*dnsPolicy); ok {
		key = itoa(int(p.id)) + ":" + key
	}
	now := time.Now()
	d.mu.Lock()
	entry, ok := d.cache[key]
	d.mu.Unlock()
	if ok && now.Before(entry.until) {
		wire := append([]byte(nil), entry.wire...)
		wire[0], wire[1] = query[0], query[1]
		age := uint32(now.Sub(entry.stored) / time.Second)
		return ageDNS(wire, age), nil
	}
	wire, err := d.exchange(ctx, query)
	if err != nil {
		return nil, err
	}
	var p dnsmessage.Parser
	_, err = p.Start(wire)
	if err != nil {
		return nil, err
	}
	p.SkipAllQuestions()
	answers, err := p.AllAnswers()
	if err != nil {
		return nil, err
	}
	_, q, _ := parseDNSQuestion(query)
	name := strings.TrimSuffix(q.Name.String(), ".")
	ttl := uint32(300)
	for _, r := range answers {
		if r.Header.TTL < ttl {
			ttl = r.Header.TTL
		}
		ip := ""
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			ip = net.IP(b.A[:]).String()
		case *dnsmessage.AAAAResource:
			ip = net.IP(b.AAAA[:]).String()
		}
		if ip != "" && validSniffName(name) {
			d.mu.Lock()
			previous := d.names[ip]
			ambiguous := time.Now().Before(previous.until) && (previous.ambiguous || previous.name != name)
			if len(d.names) >= 1024 {
				for k, v := range d.names {
					if now.After(v.until) {
						delete(d.names, k)
					}
				}
				if len(d.names) >= 1024 {
					for k := range d.names {
						delete(d.names, k)
						break
					}
				}
			}
			d.names[ip] = dnsName{name, now.Add(time.Duration(min(r.Header.TTL, 300)) * time.Second), ambiguous}
			d.mu.Unlock()
		}
	}
	if len(answers) > 0 && ttl > 0 && len(wire) <= 4096 {
		d.mu.Lock()
		if len(d.cache) >= 256 {
			for k, v := range d.cache {
				if now.After(v.until) {
					delete(d.cache, k)
				}
			}
			if len(d.cache) >= 256 {
				for k := range d.cache {
					delete(d.cache, k)
					break
				}
			}
		}
		d.cache[key] = dnsEntry{append([]byte(nil), wire...), now.Add(time.Duration(ttl) * time.Second), now}
		d.mu.Unlock()
	}
	return wire, nil
}

// Rebuild cached records so their TTL reflects elapsed time, retaining DNSSEC
// and EDNS resources rather than editing compression offsets in place.
func ageDNS(wire []byte, age uint32) []byte {
	var msg dnsmessage.Message
	if msg.Unpack(wire) != nil {
		return wire
	}
	for _, section := range [][]dnsmessage.Resource{msg.Answers, msg.Authorities, msg.Additionals} {
		for i := range section {
			if section[i].Header.Type == dnsmessage.TypeOPT {
				continue
			}
			if section[i].Header.TTL > age {
				section[i].Header.TTL -= age
			} else {
				section[i].Header.TTL = 0
			}
		}
	}
	out, err := msg.Pack()
	if err != nil {
		return wire
	}
	return out
}
func (d *dnsRelay) name(ip string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.names[ip]
	if !v.ambiguous && time.Now().Before(v.until) {
		return v.name
	}
	return ""
}

// StartDNS exposes Windows-compatible local UDP/TCP DNS. Native TUN also
// intercepts DNS packets directly; both paths use this same HTTPS relay.
func (e *Engine) StartDNS(address string) (net.Addr, error) {
	return e.startDNS(address, net.Listen, net.ListenPacket)
}

func (e *Engine) startDNS(address string, listenTCP func(string, string) (net.Listener, error), listenUDP func(string, string) (net.PacketConn, error)) (net.Addr, error) {
	if e.dns == nil {
		return nil, errors.New("NATIVE_DNS_DISABLED")
	}
	tcp, udp, err := e.listenTCPUDP(address, listenTCP, listenUDP)
	if err != nil {
		return nil, err
	}
	rollback := func() {
		tcp.Close()
		udp.Close()
		e.untrack(tcp)
		e.untrack(udp)
	}
	if !e.spawn(func() {
		defer e.untrack(tcp)
		defer tcp.Close()
		for {
			c, err := tcp.Accept()
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
			if !e.spawn(func() { defer e.release(); defer e.untrack(c); defer c.Close(); e.dns.tcp(e.ctx, c) }) {
				c.Close()
				e.untrack(c)
				e.release()
				return
			}
		}
	}) {
		rollback()
		return nil, net.ErrClosed
	}
	if !e.spawn(func() {
		defer e.untrack(udp)
		defer udp.Close()
		b := make([]byte, 4097)
		for {
			n, peer, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if n > 4096 || !e.acquire() {
				continue
			}
			q := append([]byte(nil), b[:n]...)
			if !e.spawn(func() {
				defer e.release()
				answer, err := e.dns.answer(e.ctx, q)
				if err == nil {
					udp.WriteTo(dnsDatagram(q, answer), peer)
				}
			}) {
				e.release()
				return
			}
		}
	}) {
		rollback()
		return nil, net.ErrClosed
	}
	return tcp.Addr(), nil
}

func dnsDatagram(query, answer []byte) []byte {
	size := 512
	var p dnsmessage.Parser
	if _, err := p.Start(query); err == nil {
		p.SkipAllQuestions()
		p.SkipAllAnswers()
		p.SkipAllAuthorities()
		if extra, err := p.AllAdditionals(); err == nil {
			for _, r := range extra {
				if r.Header.Type == dnsmessage.TypeOPT {
					size = max(512, min(int(r.Header.Class), 4096))
				}
			}
		}
	}
	if len(answer) <= size {
		return answer
	}
	h, q, err := parseDNSQuestion(query)
	if err != nil {
		return answer
	}
	var response dnsmessage.Parser
	rh, err := response.Start(answer)
	if err != nil {
		return answer
	}
	truncated := dnsEmpty(h, q, rh.RCode)
	truncated[2] |= 2
	return truncated
}
func (d *dnsRelay) tcp(ctx context.Context, c net.Conn) {
	for {
		c.SetReadDeadline(time.Now().Add(d.engine.config.IdleTimeout))
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 || n > 4096 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		answer, err := d.answer(ctx, query)
		if err != nil {
			return
		}
		c.SetWriteDeadline(time.Now().Add(4 * time.Second))
		binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
		if writeAll(c, size[:]) != nil || writeAll(c, answer) != nil {
			return
		}
	}
}
