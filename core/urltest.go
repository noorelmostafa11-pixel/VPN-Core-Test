package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type URLTestConfig struct {
	URLs            []string `json:"urls"`
	ExpectedBody    string   `json:"expected_body,omitempty"`
	CAFile          string   `json:"ca_file,omitempty"`
	IntervalSeconds int      `json:"interval_seconds,omitempty"`
	TimeoutMS       int      `json:"timeout_ms,omitempty"`
}
type compiledURLTest struct {
	config URLTestConfig
	urls   []*url.URL
	roots  *x509.CertPool
}
type URLHealth struct {
	Group     string `json:"group"`
	Outbound  string `json:"outbound"`
	Healthy   bool   `json:"healthy"`
	LatencyMS int64  `json:"latency_ms"`
	CheckedAt int64  `json:"checked_at"`
	Reason    string `json:"reason,omitempty"`
}

func compileURLTest(c URLTestConfig) (*compiledURLTest, error) {
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 30
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = 3000
	}
	if len(c.URLs) < 1 || len(c.URLs) > 4 || len(c.ExpectedBody) > 1024 || c.IntervalSeconds < 5 || c.IntervalSeconds > 3600 || c.TimeoutMS < 100 || c.TimeoutMS > 30000 {
		return nil, errors.New("URL_TEST_CONFIGURATION")
	}
	p := &compiledURLTest{config: c}
	p.config.URLs = append([]string(nil), c.URLs...)
	for _, text := range c.URLs {
		u, err := url.Parse(text)
		if len(text) > 4096 || err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || !hostValid(u.Hostname()) {
			return nil, errors.New("URL_TEST_HTTPS_REQUIRED")
		}
		if u.Port() != "" {
			if _, err = number(u.Port(), 1, 65535); err != nil {
				return nil, err
			}
		}
		p.urls = append(p.urls, u)
	}
	if c.CAFile != "" {
		data, err := boundedPrivateFile(c.CAFile, 1048576)
		if err != nil {
			return nil, err
		}
		p.roots = x509.NewCertPool()
		if !p.roots.AppendCertsFromPEM(data) {
			return nil, errors.New("URL_TEST_CA_INVALID")
		}
	}
	return p, nil
}
func (g *compiledGroup) healthMembers() []string {
	g.healthMu.RLock()
	defer g.healthMu.RUnlock()
	type candidate struct {
		tag     string
		latency int64
	}
	var candidates []candidate
	for _, tag := range g.members {
		if h, ok := g.health[tag]; ok && h.Healthy && time.Since(time.UnixMilli(h.CheckedAt)) < time.Duration(g.test.config.IntervalSeconds*3)*time.Second {
			candidates = append(candidates, candidate{tag, h.LatencyMS})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].latency < candidates[j].latency })
	out := make([]string, len(candidates))
	for i, v := range candidates {
		out[i] = v.tag
	}
	return out
}
func (g *compiledGroup) recordHealth(v URLHealth) {
	g.healthMu.Lock()
	if g.health == nil {
		g.health = map[string]URLHealth{}
	}
	g.health[v.Outbound] = v
	g.healthMu.Unlock()
}
func (e *Engine) URLHealth() []URLHealth {
	if e.router == nil {
		return nil
	}
	t := e.router.table.Load()
	var list []URLHealth
	for tag, g := range t.groups {
		if g.test == nil {
			continue
		}
		g.healthMu.RLock()
		for _, member := range g.members {
			v, ok := g.health[member]
			if !ok {
				v = URLHealth{Group: tag, Outbound: member, Reason: "PENDING"}
			}
			list = append(list, v)
		}
		g.healthMu.RUnlock()
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Group == list[j].Group {
			return list[i].Outbound < list[j].Outbound
		}
		return list[i].Group < list[j].Group
	})
	return list
}

type urlTestController struct {
	e       *Engine
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	request chan struct{}
	once    sync.Once
}

func (h *urlTestController) Close() error { h.once.Do(func() { h.cancel(); <-h.done }); return nil }
func (e *Engine) syncURLTesting() {
	if e.router == nil {
		return
	}
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	t := e.router.table.Load()
	wanted := false
	for _, g := range t.groups {
		wanted = wanted || g.test != nil
	}
	if e.health != nil {
		e.health.Close()
		e.untrack(e.health)
		e.health = nil
	}
	if !wanted {
		return
	}
	ctx, cancel := context.WithCancel(e.ctx)
	h := &urlTestController{e: e, ctx: ctx, cancel: cancel, done: make(chan struct{}), request: make(chan struct{}, 1)}
	go h.run()
	if !e.track(h) {
		return
	}
	e.health = h
}

// RequestURLTest queues at most one extra bounded round, without spawning
// caller-owned probe workers or exposing endpoint URLs/credentials.
func (e *Engine) RequestURLTest() bool {
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	if e.health == nil || e.ctx.Err() != nil {
		return false
	}
	select {
	case e.health.request <- struct{}{}:
	default:
	}
	return true
}

type urlTestJob struct {
	table         *routeTable
	group         *compiledGroup
	groupTag, tag string
}

func (h *urlTestController) run() {
	defer close(h.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := map[*compiledGroup]time.Time{}
	cursor := map[*compiledGroup]int{}
	groupCursor := 0
	var lastRound time.Time
	for {
		if !lastRound.IsZero() && time.Since(lastRound) < 5*time.Second {
			select {
			case <-h.ctx.Done():
				return
			case <-ticker.C:
			case <-h.request:
				last = map[*compiledGroup]time.Time{}
			}
			continue
		}
		t := h.e.router.table.Load()
		jobs := make([]urlTestJob, 0, 16)
		groups := make([]string, 0, len(t.groups))
		for tag, g := range t.groups {
			if g.test != nil {
				groups = append(groups, tag)
			}
		}
		sort.Strings(groups)
		if len(groups) > 0 {
			start := groupCursor % len(groups)
			groups = append(append([]string(nil), groups[start:]...), groups[:start]...)
		}
		for _, tag := range groups {
			g := t.groups[tag]
			if !last[g].IsZero() && time.Since(last[g]) < time.Duration(g.test.config.IntervalSeconds)*time.Second {
				continue
			}
			if len(jobs) >= 16 {
				break
			}
			last[g] = time.Now()
			groupCursor++
			seen := map[string]bool{}
			// Refresh a proven working path before gradually scanning new nodes.
			if healthy := g.healthMembers(); len(healthy) > 0 {
				jobs = append(jobs, urlTestJob{t, g, tag, healthy[0]})
				seen[healthy[0]] = true
			}
			for i := 0; i < len(g.members) && len(jobs) < 16; i++ {
				index := cursor[g] % len(g.members)
				cursor[g]++
				member := g.members[index]
				if !seen[member] {
					jobs = append(jobs, urlTestJob{t, g, tag, member})
					seen[member] = true
				}
			}
		}
		// Old generations are not retained indefinitely by the scheduler.
		for g := range last {
			present := false
			for _, current := range t.groups {
				present = present || current == g
			}
			if !present {
				delete(last, g)
				delete(cursor, g)
			}
		}
		if len(jobs) > 0 {
			h.round(jobs)
			lastRound = time.Now()
		}
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
		case <-h.request:
			last = map[*compiledGroup]time.Time{}
		}
	}
}
func (h *urlTestController) round(jobs []urlTestJob) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	queue := make(chan urlTestJob, len(jobs))
	for _, job := range jobs {
		queue <- job
	}
	close(queue)
	var workers sync.WaitGroup
	for i := 0; i < 4 && i < len(jobs); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range queue {
				if ctx.Err() != nil {
					return
				}
				if h.e.router.table.Load() != job.table {
					continue
				}
				v, local := h.probe(ctx, job)
				if local {
					cancel()
					return
				}
				if h.e.router.table.Load() == job.table && v.CheckedAt != 0 {
					job.group.recordHealth(v)
				}
			}
		}()
	}
	workers.Wait()
}
func (h *urlTestController) probe(ctx context.Context, job urlTestJob) (URLHealth, bool) {
	v := URLHealth{Group: job.groupTag, Outbound: job.tag}
	if !h.e.acquire() {
		return v, true
	}
	defer h.e.release()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(job.group.test.config.TimeoutMS)*time.Millisecond)
	defer cancel()
	start := time.Now()
	cfg := job.group.test
	for i, u := range cfg.urls {
		attempt := ctx
		stop := func() {}
		if deadline, ok := ctx.Deadline(); ok && i < len(cfg.urls)-1 {
			attempt, stop = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(cfg.urls)-i))
		}
		err := h.fetch(attempt, job, u)
		stop()
		if err == nil {
			v.Healthy = true
			v.LatencyMS = time.Since(start).Milliseconds()
			v.CheckedAt = time.Now().UnixMilli()
			return v, false
		}
		if h.ctx.Err() != nil || ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
			return v, true
		}
		if strings.Contains(err.Error(), "SOCKET_PROTECTION_FAILED") || strings.Contains(err.Error(), "PROTOCOL_CLIENT_LIMIT") {
			return v, true
		}
	}
	v.CheckedAt = time.Now().UnixMilli()
	v.Reason = "HTTPS_BODY_FAILED"
	return v, false
}
func (h *urlTestController) fetch(ctx context.Context, job urlTestJob, u *url.URL) error {
	probeCtx := ctx
	port := 443
	if u.Port() != "" {
		port, _ = number(u.Port(), 1, 65535)
	}
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, ResponseHeaderTimeout: time.Duration(job.group.test.config.TimeoutMS) * time.Millisecond, MaxResponseHeaderBytes: 32768}
	defer transport.CloseIdleConnections()
	transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		raw, err := job.table.tcp(ctx, job.tag, u.Hostname(), port, 0)
		if err != nil {
			return nil, err
		}
		secure := tls.Client(raw, &tls.Config{ServerName: u.Hostname(), RootCAs: job.group.test.roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		if !h.e.track(secure) {
			return nil, net.ErrClosed
		}
		closed := make(chan struct{})
		stop := context.AfterFunc(probeCtx, func() { secure.Close(); close(closed) })
		if err = secure.HandshakeContext(ctx); err != nil {
			if !stop() {
				<-closed
			}
			secure.Close()
			h.e.untrack(secure)
			return nil, err
		}
		return &urlTestConn{Conn: secure, e: h.e, stop: stop, closed: closed}, nil
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("URL_TEST_STATUS")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > 65536 || !strings.Contains(string(body), job.group.test.config.ExpectedBody) {
		return errors.New("URL_TEST_BODY")
	}
	return nil
}

type urlTestConn struct {
	net.Conn
	e      *Engine
	stop   func() bool
	closed chan struct{}
	once   sync.Once
}

func (c *urlTestConn) Close() error {
	c.once.Do(func() {
		if !c.stop() {
			<-c.closed
		}
		c.Conn.Close()
		c.e.untrack(c.Conn)
	})
	return nil
}
