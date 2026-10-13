package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// RouterConfig is optional. Existing one-node ini configurations take the
// original path without allocating a routing table or background workers.
type RouterConfig struct {
	ListenPort     int              `json:"listen_port"`
	MaxConnections int              `json:"max_connections,omitempty"`
	Outbounds      []OutboundConfig `json:"outbounds"`
	Groups         []GroupConfig    `json:"groups,omitempty"`
	Rules          []RouteRule      `json:"rules,omitempty"`
	Final          string           `json:"final"`
	DNS            *DNSPolicyConfig `json:"dns,omitempty"`
	Inbounds       []ServerConfig   `json:"inbounds,omitempty"`
}
type OutboundConfig struct {
	Tag    string `json:"tag"`
	URI    string `json:"uri"`
	Detour string `json:"detour,omitempty"`
}
type GroupConfig struct {
	Tag      string   `json:"tag"`
	Mode     string   `json:"mode"`
	Members  []string `json:"members"`
	Selected string   `json:"selected,omitempty"`
}
type RouteRule struct {
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	DomainRegex    []string `json:"domain_regex,omitempty"`
	CIDRs          []string `json:"cidrs,omitempty"`
	SourceCIDRs    []string `json:"source_cidrs,omitempty"`
	Ports          []int    `json:"ports,omitempty"`
	PortRanges     []string `json:"port_ranges,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	Processes      []string `json:"processes,omitempty"`
	Interfaces     []string `json:"interfaces,omitempty"`
	Outbound       string   `json:"outbound"`
}

// Hosts may supply process/interface metadata when they own OS flow lookup.
// A missing field never matches a rule that requires that field.
type RouteMetadata struct {
	SourceIP      netip.Addr
	DestinationIP netip.Addr
	Process       string
	Interface     string
}
type routeMetadataKey struct{}

func WithRouteMetadata(ctx context.Context, m RouteMetadata) context.Context {
	return context.WithValue(ctx, routeMetadataKey{}, m)
}

type compiledRule struct {
	spec               RouteRule
	domains, suffixes  []string
	regex              []*regexp.Regexp
	cidrs, sourceCIDRs []netip.Prefix
	ports              [][2]int
}
type compiledOutbound struct {
	config Config
	detour string
}
type compiledGroup struct {
	mode     string
	members  []string
	selected string
	cursor   atomic.Uint64
	active   atomic.Uint32
}
type routeTable struct {
	outbounds map[string]compiledOutbound
	groups    map[string]*compiledGroup
	rules     []compiledRule
	final     string
}
type Router struct {
	table                      atomic.Pointer[routeTable]
	listenPort, maxConnections int
}

func ReadRouterConfig(reader io.Reader) (RouterConfig, error) {
	var c RouterConfig
	b, err := io.ReadAll(io.LimitReader(reader, 1048577))
	if err != nil {
		return c, err
	}
	if len(b) > 1048576 {
		return c, errors.New("ROUTE_CONFIG_SIZE")
	}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&c); err != nil {
		return c, errors.New("ROUTE_CONFIG_INVALID")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return c, errors.New("ROUTE_CONFIG_INVALID")
	}
	_, err = compileRoutes(c)
	return c, err
}

func NewRouterEngine(ctx context.Context, c RouterConfig, h Hooks) (*Engine, error) {
	base := defaults()
	base.Protocol, base.Transport, base.Security = "direct", "raw", "none"
	base.ListenPort = c.ListenPort
	base.Routing = &c
	if c.MaxConnections != 0 {
		base.MaxConnections = c.MaxConnections
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return nil, errors.New("LISTEN_PORT_INVALID")
	}
	return NewEngine(ctx, base, h)
}

func (e *Engine) Router() *Router { return e.router }

// Reload swaps a fully validated immutable table. Invalid replacements leave
// current routing and existing connections intact.
func (r *Router) Reload(c RouterConfig) error {
	if c.ListenPort != 0 && c.ListenPort != r.listenPort || c.MaxConnections != 0 && c.MaxConnections != r.maxConnections {
		return errors.New("ENGINE_LIMIT_RELOAD_SEPARATE")
	}
	if c.DNS != nil {
		return errors.New("DNS_RELOAD_SEPARATE")
	}
	if len(c.Inbounds) > 0 {
		return errors.New("LISTENER_RELOAD_SEPARATE")
	}
	table, err := compileRoutes(c)
	if err != nil {
		return err
	}
	r.table.Store(table)
	return nil
}
func (r *Router) Select(group, tag string) error {
	for {
		old := r.table.Load()
		g, ok := old.groups[group]
		if !ok || g.mode != "selector" || !contains(g.members, tag) {
			return errors.New("ROUTE_SELECTION_INVALID")
		}
		groups := make(map[string]*compiledGroup, len(old.groups))
		for k, v := range old.groups {
			groups[k] = v
		}
		groups[group] = &compiledGroup{mode: g.mode, members: g.members, selected: tag}
		replacement := &routeTable{outbounds: old.outbounds, groups: groups, rules: old.rules, final: old.final}
		if r.table.CompareAndSwap(old, replacement) {
			return nil
		}
	}
}

func compileRoutes(c RouterConfig) (*routeTable, error) {
	if len(c.Inbounds) > 32 {
		return nil, errors.New("SERVER_LISTENER_LIMIT")
	}
	for _, server := range c.Inbounds {
		if _, err := compileServer(server); err != nil {
			return nil, err
		}
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 || c.MaxConnections < 0 || c.MaxConnections > 512 {
		return nil, errors.New("ENGINE_LIMIT_INVALID")
	}
	if len(c.Outbounds) == 0 || len(c.Outbounds) > 4096 || len(c.Groups) > 128 || len(c.Rules) > 4096 {
		return nil, errors.New("ROUTE_CONFIG_LIMIT")
	}
	if c.DNS != nil {
		if _, err := compileDNSPolicy(*c.DNS); err != nil {
			return nil, err
		}
	}
	t := &routeTable{outbounds: map[string]compiledOutbound{}, groups: map[string]*compiledGroup{}, final: c.Final}
	validTag := func(s string) bool {
		return len(s) > 0 && len(s) <= 64 && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. ") == "" && !strings.Contains(s, " ")
	}
	for _, o := range c.Outbounds {
		if !validTag(o.Tag) {
			return nil, errors.New("ROUTE_TAG_INVALID")
		}
		if _, ok := t.outbounds[o.Tag]; ok {
			return nil, errors.New("ROUTE_TAG_DUPLICATE")
		}
		config, err := ParseURI(o.URI)
		if err == nil {
			err = config.Validate()
		}
		if err != nil {
			return nil, fmt.Errorf("ROUTE_OUTBOUND_INVALID: %s", o.Tag)
		}
		if config.Protocol == "direct" && o.Detour != "" || config.Protocol == "block" && o.Detour != "" {
			return nil, errors.New("ROUTE_DETOUR_INVALID")
		}
		t.outbounds[o.Tag] = compiledOutbound{config: config, detour: o.Detour}
	}
	for _, g := range c.Groups {
		if !validTag(g.Tag) || len(g.Members) == 0 || len(g.Members) > 4096 {
			return nil, errors.New("ROUTE_GROUP_INVALID")
		}
		if _, ok := t.groups[g.Tag]; ok {
			return nil, errors.New("ROUTE_TAG_DUPLICATE")
		}
		if _, ok := t.outbounds[g.Tag]; ok {
			return nil, errors.New("ROUTE_TAG_DUPLICATE")
		}
		if !contains([]string{"selector", "failover", "round_robin"}, g.Mode) {
			return nil, errors.New("ROUTE_GROUP_MODE")
		}
		selected := g.Selected
		if selected == "" {
			selected = g.Members[0]
		}
		if !contains(g.Members, selected) {
			return nil, errors.New("ROUTE_SELECTION_INVALID")
		}
		seen := map[string]bool{}
		for _, m := range g.Members {
			if seen[m] {
				return nil, errors.New("ROUTE_GROUP_DUPLICATE")
			}
			seen[m] = true
		}
		t.groups[g.Tag] = &compiledGroup{mode: g.Mode, members: append([]string(nil), g.Members...), selected: selected}
	}
	exists := func(tag string) bool { _, o := t.outbounds[tag]; _, g := t.groups[tag]; return o || g }
	if !exists(t.final) {
		return nil, errors.New("ROUTE_FINAL_INVALID")
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string, int) error
	visit = func(tag string, depth int) error {
		if !exists(tag) {
			return errors.New("ROUTE_TARGET_UNKNOWN")
		}
		if visiting[tag] || depth > 8 {
			return errors.New("ROUTE_CYCLE_OR_DEPTH")
		}
		if done[tag] {
			return nil
		}
		visiting[tag] = true
		if g, ok := t.groups[tag]; ok {
			for _, member := range g.members {
				if err := visit(member, depth+1); err != nil {
					return err
				}
			}
		} else if detour := t.outbounds[tag].detour; detour != "" {
			if err := visit(detour, depth+1); err != nil {
				return err
			}
		}
		visiting[tag] = false
		done[tag] = true
		return nil
	}
	for tag := range t.outbounds {
		if err := visit(tag, 0); err != nil {
			return nil, err
		}
	}
	for tag := range t.groups {
		if err := visit(tag, 0); err != nil {
			return nil, err
		}
	}
	for _, rule := range c.Rules {
		if !exists(rule.Outbound) {
			return nil, errors.New("ROUTE_TARGET_UNKNOWN")
		}
		rule.Networks = append([]string(nil), rule.Networks...)
		rule.Processes = append([]string(nil), rule.Processes...)
		rule.Interfaces = append([]string(nil), rule.Interfaces...)
		r := compiledRule{spec: rule}
		if len(rule.Domains)+len(rule.DomainSuffixes)+len(rule.DomainRegex)+len(rule.CIDRs)+len(rule.SourceCIDRs)+len(rule.Ports)+len(rule.PortRanges) > 1024 {
			return nil, errors.New("ROUTE_RULE_LIMIT")
		}
		for _, n := range rule.Networks {
			if n != "tcp" && n != "udp" {
				return nil, errors.New("ROUTE_NETWORK_INVALID")
			}
		}
		for i, items := range [][]string{rule.Domains, rule.DomainSuffixes} {
			for _, d := range items {
				d = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(d, "."), "."))
				if !hostValid(d) || net.ParseIP(d) != nil {
					return nil, errors.New("ROUTE_DOMAIN_INVALID")
				}
				if i == 0 {
					r.domains = append(r.domains, d)
				} else {
					r.suffixes = append(r.suffixes, d)
				}
			}
		}
		for _, pattern := range rule.DomainRegex {
			if len(pattern) > 1024 {
				return nil, errors.New("ROUTE_REGEX_LIMIT")
			}
			x, err := regexp.Compile(pattern)
			if err != nil {
				return nil, errors.New("ROUTE_REGEX_INVALID")
			}
			r.regex = append(r.regex, x)
		}
		for i, items := range [][]string{rule.CIDRs, rule.SourceCIDRs} {
			for _, s := range items {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					return nil, errors.New("ROUTE_CIDR_INVALID")
				}
				if i == 0 {
					r.cidrs = append(r.cidrs, p.Masked())
				} else {
					r.sourceCIDRs = append(r.sourceCIDRs, p.Masked())
				}
			}
		}
		for _, p := range rule.Ports {
			if p < 1 || p > 65535 {
				return nil, errors.New("ROUTE_PORT_INVALID")
			}
			r.ports = append(r.ports, [2]int{p, p})
		}
		for _, p := range rule.PortRanges {
			lo, hi, ok := strings.Cut(p, "-")
			a, ae := strconv.Atoi(lo)
			b, be := strconv.Atoi(hi)
			if !ok || ae != nil || be != nil || a < 1 || a > b || b > 65535 {
				return nil, errors.New("ROUTE_PORT_INVALID")
			}
			r.ports = append(r.ports, [2]int{a, b})
		}
		t.rules = append(t.rules, r)
	}
	return t, nil
}

func anyPrefix(prefixes []netip.Prefix, ip netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
func (r compiledRule) matches(ctx context.Context, network, host string, port int) bool {
	if len(r.spec.Networks) > 0 && !contains(r.spec.Networks, network) {
		return false
	}
	if len(r.ports) > 0 {
		found := false
		for _, p := range r.ports {
			found = found || port >= p[0] && port <= p[1]
		}
		if !found {
			return false
		}
	}
	ip, _ := netip.ParseAddr(host)
	m, _ := ctx.Value(routeMetadataKey{}).(RouteMetadata)
	if m.DestinationIP.IsValid() {
		ip = m.DestinationIP
	}
	if !anyPrefix(r.cidrs, ip) {
		return false
	}
	if !anyPrefix(r.sourceCIDRs, m.SourceIP) {
		return false
	}
	if len(r.spec.Processes) > 0 && !contains(r.spec.Processes, m.Process) {
		return false
	}
	if len(r.spec.Interfaces) > 0 && !contains(r.spec.Interfaces, m.Interface) {
		return false
	}
	if len(r.domains)+len(r.suffixes)+len(r.regex) > 0 {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		found := contains(r.domains, host)
		for _, suffix := range r.suffixes {
			found = found || host == suffix || strings.HasSuffix(host, "."+suffix)
		}
		for _, pattern := range r.regex {
			found = found || pattern.MatchString(host)
		}
		if !found {
			return false
		}
	}
	return true
}
func (t *routeTable) target(ctx context.Context, network, host string, port int) string {
	for _, r := range t.rules {
		if r.matches(ctx, network, host, port) {
			return r.spec.Outbound
		}
	}
	return t.final
}
func groupMembers(g *compiledGroup) []string {
	switch g.mode {
	case "selector":
		return []string{g.selected}
	case "round_robin":
		return []string{g.members[(g.cursor.Add(1)-1)%uint64(len(g.members))]}
	default:
		start := int(g.active.Load()) % len(g.members)
		if start == 0 {
			return g.members
		}
		members := make([]string, 0, len(g.members))
		members = append(members, g.members[start:]...)
		return append(members, g.members[:start]...)
	}
}
func terminalRouteError(err error) bool {
	return errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "SOCKET_PROTECTION_FAILED") || strings.Contains(err.Error(), "ROUTE_BLOCKED") || strings.Contains(err.Error(), "ROUTE_ATTEMPT_LIMIT")
}

type routeBudgetKey struct{}
type routeBudget struct{ remaining atomic.Int32 }

func initialRouteBudget(ctx context.Context, depth int) context.Context {
	if depth == 0 {
		b := &routeBudget{}
		b.remaining.Store(16)
		return context.WithValue(ctx, routeBudgetKey{}, b)
	}
	return ctx
}
func useRouteAttempt(ctx context.Context) error {
	if b, ok := ctx.Value(routeBudgetKey{}).(*routeBudget); ok && b.remaining.Add(-1) < 0 {
		return errors.New("ROUTE_ATTEMPT_LIMIT")
	}
	return ctx.Err()
}
func (t *routeTable) tcp(ctx context.Context, tag, host string, port, depth int) (net.Conn, error) {
	ctx = initialRouteBudget(ctx, depth)
	if depth > 8 {
		return nil, errors.New("ROUTE_DEPTH")
	}
	if g, ok := t.groups[tag]; ok {
		var last error
		for _, member := range groupMembers(g) {
			conn, err := t.tcp(ctx, member, host, port, depth+1)
			if err == nil {
				if g.mode == "failover" {
					for i, m := range g.members {
						if m == member {
							g.active.Store(uint32(i))
							break
						}
					}
				}
				return conn, nil
			}
			last = err
			if ctx.Err() != nil || terminalRouteError(err) {
				return nil, err
			}
		}
		return nil, last
	}
	o := t.outbounds[tag]
	if err := useRouteAttempt(ctx); err != nil {
		return nil, err
	}
	if o.detour != "" {
		h, _ := ctx.Value(hooksKey{}).(Hooks)
		base := h
		h.Dial = func(inner context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("DETOUR_UDP_UNSUPPORTED")
			}
			host, p, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			// Remove this level's hook so its physical dial cannot recurse.
			return t.tcp(WithHooks(inner, base), o.detour, host, port, depth+1)
		}
		ctx = WithHooks(ctx, h)
	}
	return Dial(ctx, o.config, host, port)
}
func (t *routeTable) udp(ctx context.Context, tag, host string, port, depth int) (PacketStream, error) {
	ctx = initialRouteBudget(ctx, depth)
	if depth > 8 {
		return nil, errors.New("ROUTE_DEPTH")
	}
	if g, ok := t.groups[tag]; ok {
		var last error
		for _, member := range groupMembers(g) {
			s, err := t.udp(ctx, member, host, port, depth+1)
			if err == nil {
				if g.mode == "failover" {
					for i, m := range g.members {
						if m == member {
							g.active.Store(uint32(i))
							break
						}
					}
				}
				return s, nil
			}
			last = err
			if ctx.Err() != nil || terminalRouteError(err) {
				return nil, err
			}
		}
		return nil, last
	}
	o := t.outbounds[tag]
	if err := useRouteAttempt(ctx); err != nil {
		return nil, err
	}
	if o.detour != "" {
		return nil, errors.New("DETOUR_UDP_UNSUPPORTED")
	}
	return DialPacket(ctx, o.config, host, port)
}
func (e *Engine) dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	if e.dns != nil {
		if name := e.dns.fakeName(host); name != "" {
			host = name
		}
	}
	if e.router == nil {
		return Dial(ctx, e.config, host, port)
	}
	t := e.router.table.Load()
	return t.tcp(ctx, t.target(ctx, "tcp", host, port), host, port, 0)
}
func (e *Engine) dialPacket(ctx context.Context, host string, port int) (PacketStream, error) {
	if e.dns != nil {
		if name := e.dns.fakeName(host); name != "" {
			host = name
		}
	}
	if e.router == nil {
		return DialPacket(ctx, e.config, host, port)
	}
	t := e.router.table.Load()
	return t.udp(ctx, t.target(ctx, "udp", host, port), host, port, 0)
}

func flowMetadata(ctx context.Context, source net.Addr, destination string) context.Context {
	m, _ := ctx.Value(routeMetadataKey{}).(RouteMetadata)
	m.DestinationIP, _ = netip.ParseAddr(destination)
	if source != nil {
		if host, _, err := net.SplitHostPort(source.String()); err == nil {
			m.SourceIP, _ = netip.ParseAddr(host)
		}
	}
	return WithRouteMetadata(ctx, m)
}

func (e *Engine) flowContext(ctx context.Context, source net.Addr, destination string) context.Context {
	if e.router == nil {
		return ctx
	}
	return flowMetadata(ctx, source, destination)
}
