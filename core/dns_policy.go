package core

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

type DNSPolicyConfig struct {
	Servers []DNSServerConfig `json:"servers"`
	Rules   []DNSRuleConfig   `json:"rules,omitempty"`
	Final   string            `json:"final"`
	FakeIP  bool              `json:"fakeip,omitempty"`
}
type DNSServerConfig struct {
	Tag  string   `json:"tag"`
	URLs []string `json:"urls"`
}
type DNSRuleConfig struct {
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	Action         string   `json:"action"`
	Server         string   `json:"server,omitempty"`
}
type dnsPolicyKey struct{}
type dnsPolicy struct {
	id      uint64
	servers map[string][]string
	rules   []DNSRuleConfig
	final   string
	fake    bool
}

func compileDNSPolicy(c DNSPolicyConfig) (*dnsPolicy, error) {
	if len(c.Servers) == 0 || len(c.Servers) > 16 || len(c.Rules) > 1024 {
		return nil, errors.New("DNS_POLICY_LIMIT")
	}
	p := &dnsPolicy{servers: map[string][]string{}, final: c.Final, fake: c.FakeIP}
	for _, s := range c.Servers {
		if s.Tag == "" || len(s.Tag) > 64 || len(s.URLs) == 0 || len(s.URLs) > 8 || p.servers[s.Tag] != nil {
			return nil, errors.New("DNS_SERVER_INVALID")
		}
		for _, raw := range s.URLs {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || !hostValid(u.Hostname()) || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
				return nil, errors.New("DNS_HTTPS_URL_REQUIRED")
			}
			p.servers[s.Tag] = append(p.servers[s.Tag], raw)
		}
	}
	if p.servers[p.final] == nil {
		return nil, errors.New("DNS_FINAL_INVALID")
	}
	for _, rule := range c.Rules {
		if !contains([]string{"route", "block", "fakeip"}, rule.Action) || rule.Action == "route" && p.servers[rule.Server] == nil || len(rule.Domains)+len(rule.DomainSuffixes) > 1024 {
			return nil, errors.New("DNS_RULE_INVALID")
		}
		clone := rule
		clone.Domains = nil
		clone.DomainSuffixes = nil
		for i, items := range [][]string{rule.Domains, rule.DomainSuffixes} {
			for _, name := range items {
				name = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "."), "."))
				if !validSniffName(name) {
					return nil, errors.New("DNS_RULE_DOMAIN_INVALID")
				}
				if i == 0 {
					clone.Domains = append(clone.Domains, name)
				} else {
					clone.DomainSuffixes = append(clone.DomainSuffixes, name)
				}
			}
		}
		p.rules = append(p.rules, clone)
	}
	return p, nil
}
func (p *dnsPolicy) ruleFor(name string) *DNSRuleConfig {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for i, r := range p.rules {
		match := len(r.Domains)+len(r.DomainSuffixes) == 0 || contains(r.Domains, name)
		for _, suffix := range r.DomainSuffixes {
			match = match || name == suffix || strings.HasSuffix(name, "."+suffix)
		}
		if match {
			return &p.rules[i]
		}
	}
	return nil
}
func (p *dnsPolicy) actionFor(name string) string {
	if r := p.ruleFor(name); r != nil {
		return r.Action
	}
	if p.fake {
		return "fakeip"
	}
	return "route"
}
func (p *dnsPolicy) serversFor(name string) []string {
	if r := p.ruleFor(name); r != nil && r.Action == "route" {
		return p.servers[r.Server]
	}
	return p.servers[p.final]
}
func (e *Engine) ConfigureDNS(c DNSPolicyConfig) error {
	if e.dns == nil {
		return errors.New("DNS_DISABLED")
	}
	p, err := compileDNSPolicy(c)
	if err != nil {
		return err
	}
	p.id = e.dns.policyID.Add(1)
	if p.fake {
		e.dns.fakeActive.Store(true)
	}
	for _, rule := range p.rules {
		if rule.Action == "fakeip" {
			e.dns.fakeActive.Store(true)
			break
		}
	}
	e.dns.policy.Store(p)
	return nil
}

// Fake addresses are never recycled during an engine's lifetime. Exhaustion
// yields SERVFAIL rather than pointing an old client's IP at another name.
func (d *dnsRelay) fakeAnswer(h dnsmessage.Header, q dnsmessage.Question) ([]byte, error) {
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if !validSniffName(name) {
		return dnsEmpty(h, q, dnsmessage.RCodeNameError), nil
	}
	if q.Type == dnsmessage.TypeAAAA && d.engine.config.PreferIPv4 {
		return dnsEmpty(h, q, 0), nil
	}
	key := name
	if q.Type == dnsmessage.TypeAAAA {
		key = "6:" + name
	}
	d.mu.Lock()
	if d.fakeNames == nil {
		d.fakeNames = map[string]string{}
		d.fakeIPs = map[string]string{}
	}
	ipString := d.fakeNames[key]
	if ipString == "" {
		if len(d.fakeNames) >= 4096 {
			d.mu.Unlock()
			return dnsEmpty(h, q, dnsmessage.RCodeServerFailure), nil
		}
		d.fakeNext++
		if q.Type == dnsmessage.TypeA {
			n := d.fakeNext
			ipString = net.IPv4(198, 18, byte(n>>8), byte(n)).String()
		} else {
			ip := make(net.IP, 16)
			ip[0], ip[1] = 0xfc, 0x00
			ip[12], ip[13], ip[14], ip[15] = byte(d.fakeNext>>24), byte(d.fakeNext>>16), byte(d.fakeNext>>8), byte(d.fakeNext)
			ipString = ip.String()
		}
		d.fakeNames[key], d.fakeIPs[ipString] = ipString, name
	}
	d.mu.Unlock()
	h.Response = true
	h.RCode = 0
	h.RecursionAvailable = true
	h.AuthenticData = false
	b := dnsmessage.NewBuilder(nil, h)
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60}
	if q.Type == dnsmessage.TypeA {
		var a [4]byte
		copy(a[:], net.ParseIP(ipString).To4())
		b.AResource(rh, dnsmessage.AResource{A: a})
	} else {
		var a [16]byte
		copy(a[:], net.ParseIP(ipString).To16())
		b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a})
	}
	return b.Finish()
}
func (d *dnsRelay) fakeName(ip string) string {
	if !d.fakeActive.Load() {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fakeIPs[ip]
}
