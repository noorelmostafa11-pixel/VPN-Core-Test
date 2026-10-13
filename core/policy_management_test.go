package core

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSOCKSRemoteUDPAndControlLifetime(t *testing.T) {
	c, _ := ParseURI("direct://")
	c.ListenPort = 0
	peer, err := NewEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	a, err := peer.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			u.WriteTo(b[:n], a)
		}
	}()
	remote, err := ParseURI("socks5://" + a.String())
	if err != nil {
		t.Fatal(err)
	}
	host, p, _ := net.SplitHostPort(u.LocalAddr().String())
	port, _ := number(p, 1, 65535)
	for i := 0; i < 32; i++ {
		s, err := DialPacket(context.Background(), remote, host, port)
		if err != nil {
			t.Fatal(err)
		}
		s.SetDeadline(time.Now().Add(3 * time.Second))
		if err = s.WritePacket([]byte("UDP body")); err != nil {
			s.Close()
			t.Fatal(err)
		}
		packet, err := s.ReadPacket()
		if err != nil || string(packet.Payload) != "UDP body" {
			s.Close()
			t.Fatal(packet, err)
		}
		s.Close()
	}
	until := time.Now().Add(time.Second)
	for peer.Stats().Active > 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if peer.Stats().Active != 0 {
		t.Fatal("UDP control resources retained")
	}
	u.Close()
	<-done
}

func TestDNSPolicyUpstreamsBlockCacheAndFakeIP(t *testing.T) {
	var count [2]atomic.Int32
	servers := make([]*httptest.Server, 2)
	for i := 0; i < 2; i++ {
		i := i
		servers[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count[i].Add(1)
			query, _ := io.ReadAll(r.Body)
			h, q, err := parseDNSQuestion(query)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			h.Response = true
			b := dnsmessage.NewBuilder(nil, h)
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i + 1)}})
			wire, _ := b.Finish()
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(wire)
		}))
		defer servers[i].Close()
	}
	c, _ := ParseURI("direct://")
	e, err := NewEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	roots := x509.NewCertPool()
	for _, s := range servers {
		roots.AddCert(s.Certificate())
	}
	e.dns.transport.TLSClientConfig.RootCAs = roots
	p := DNSPolicyConfig{Servers: []DNSServerConfig{{Tag: "first", URLs: []string{servers[0].URL}}, {Tag: "second", URLs: []string{servers[1].URL}}}, Final: "first", Rules: []DNSRuleConfig{{DomainSuffixes: []string{"private.test"}, Action: "route", Server: "second"}, {Domains: []string{"ads.test"}, Action: "block"}, {DomainSuffixes: []string{"fake.test"}, Action: "fakeip"}}}
	if err = e.ConfigureDNS(p); err != nil {
		t.Fatal(err)
	}
	query := testDNSQuery("api.private.test", dnsmessage.TypeA)
	for i := 0; i < 2; i++ {
		wire, err := e.dns.answer(e.ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		var msg dnsmessage.Message
		if err = msg.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		if got := msg.Answers[0].Body.(*dnsmessage.AResource).A; got[3] != 2 {
			t.Fatal(got)
		}
	}
	if count[0].Load() != 0 || count[1].Load() != 1 {
		t.Fatal("wrong DNS upstream/cache", count[0].Load(), count[1].Load())
	}
	wire, _ := e.dns.answer(e.ctx, testDNSQuery("ads.test", dnsmessage.TypeA))
	var msg dnsmessage.Message
	msg.Unpack(wire)
	if msg.Header.RCode != dnsmessage.RCodeNameError || count[0].Load() != 0 {
		t.Fatal("blocked DNS escaped")
	}
	query = testDNSQuery("service.fake.test", dnsmessage.TypeA)
	wire, err = e.dns.answer(e.ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	msg.Unpack(wire)
	a := msg.Answers[0].Body.(*dnsmessage.AResource).A
	ip := net.IP(a[:]).String()
	if e.dns.fakeName(ip) != "service.fake.test" {
		t.Fatal("fake map")
	}
	_, name := e.destination(nil, ip, 22)
	if name != "service.fake.test" {
		t.Fatal("non-web fake destination not recovered")
	}
	again, _ := e.dns.answer(e.ctx, query)
	if !bytes.Equal(wire, again) {
		t.Fatal("fake address changed")
	}
	e.config.PreferIPv4 = false
	wire, err = e.dns.answer(e.ctx, testDNSQuery("service.fake.test", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	msg.Unpack(wire)
	six := msg.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA
	if e.dns.fakeName(net.IP(six[:]).String()) != "service.fake.test" {
		t.Fatal("IPv6 fake map")
	}
	p.Rules[0].Server = "first"
	if err = e.ConfigureDNS(p); err != nil {
		t.Fatal(err)
	}
	e.dns.answer(e.ctx, testDNSQuery("api.private.test", dnsmessage.TypeA))
	if count[0].Load() != 1 {
		t.Fatal("old DNS cache used after policy update")
	}
	p.Servers[0].URLs = []string{"http://plain.invalid"}
	if e.ConfigureDNS(p) == nil {
		t.Fatal("plaintext upstream accepted")
	}
}

func TestManagementAuthRedactionUpdatesAndClose(t *testing.T) {
	c := RouterConfig{Outbounds: []OutboundConfig{{Tag: "deny", URI: "block://"}, {Tag: "pass", URI: "direct://"}, {Tag: "private", URI: "http://alice:private-secret@127.0.0.1:10"}}, Groups: []GroupConfig{{Tag: "select", Mode: "selector", Members: []string{"deny", "pass"}}}, Final: "select"}
	e, err := NewRouterEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	token := strings.Repeat("x", 32)
	a, err := e.StartManagementAPI("127.0.0.1:0", token)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	call := func(method, path, body, auth string) (int, string) {
		t.Helper()
		r, _ := http.NewRequest(method, "http://"+a.String()+path, strings.NewReader(body))
		r.Header.Set("Authorization", auth)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	status, _ := call("GET", "/routing", "", "")
	if status != 401 {
		t.Fatal(status)
	}
	status, body := call("GET", "/routing", "", "Bearer "+token)
	if status != 200 || strings.Contains(body, "private-secret") || strings.Contains(body, "127.0.0.1") || strings.Contains(body, "alice") {
		t.Fatal(status, body)
	}
	status, _ = call("POST", "/select", `{"group":"select","outbound":"pass"}`, "Bearer "+token)
	if status != 200 {
		t.Fatal(status)
	}
	if e.router.table.Load().groups["select"].selected != "pass" {
		t.Fatal("selection not applied")
	}
	c.Final = "missing"
	b, _ := json.Marshal(c)
	status, _ = call("PUT", "/routing", string(b), "Bearer "+token)
	if status != 400 || e.router.table.Load().final != "select" {
		t.Fatal("invalid policy replaced current one")
	}
	e.Close()
	conn, err := net.DialTimeout("tcp", a.String(), 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("API still listening after Close")
	}
}

func TestJSONProfileAndConcurrentRouteReplacement(t *testing.T) {
	config := `{"listen_port":0,"outbounds":[{"tag":"pass","uri":"direct://"},{"tag":"deny","uri":"block://"}],"groups":[{"tag":"pick","mode":"selector","members":["pass","deny"]}],"final":"pick"}`
	path := filepath.Join(t.TempDir(), "profile.json")
	os.WriteFile(path, []byte(config), 0600)
	c, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.router == nil {
		t.Fatal("routing not installed")
	}
	parsed, _ := ReadRouterConfig(strings.NewReader(config))
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 128; j++ {
				e.Router().Select("pick", "deny")
				e.Router().Reload(parsed)
				table := e.Router().table.Load()
				if table.target(e.ctx, "tcp", "unit.test", 80) != "pick" {
					t.Error("torn table")
				}
			}
		}()
	}
	workers.Wait()
	if _, err = ReadRouterConfig(strings.NewReader(config + "{}")); err == nil {
		t.Fatal("trailing document accepted")
	}
}

func TestLargeNodeProfileAndUnsupportedRuntimeReplacement(t *testing.T) {
	c := RouterConfig{ListenPort: 1080, MaxConnections: 32, Final: "choose"}
	g := GroupConfig{Tag: "choose", Mode: "selector"}
	for i := 0; i < 1700; i++ {
		tag := "node" + itoa(i)
		c.Outbounds = append(c.Outbounds, OutboundConfig{Tag: tag, URI: "socks5://synthetic-only-user:synthetic-password@bootstrap.invalid:443"})
		g.Members = append(g.Members, tag)
	}
	g.Selected = g.Members[1699]
	c.Groups = []GroupConfig{g}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) <= 131072 {
		t.Fatal("large config fixture is too small")
	}
	file := filepath.Join(t.TempDir(), "large.json")
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := ReadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(context.Background(), config, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.router.table.Load().groups["choose"].selected != "node1699" {
		t.Fatal("large selector was truncated")
	}
	c.MaxConnections = 64
	if e.Router().Reload(c) == nil {
		t.Fatal("runtime budget change silently accepted")
	}
}
