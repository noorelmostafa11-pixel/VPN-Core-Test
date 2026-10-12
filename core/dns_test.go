package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testDNSQuery(name string, kind dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 123, RecursionDesired: true})
	b.StartQuestions()
	n, _ := dnsmessage.NewName(name + ".")
	b.Question(dnsmessage.Question{Name: n, Type: kind, Class: dnsmessage.ClassINET})
	wire, _ := b.Finish()
	return wire
}

func TestDNSDatagramTruncatesAndNamesAmbiguous(t *testing.T) {
	query := testDNSQuery("large.test", dnsmessage.TypeA)
	h, q, _ := parseDNSQuestion(query)
	h.Response = true
	b := dnsmessage.NewBuilder(nil, h)
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	for i := 0; i < 100; i++ {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i)}})
	}
	answer, _ := b.Finish()
	truncated := dnsDatagram(query, answer)
	var p dnsmessage.Parser
	head, err := p.Start(truncated)
	if err != nil || !head.Truncated || len(truncated) > 512 {
		t.Fatal("Large UDP DNS answer did not request TCP retry")
	}
	malformed := [][]byte{nil, {0}, {0, 1, 128, 0, 0, 1, 0, 0, 0, 0, 0, 0}, {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 192, 12, 0, 1, 0, 1}}
	for _, wire := range malformed {
		if _, _, err := parseDNSQuestion(wire); err == nil {
			t.Fatal("Malformed DNS query was accepted")
		}
	}
}
func TestDNSLocalAndNativeTCPUDP(t *testing.T) {
	var requests atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/dns-query" {
			w.WriteHeader(503)
			return
		}
		query, _ := io.ReadAll(r.Body)
		h, q, err := parseDNSQuestion(query)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		h.Response = true
		h.RecursionAvailable = true
		b := dnsmessage.NewBuilder(nil, h)
		b.StartQuestions()
		b.Question(q)
		b.StartAnswers()
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60}
		if q.Type == dnsmessage.TypeA && q.Name.String() != "v6only.test." {
			b.AResource(rh, dnsmessage.AResource{A: [4]byte{192, 0, 2, 80}})
		} else if q.Type == dnsmessage.TypeAAAA {
			var ip [16]byte
			copy(ip[:], net.ParseIP("2001:db8::80").To16())
			b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ip})
		}
		wire, _ := b.Finish()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}))
	defer upstream.Close()
	uri := forwardingPeer(t, upstream.Listener.Addr().String(), "")
	cfg, _ := ParseURI(uri)
	cfg.PreferTCP = true
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	e.dns.transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	e.dns.servers = []string{upstream.URL + "/unavailable", upstream.URL + "/dns-query"}
	local, err := e.StartDNS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := nativeTestClient(t, e, false)
	for _, native := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			t.Run(itoa(boolInt(native))+"/"+itoa(boolInt(tcp)), func(t *testing.T) {
				var c net.Conn
				var err error
				if native {
					target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(net.ParseIP("192.0.2.53").To4()), Port: 53}
					if tcp {
						c, err = gonet.DialContextTCP(context.Background(), s, target, ipv4.ProtocolNumber)
					} else {
						c, err = gonet.DialUDP(s, nil, &target, ipv4.ProtocolNumber)
					}
				} else {
					network := "udp"
					if tcp {
						network = "tcp"
					}
					c, err = net.Dial(network, local.String())
				}
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				q := testDNSQuery("example.test", dnsmessage.TypeA)
				if tcp {
					q = join(word(len(q)), q)
				}
				if _, err = c.Write(q); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 4096)
				var n int
				if tcp {
					var size [2]byte
					io.ReadFull(c, size[:])
					n = int(binary.BigEndian.Uint16(size[:]))
					_, err = io.ReadFull(c, b[:n])
				} else {
					n, err = c.Read(b)
				}
				if err != nil {
					t.Fatal(err)
				}
				var p dnsmessage.Parser
				h, err := p.Start(b[:n])
				if err != nil || h.ID != 123 || h.RCode != 0 {
					t.Fatalf("DNS header: %+v %v", h, err)
				}
				p.SkipAllQuestions()
				answers, err := p.AllAnswers()
				if err != nil || len(answers) != 1 {
					t.Fatal("A answer missing")
				}
			})
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("Cache missed: upstream requests=%d", requests.Load())
	}
	for _, name := range []string{"example.test", "v6only.test"} {
		wire, err := e.dns.answer(e.ctx, testDNSQuery(name, dnsmessage.TypeAAAA))
		if err != nil {
			t.Fatal(err)
		}
		var p dnsmessage.Parser
		p.Start(wire)
		p.SkipAllQuestions()
		rr, _ := p.AllAnswers()
		want := 0
		if name == "v6only.test" {
			want = 1
		}
		if len(rr) != want {
			t.Fatalf("IPv6-only preservation %s: %d", name, len(rr))
		}
	}
	if e.dns.name("192.0.2.80") != "example.test" {
		t.Fatal("DNS destination name mapping missing")
	}
	// DNS disabled in the resolver returns a wire failure, never direct UDP.
	e.dns.servers = []string{upstream.URL + "/bad"}
	upstream.Close()
	answer, err := e.dns.answer(e.ctx, testDNSQuery("uncached.test", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, _ := p.Start(answer)
	if h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("DNS failure was not explicit")
	}
}
