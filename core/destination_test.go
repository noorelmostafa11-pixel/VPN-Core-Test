package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Independent VLESS peer: web tests reject numeric destinations, exposing the
// original failure without depending on public Internet or a working IPv6 WAN.
func forwardingPeer(t *testing.T, target, requiredHost string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				h := make([]byte, 18)
				if _, err = io.ReadFull(c, h); err != nil || h[0] != 0 || h[17] != 0 {
					return
				}
				r := make([]byte, 4)
				if _, err = io.ReadFull(c, r); err != nil || r[0] != 1 {
					return
				}
				var host string
				switch r[3] {
				case 1:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					b := make([]byte, 16)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 2:
					var n [1]byte
					io.ReadFull(c, n[:])
					b := make([]byte, int(n[0]))
					io.ReadFull(c, b)
					host = string(b)
				default:
					return
				}
				if requiredHost != "" && host != requiredHost {
					return
				}
				up, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				writeAll(c, []byte{0, 0})
				c.SetDeadline(time.Time{}) // Bound header parsing, not the pooled HTTPS connection lifetime.
				copyDone := make(chan struct{})
				go func() { io.Copy(up, c); up.Close(); close(copyDone) }()
				io.Copy(c, up)
				c.Close()
				<-copyDone
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return "vless://12345678-1234-4567-9234-567812345678@" + l.Addr().String() + "?security=none"
}

func nativeTestClient(t *testing.T, e *Engine, v6 bool) *stack.Stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dev := &memoryDevice{in: make(chan []byte, 256), out: make(chan []byte, 256), stop: make(chan struct{})}
	tunnel, err := e.StartTUN(dev, 1500)
	if err != nil {
		t.Fatal(err)
	}
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	link := channel.New(256, 1500, "")
	s.CreateNIC(1, link)
	proto := ipv4.ProtocolNumber
	source := net.ParseIP("10.77.0.2").To4()
	subnet := header.IPv4EmptySubnet
	bits := 32
	if v6 {
		proto = ipv6.ProtocolNumber
		source = net.ParseIP("fd77::2").To16()
		subnet = header.IPv6EmptySubnet
		bits = 128
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(source), PrefixLen: bits}}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			b := append([]byte(nil), view.AsSlice()...)
			view.Release()
			pkt.DecRef()
			select {
			case dev.in <- b:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer pumps.Done()
		for {
			select {
			case b := <-dev.out:
				p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
				link.InjectInbound(proto, p)
				p.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		tunnel.Close()
		link.Close()
		s.Close()
		s.Wait()
		pumps.Wait()
	})
	return s
}

func TestDestinationHTTPSRegression(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified HTTPS response") }))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	for _, native := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(itoa(boolInt(native))+"/"+itoa(boolInt(v6))+"/"+itoa(boolInt(enabled)), func(t *testing.T) {
					uri := forwardingPeer(t, origin.Listener.Addr().String(), "example.com")
					cfg, _ := ParseURI(uri)
					cfg.Sniffing = enabled
					cfg.ListenPort = 0
					e, err := NewEngine(context.Background(), cfg, Hooks{})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { e.Close() })
					e.sniffBudget = 2 * time.Second // Race-instrumented virtual stacks are not latency benchmarks.
					ip := "192.0.2.80"
					proto := ipv4.ProtocolNumber
					if v6 {
						ip = "2001:db8::80"
						proto = ipv6.ProtocolNumber
					}
					transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}}
					if native {
						s := nativeTestClient(t, e, v6)
						transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
							return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(net.ParseIP(ip).To16()), Port: 443}, proto)
						}
						if !v6 {
							transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
								return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(net.ParseIP(ip).To4()), Port: 443}, proto)
							}
						}
					} else {
						a, err := e.StartSOCKS()
						if err != nil {
							t.Fatal(err)
						}
						proxy, _ := url.Parse("socks5://" + a.String())
						transport.Proxy = http.ProxyURL(proxy)
					}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
					response, err := client.Get("https://" + net.JoinHostPort(ip, "443") + "/")
					if !enabled {
						if err == nil {
							response.Body.Close()
							t.Fatal("Disabled sniffing unexpectedly passed the rejecting peer")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					if err != nil || string(body) != "verified HTTPS response" {
						t.Fatalf("TLS prefix replay failed: %q %v", body, err)
					}
				})
			}
		}
	}
}

func TestSniffHTTPAndMalformed(t *testing.T) {
	for _, test := range []struct{ wire, name string }{{"GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "example.com"}, {"POST / HTTP/1.1\r\nhOsT: test.example\r\n\r\npayload", "test.example"}, {"GET / HTTP/1.1\r\nHost: attacker.example@127.0.0.1\r\n\r\n", ""}, {"SSH-2.0-test\r\n", ""}, {"\x16\x03\x03\xff\xff", ""}} {
		name, _ := sniffDestination([]byte(test.wire))
		if name != test.name {
			t.Fatalf("sniff %q: %q", test.wire, name)
		}
	}
}
func TestSniffFragmentedClientHelloAndECH(t *testing.T) {
	hello := []byte{3, 3}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0, 0, 2, 0x13, 1, 1, 0)
	name := []byte("example.com")
	sni := join(word(3+len(name)), []byte{0}, word(len(name)), name)
	ext := join([]byte{0, 0}, word(len(sni)), sni)
	for _, ech := range []bool{false, true} {
		extra := ext
		if ech {
			extra = join(ext, []byte{0xfe, 0x0d, 0, 0})
		}
		h := join(hello, word(len(extra)), extra)
		h = join([]byte{1, byte(len(h) >> 16), byte(len(h) >> 8), byte(len(h))}, h)
		wire := join([]byte{22, 3, 3}, word(7), h[:7], []byte{22, 3, 3}, word(len(h)-7), h[7:])
		got, _ := sniffDestination(wire)
		want := "example.com"
		if ech {
			want = ""
		}
		if got != want {
			t.Fatalf("fragmented ECH=%v: %q", ech, got)
		}
		for i := 0; i < len(wire); i++ {
			sniffDestination(wire[:i])
		}
	}
}

func TestDialResolvedFallbackAndCleanup(t *testing.T) {
	ips := []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}
	for _, slow4 := range []bool{false, true} {
		t.Run(itoa(boolInt(slow4)), func(t *testing.T) {
			var attempts atomic.Int32
			peer, server := net.Pipe()
			defer server.Close()
			start := time.Now()
			conn, err := dialResolved(context.Background(), "tcp", ips, "443", func(ctx context.Context, _, address string) (net.Conn, error) {
				attempts.Add(1)
				if strings.HasPrefix(address, "192.") {
					if slow4 {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return nil, errors.New("IPv4 unavailable")
				}
				return peer, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if attempts.Load() != 2 || time.Since(start) > time.Second {
				t.Fatal("Fallback waited for the global timeout")
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if c, err := dialResolved(ctx, "tcp", ips, "443", func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }); c != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Canceled race: %v %v", c, err)
	}
}

func BenchmarkSniffHTTP(b *testing.B) {
	wire := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	for i := 0; i < b.N; i++ {
		sniffDestination(wire)
	}
}
