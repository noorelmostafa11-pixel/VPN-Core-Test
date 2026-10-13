package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func echoPeer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	t.Cleanup(func() { l.Close(); workers.Wait() })
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}
func payloadCheck(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("actual bidirectional payload\x00\xff")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(payload))
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != string(payload) {
		t.Fatalf("payload mismatch: %q", b)
	}
}

func TestProxyHTTPRemote(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(fmt.Sprint(authenticated), func(t *testing.T) {
			target := echoPeer(t)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			peerDone := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReader(c)
				req, err := http.ReadRequest(r)
				if err != nil {
					peerDone <- err
					return
				}
				if req.Method != "CONNECT" || req.Host != target {
					peerDone <- errors.New("wrong destination")
					return
				}
				if authenticated && req.Header.Get("Proxy-Authorization") != "Basic YWxpY2U6c2VjcmV0" {
					peerDone <- errors.New("wrong auth")
					return
				}
				server, err := net.Dial("tcp", req.Host)
				if err != nil {
					peerDone <- err
					return
				}
				defer server.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{})
				go func() { io.Copy(server, r); close(done) }()
				io.Copy(c, server)
				c.Close()
				server.Close()
				<-done
				peerDone <- nil
			}()
			userinfo := ""
			if authenticated {
				userinfo = "alice:secret@"
			}
			config, err := ParseURI("http://" + userinfo + l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			host, portText, _ := net.SplitHostPort(target)
			port, _ := number(portText, 1, 65535)
			conn, err := Dial(context.Background(), config, host, port)
			if err != nil {
				t.Fatal(err)
			}
			payloadCheck(t, conn)
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxySOCKSRemoteAndAuth(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks4a"} {
		t.Run(scheme, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if scheme == "socks5" {
					b := make([]byte, 3)
					_, err = io.ReadFull(c, b)
					if err != nil || string(b) != string([]byte{5, 1, 2}) {
						done <- errors.New("greeting")
						return
					}
					c.Write([]byte{5, 2})
					auth := make([]byte, 14)
					_, err = io.ReadFull(c, auth)
					if err != nil || string(auth) != string(append(append([]byte{1, 5}, []byte("alice")...), append([]byte{6}, []byte("secret")...)...)) {
						done <- errors.New("auth")
						return
					}
					c.Write([]byte{1, 0})
					h := make([]byte, 4)
					io.ReadFull(c, h)
					if string(h) != string([]byte{5, 1, 0, 3}) {
						done <- errors.New("command")
						return
					}
					n := make([]byte, 1)
					io.ReadFull(c, n)
					a := make([]byte, int(n[0])+2)
					io.ReadFull(c, a)
					if string(a[:len(a)-2]) != "remote-only.invalid" {
						done <- errors.New("local DNS leak")
						return
					}
					c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				} else {
					r := bufio.NewReader(c)
					h := make([]byte, 8)
					io.ReadFull(r, h)
					user, _ := r.ReadString(0)
					domain, _ := r.ReadString(0)
					if string(h) != string([]byte{4, 1, 1, 187, 0, 0, 0, 1}) || user != "alice\x00" || domain != "remote-only.invalid\x00" {
						done <- errors.New("SOCKS4a request")
						return
					}
					c.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
					io.Copy(c, r)
					done <- nil
					return
				}
				io.Copy(c, c)
				done <- nil
			}()
			auth := "alice@"
			if scheme == "socks5" {
				auth = "alice:secret@"
			}
			config, err := ParseURI(scheme + "://" + auth + l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithHooks(context.Background(), Hooks{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
				t.Error("unexpected local destination DNS")
				return nil, errors.New("DNS forbidden")
			}})
			conn, err := Dial(ctx, config, "remote-only.invalid", 443)
			if err != nil {
				t.Fatal(err)
			}
			payloadCheck(t, conn)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRouterRulesGroupsAndReload(t *testing.T) {
	c := RouterConfig{Outbounds: []OutboundConfig{{Tag: "pass", URI: "direct://"}, {Tag: "deny", URI: "block://"}}, Groups: []GroupConfig{{Tag: "pick", Mode: "selector", Members: []string{"deny", "pass"}}}, Rules: []RouteRule{{DomainSuffixes: []string{"blocked.test"}, Outbound: "deny"}, {CIDRs: []string{"10.0.0.0/8"}, Ports: []int{443}, Outbound: "deny"}, {Processes: []string{"browser"}, Interfaces: []string{"wifi"}, SourceCIDRs: []string{"192.168.1.0/24"}, Outbound: "deny"}}, Final: "pick"}
	e, err := NewRouterEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.dialTCP(e.ctx, "blocked.test", 80); err == nil || err.Error() != "ROUTE_BLOCKED" {
		t.Fatal(err)
	}
	if _, err = e.dialTCP(e.ctx, "10.1.2.3", 443); err == nil || err.Error() != "ROUTE_BLOCKED" {
		t.Fatal(err)
	}
	if err = e.Router().Select("pick", "pass"); err != nil {
		t.Fatal(err)
	}
	target := echoPeer(t)
	host, p, _ := net.SplitHostPort(target)
	port, _ := number(p, 1, 65535)
	conn, err := e.dialTCP(e.ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	ctx := WithRouteMetadata(e.ctx, RouteMetadata{Process: "browser", Interface: "wifi", SourceIP: netip.MustParseAddr("192.168.1.4")})
	if _, err = e.dialTCP(ctx, host, port); err == nil || err.Error() != "ROUTE_BLOCKED" {
		t.Fatal(err)
	}
	c.Final = "missing"
	if e.Router().Reload(c) == nil {
		t.Fatal("invalid update accepted")
	}
	conn, err = e.dialTCP(e.ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	if got := e.Router().table.Load().target(e.ctx, "tcp", "evilblocked.test", 80); got != "pick" {
		t.Fatal("suffix matched partial label", got)
	}
}

func TestRouterFailoverDetourAndProtection(t *testing.T) {
	target := echoPeer(t)
	host, p, _ := net.SplitHostPort(target)
	port, _ := number(p, 1, 65535)
	pass := defaults()
	pass.Protocol, pass.Transport, pass.Security = "direct", "raw", "none"
	pass.ListenPort = 0
	peer, err := NewEngine(context.Background(), pass, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	a, err := peer.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	c := RouterConfig{Outbounds: []OutboundConfig{{Tag: "bad", URI: "socks5://127.0.0.1:1"}, {Tag: "good", URI: "socks5://" + a.String(), Detour: "hop"}, {Tag: "hop", URI: "socks5://" + a.String()}}, Groups: []GroupConfig{{Tag: "backup", Mode: "failover", Members: []string{"bad", "good"}}}, Final: "backup"}
	e, err := NewRouterEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	conn, err := e.dialTCP(e.ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	var protected atomic.Int32
	blocked, err := NewRouterEngine(context.Background(), c, Hooks{Protect: func(context.Context, int64) error { protected.Add(1); return errors.New("denied") }})
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	if _, err = blocked.dialTCP(blocked.ctx, host, port); err == nil || !strings.Contains(err.Error(), "SOCKET_PROTECTION_FAILED") {
		t.Fatal(err)
	}
	if protected.Load() != 1 {
		t.Fatal("protection failure triggered alternate dial", protected.Load())
	}
	c.Outbounds[2].Detour = "good"
	if e.Router().Reload(c) == nil {
		t.Fatal("detour cycle accepted")
	}
}

func TestMixedHTTPAndSOCKSPayload(t *testing.T) {
	c, _ := ParseURI("direct://")
	c.ListenPort = 0
	e, err := NewEngine(context.Background(), c, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.StartMixed("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := echoPeer(t)
	conn, err := net.Dial("tcp", a.String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Send the first payload with CONNECT, to catch accidental read-ahead loss.
	io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\nEARLY")
	r := bufio.NewReader(conn)
	req := &http.Request{Method: "CONNECT"}
	resp, err := http.ReadResponse(r, req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	b := make([]byte, 5)
	if _, err = io.ReadFull(r, b); err != nil || string(b) != "EARLY" {
		t.Fatal("lost early payload", string(b), err)
	}
	conn.Close()
	remote, _ := ParseURI("socks5://" + a.String())
	host, p, _ := net.SplitHostPort(target)
	port, _ := number(p, 1, 65535)
	conn, err = Dial(context.Background(), remote, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	web := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("credentials forwarded")
		}
		io.WriteString(w, "HTTP body verified")
	})}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	go web.Serve(l)
	conn, err = net.Dial("tcp", a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "GET http://"+l.Addr().String()+"/test HTTP/1.1\r\nHost: "+l.Addr().String()+"\r\nProxy-Authorization: secret\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "HTTP body verified" {
		t.Fatal(string(body), err)
	}
}
