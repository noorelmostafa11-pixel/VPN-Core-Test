package core

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSProxyVerificationAndPayload(t *testing.T) {
	target := echoPeer(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != target {
			w.WriteHeader(400)
			return
		}
		remote, err := net.Dial("tcp", target)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer remote.Close()
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(remote, rw); close(done) }()
		io.Copy(c, remote)
		c.Close()
		remote.Close()
		<-done
	}))
	defer server.Close()
	config, err := ParseURI(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	config.CAFile = path
	host, p, _ := net.SplitHostPort(target)
	port, _ := number(p, 1, 65535)
	conn, err := Dial(context.Background(), config, host, port)
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, conn)
	config.ServerName = "wrong-name.invalid"
	if conn, err = Dial(context.Background(), config, host, port); err == nil {
		conn.Close()
		t.Fatal("wrong TLS name accepted")
	}
}

func TestSDKRoutingConnectionOwnership(t *testing.T) {
	target := echoPeer(t)
	c := RouterConfig{MaxConnections: 2, Outbounds: []OutboundConfig{{Tag: "pass", URI: "direct://"}}, Final: "pass"}
	for i := 0; i < 16; i++ {
		e, err := NewRouterEngine(context.Background(), c, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		first, err := e.DialContext(context.Background(), "tcp", target)
		if err != nil {
			e.Close()
			t.Fatal(err)
		}
		second, err := e.DialContext(context.Background(), "tcp", target)
		if err != nil {
			first.Close()
			e.Close()
			t.Fatal(err)
		}
		if _, err = e.DialContext(context.Background(), "tcp", target); err == nil || err.Error() != "CONNECTION_LIMIT" {
			t.Fatal("SDK budget not enforced", err)
		}
		first.Write([]byte("data"))
		b := make([]byte, 4)
		io.ReadFull(first, b)
		if string(b) != "data" {
			t.Fatal(string(b))
		}
		e.Close()
		first.Close()
		second.Close()
		if e.Stats().Active != 0 || e.Stats().Uploaded != 4 || e.Stats().Downloaded != 4 {
			t.Fatal(e.Stats())
		}
		if _, err = e.DialContext(context.Background(), "tcp", target); !errors.Is(err, net.ErrClosed) {
			t.Fatal("closed SDK dial", err)
		}
	}
}

func TestRoutingNestedFailoverHasGlobalAttemptLimit(t *testing.T) {
	c := RouterConfig{Final: "root"}
	members := []string{}
	for i := 0; i < 16; i++ {
		tag := "bad" + itoa(i)
		members = append(members, tag)
		c.Outbounds = append(c.Outbounds, OutboundConfig{Tag: tag, URI: "http://127.0.0.1:1"})
	}
	c.Groups = []GroupConfig{{Tag: "one", Mode: "failover", Members: members}, {Tag: "two", Mode: "failover", Members: members}, {Tag: "root", Mode: "failover", Members: []string{"one", "two"}}}
	var dials atomic.Int32
	e, err := NewRouterEngine(context.Background(), c, Hooks{Dial: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("CONTROLLED_FAILURE")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	_, err = e.DialContext(context.Background(), "tcp", "destination.invalid:443")
	if err == nil || !strings.Contains(err.Error(), "ROUTE_ATTEMPT_LIMIT") || dials.Load() != 16 {
		t.Fatal("unbounded fallback", dials.Load(), err)
	}
}

func TestHTTPProxyPreservesResponseReadAhead(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(c)
		http.ReadRequest(r)
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nGREETING")
	}()
	config, _ := ParseURI("http://" + l.Addr().String())
	c, err := Dial(context.Background(), config, "remote.invalid", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	b := make([]byte, 8)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "GREETING" {
		t.Fatal("response read-ahead lost", string(b), err)
	}
	<-done
}

func TestRoutingBootstrapKeepsHealthyAlternativeAndSkipsDetouredNames(t *testing.T) {
	profile := RouterConfig{Outbounds: []OutboundConfig{{Tag: "first", URI: "socks5://healthy.invalid:443"}, {Tag: "offline", URI: "socks5://offline.invalid:443"}, {Tag: "downstream", URI: "http://private-hop.invalid:443", Detour: "first"}}, Final: "first"}
	c := defaults()
	c.Routing = &profile
	var calls atomic.Int32
	h, ips, err := PinBootstrap(context.Background(), c, Hooks{Resolve: func(_ context.Context, host string) ([]net.IPAddr, error) {
		calls.Add(1)
		if host == "healthy.invalid" {
			return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 1)}}, nil
		}
		if host == "private-hop.invalid" {
			t.Error("detoured hop resolved on physical network")
		}
		return nil, errors.New("unavailable")
	}})
	if err != nil || len(ips) != 1 || calls.Load() != 2 {
		t.Fatal(ips, calls.Load(), err)
	}
	if _, err = h.Resolve(context.Background(), "offline.invalid"); err == nil {
		t.Fatal("offline exit accepted")
	}
	resolved, err := h.Resolve(context.Background(), "healthy.invalid")
	if err != nil || resolved[0].IP.String() != "192.0.2.1" || calls.Load() != 2 {
		t.Fatal(resolved, err)
	}
}
