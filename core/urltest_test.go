package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func healthProfile(t *testing.T, handler http.HandlerFunc) (RouterConfig, *httptest.Server) {
	t.Helper()
	site := httptest.NewTLSServer(handler)
	t.Cleanup(site.Close)
	cert, _ := testServerCertificate(t)
	cfg := RouterConfig{Outbounds: []OutboundConfig{{Tag: "bad", URI: "socks5://127.0.0.1:1"}, {Tag: "good", URI: "direct://"}}, Groups: []GroupConfig{{Tag: "automatic", Mode: "url_test", Members: []string{"bad", "good"}, URLTest: &URLTestConfig{URLs: []string{"https://127.0.0.1:1/", site.URL}, CAFile: cert, ExpectedBody: "verified-body", TimeoutMS: 1000}}}, Final: "automatic"}
	return cfg, site
}
func waitURLHealth(t *testing.T, e *Engine, checked int) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		n := 0
		for _, v := range e.URLHealth() {
			if v.CheckedAt != 0 {
				n++
			}
		}
		if n >= checked {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("health results not published", e.URLHealth())
}
func TestURLTestVerifiedBodyFallbackAndSelection(t *testing.T) {
	cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified-body actual HTTPS content") })
	table, err := compileRoutes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := table.tcp(context.Background(), "automatic", "127.0.0.1", 443, 0); err == nil {
		if c != nil {
			c.Close()
		}
		t.Fatal("unverified group selected a node")
	}
	e, err := NewRouterEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitURLHealth(t, e, 2)
	results := e.URLHealth()
	if len(results) != 2 || results[0].Healthy || !results[1].Healthy {
		t.Fatal(results)
	}
	c, err := e.DialContext(context.Background(), "tcp", echoPeer(t))
	if err != nil {
		t.Fatal(err)
	}
	payloadCheck(t, c)
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("health owner not joined")
	}
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}
func TestURLTestRejectsEmptyWrongBodyStatusAndTrust(t *testing.T) {
	for _, mode := range []string{"empty", "body", "status", "trust"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "empty":
					return
				case "body":
					io.WriteString(w, "wrong response")
				case "status":
					w.WriteHeader(403)
					io.WriteString(w, "verified-body")
				case "trust":
					io.WriteString(w, "verified-body")
				}
			})
			if mode == "trust" {
				cfg.Groups[0].URLTest.CAFile = ""
			}
			e, err := NewRouterEngine(context.Background(), cfg, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			waitURLHealth(t, e, 2)
			if members := e.router.table.Load().groups["automatic"].healthMembers(); len(members) != 0 {
				t.Fatal("invalid body/trust accepted", members)
			}
			if c, err := e.DialContext(context.Background(), "tcp", echoPeer(t)); err == nil {
				c.Close()
				t.Fatal("unhealthy group forwarded traffic")
			}
		})
	}
}
func TestURLTest1700CatalogIsBoundedAndManualChecksAreThrottled(t *testing.T) {
	var calls atomic.Int32
	cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "verified-body") })
	cfg.Outbounds = nil
	cfg.Groups[0].Members = nil
	for i := 0; i < 1700; i++ {
		tag := "node-" + itoa(i)
		cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{Tag: tag, URI: "direct://"})
		cfg.Groups[0].Members = append(cfg.Groups[0].Members, tag)
	}
	e, err := NewRouterEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitURLHealth(t, e, 16)
	for i := 0; i < 100; i++ {
		e.RequestURLTest()
	}
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 16 {
		t.Fatal("catalog exhausted or manual checks bypassed throttle", calls.Load())
	}
	e.Close()
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}
func TestURLTestProtectionFailureDoesNotMarkCatalogBad(t *testing.T) {
	cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified-body") })
	var calls atomic.Int32
	e, err := NewRouterEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { calls.Add(1); return errors.New("denied") }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	e.Close()
	for _, v := range e.URLHealth() {
		if v.CheckedAt != 0 || v.Reason != "PENDING" {
			t.Fatal("local protection error blamed on node", v)
		}
	}
}
func TestURLTestDisableReloadAndIdleFeature(t *testing.T) {
	e := testServerEngine(t)
	if e.health != nil || e.RequestURLTest() {
		t.Fatal("unused feature allocated a controller")
	}
	cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified-body") })
	r, err := NewRouterEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	waitURLHealth(t, r, 2)
	plain := RouterConfig{Outbounds: []OutboundConfig{{Tag: "direct", URI: "direct://"}}, Final: "direct"}
	if err = r.Router().Reload(plain); err != nil {
		t.Fatal(err)
	}
	if r.health != nil || r.RequestURLTest() {
		t.Fatal("disabled controller survived reload")
	}
	if err = r.Router().Reload(cfg); err != nil {
		t.Fatal(err)
	}
	waitURLHealth(t, r, 2)
}
func TestURLTestOwnerClosesBlockedResponse(t *testing.T) {
	started := make(chan struct{})
	cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	cfg.Groups[0].Members = []string{"good"}
	e, err := NewRouterEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		e.Close()
		t.Fatal("probe not started")
	}
	start := time.Now()
	e.Close()
	if time.Since(start) > time.Second {
		t.Fatal("blocked response survived Close")
	}
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}
func TestURLTestInputValidation(t *testing.T) {
	for _, urls := range [][]string{nil, {"http://example.com"}, {"https://user:pass@example.com"}, {"https://example.com/#fragment"}} {
		if _, err := compileURLTest(URLTestConfig{URLs: urls}); err == nil {
			t.Fatal(urls)
		}
	}
	if _, err := compileURLTest(URLTestConfig{URLs: []string{"https://example.com"}, ExpectedBody: strings.Repeat("x", 1025)}); err == nil {
		t.Fatal("unbounded expected body")
	}
}

func TestURLTestManagementRedactionAndReloadConcurrency(t *testing.T) {
	cfg, _ := healthProfile(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified-body") })
	e, err := NewRouterEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitURLHealth(t, e, 2)
	token := strings.Repeat("a", 32)
	a, err := e.StartManagementAPI("127.0.0.1:0", token)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "http://"+a.String()+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || strings.Contains(string(body), cfg.Groups[0].URLTest.URLs[1]) || strings.Contains(string(body), "socks5://") {
		t.Fatal("health API leaked endpoint or failed", string(body), err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			_ = e.URLHealth()
			group := e.router.table.Load().groups["automatic"]
			if group != nil {
				_ = groupMembers(group)
			}
		}
	}()
	for i := 0; i < 8; i++ {
		if err = e.Router().Reload(cfg); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	waitURLHealth(t, e, 2)
	e.Close()
	if e.Stats().Active != 0 {
		t.Fatal(e.Stats())
	}
}
