package core

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// StartManagementAPI is opt-in, loopback-only, and requires a bearer secret.
// It never returns node URIs, destination addresses, credentials or keys.
func (e *Engine) StartManagementAPI(address, token string) (net.Addr, error) {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("LOCAL_LISTENER_REQUIRED")
	}
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("API_TOKEN_INVALID")
	}
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		if e.closed || e.ctx.Err() != nil {
			e.mu.Unlock()
			w.WriteHeader(503)
			return
		}
		e.workers.Add(1)
		e.mu.Unlock()
		defer e.workers.Done()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if !e.acquire() {
			w.WriteHeader(503)
			return
		}
		defer e.release()
		if r.Header.Get("Origin") != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.WriteHeader(401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1048576)
		defer r.Body.Close()
		encoder := json.NewEncoder(w)
		switch {
		case r.Method == "GET" && r.URL.Path == "/stats":
			encoder.Encode(e.Stats())
		case r.Method == "GET" && r.URL.Path == "/routing":
			if e.router == nil {
				w.WriteHeader(409)
				return
			}
			t := e.router.table.Load()
			out := map[string]string{}
			groups := map[string]any{}
			for tag, o := range t.outbounds {
				out[tag] = o.config.Protocol
			}
			for tag, g := range t.groups {
				groups[tag] = map[string]any{"mode": g.mode, "members": g.members, "selected": g.selected}
			}
			encoder.Encode(map[string]any{"outbounds": out, "groups": groups, "final": t.final, "rule_count": len(t.rules)})
		case r.Method == "PUT" && r.URL.Path == "/routing":
			if e.router == nil {
				w.WriteHeader(409)
				return
			}
			config, err := ReadRouterConfig(r.Body)
			if err == nil && config.DNS != nil {
				err = errors.New("DNS_RELOAD_SEPARATE")
			}
			if err == nil {
				err = e.router.Reload(config)
			}
			if err != nil {
				w.WriteHeader(400)
				encoder.Encode(map[string]string{"error": "ROUTE_UPDATE_REJECTED"})
				return
			}
			encoder.Encode(map[string]bool{"updated": true})
		case r.Method == "POST" && r.URL.Path == "/select":
			if e.router == nil {
				w.WriteHeader(409)
				return
			}
			var selection struct {
				Group    string `json:"group"`
				Outbound string `json:"outbound"`
			}
			if strictJSON(r.Body, &selection) != nil || e.router.Select(selection.Group, selection.Outbound) != nil {
				w.WriteHeader(400)
				return
			}
			encoder.Encode(map[string]bool{"updated": true})
		case r.Method == "PUT" && r.URL.Path == "/dns":
			var config DNSPolicyConfig
			if strictJSON(r.Body, &config) != nil || e.ConfigureDNS(config) != nil {
				w.WriteHeader(400)
				return
			}
			encoder.Encode(map[string]bool{"updated": true})
		default:
			w.WriteHeader(404)
		}
	})
	if !e.track(l) {
		return nil, net.ErrClosed
	}
	if !e.track(server) {
		l.Close()
		e.untrack(l)
		return nil, net.ErrClosed
	}
	if !e.spawn(func() { defer e.untrack(server); defer e.untrack(l); server.Serve(l) }) {
		server.Close()
		return nil, net.ErrClosed
	}
	return l.Addr(), nil
}
func strictJSON(reader io.Reader, dst any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("JSON_TRAILING_DATA")
	}
	return nil
}
