package core

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Freeze physical first-hop names before the host changes DNS. Names of
// downstream hops are carried by their preceding proxy, never resolved here.
// An unavailable alternate does not prevent another pinned exit from working.
func pinRoutingBootstrap(ctx context.Context, c Config, h Hooks) (Hooks, []net.IPAddr, error) {
	table, err := compileRoutes(*c.Routing)
	if err != nil {
		return h, nil, err
	}
	hosts := map[string]bool{}
	for _, o := range table.outbounds {
		if o.detour != "" || o.config.Protocol == "direct" || o.config.Protocol == "block" {
			continue
		}
		hosts[o.config.Server] = true
		if o.config.Transport == "xhttp" {
			x, err := o.config.xSettings()
			if err != nil {
				return h, nil, err
			}
			options, err := x.options()
			if err != nil {
				return h, nil, err
			}
			if len(options.DownloadSettings) > 0 && string(options.DownloadSettings) != "null" {
				down, err := downloadConfig(x, options.DownloadSettings)
				if err != nil {
					return h, nil, err
				}
				hosts[down.Server] = true
			}
		}
	}
	if len(hosts) == 0 {
		return h, nil, errors.New("TUN_ROUTING_PROXY_REQUIRED")
	}
	deadline, cancel := context.WithTimeout(WithHooks(ctx, h), c.ConnectTimeout)
	defer cancel()
	pending := make(chan string, len(hosts))
	for host := range hosts {
		pending <- host
	}
	close(pending)
	var workers sync.WaitGroup
	var mu sync.Mutex
	pinned := map[string][]net.IPAddr{}
	failures := map[string]error{}
	for i := 0; i < min(4, len(hosts)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for host := range pending {
				ips, err := bootstrapIPs(deadline, host)
				mu.Lock()
				if err != nil || len(ips) == 0 {
					failures[host] = errors.New("BOOTSTRAP_DNS_FAILED")
				} else {
					pinned[host] = append([]net.IPAddr(nil), ips...)
				}
				mu.Unlock()
			}
		}()
	}
	workers.Wait()
	var all []net.IPAddr
	seen := map[string]bool{}
	for _, ips := range pinned {
		for _, ip := range ips {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				all = append(all, ip)
			}
		}
	}
	if len(all) == 0 {
		return h, nil, errors.New("BOOTSTRAP_DNS_FAILED")
	}
	original := h.Resolve
	h.Resolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if ips, ok := pinned[host]; ok {
			return append([]net.IPAddr(nil), ips...), nil
		}
		if err, ok := failures[host]; ok {
			return nil, err
		}
		if original != nil {
			return original(ctx, host)
		}
		return nil, errors.New("BOOTSTRAP_DNS_FAILED")
	}
	return h, all, nil
}
