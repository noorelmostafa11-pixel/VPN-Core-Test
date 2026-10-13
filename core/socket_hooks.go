package core

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Hooks let VPN hosts protect every outgoing socket and resolve through the
// underlying network before installing tunnel routes. Failures never fall back.
type Hooks struct {
	Protect func(context.Context, int64) error
	Resolve func(context.Context, string) ([]net.IPAddr, error)
	// Dial is an optional stream detour. A dialer must honor context and
	// return an error rather than silently switching to a direct connection.
	Dial func(context.Context, string, string) (net.Conn, error)
}
type hooksKey struct{}

// Freeze only the node's bootstrap addresses before a desktop host changes
// system DNS. Proxy destinations still resolve at the node; no recursive DNS
// dependency or URI rewrite is introduced.
func PinBootstrap(ctx context.Context, c Config, h Hooks) (Hooks, []net.IPAddr, error) {
	if c.Routing != nil {
		return pinRoutingBootstrap(ctx, c, h)
	}
	hosts := []string{c.Server}
	if c.Transport == "xhttp" {
		x, err := c.xSettings()
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
			hosts = append(hosts, down.Server)
		}
	}
	pinned := map[string][]net.IPAddr{}
	var all []net.IPAddr
	deadline, cancel := context.WithTimeout(WithHooks(ctx, h), c.ConnectTimeout)
	defer cancel()
	for _, host := range hosts {
		if _, ok := pinned[host]; ok {
			continue
		}
		ips, err := bootstrapIPs(deadline, host)
		if err != nil {
			return h, nil, err
		}
		pinned[host] = ips
		all = append(all, ips...)
	}
	original := h.Resolve
	h.Resolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if ips, ok := pinned[host]; ok {
			return append([]net.IPAddr(nil), ips...), nil
		}
		if original != nil {
			return original(ctx, host)
		}
		return nil, errors.New("BOOTSTRAP_DNS_FAILED")
	}
	return h, all, nil
}

func WithHooks(ctx context.Context, h Hooks) context.Context {
	return context.WithValue(ctx, hooksKey{}, h)
}
func providerContext() context.Context { return context.Background() }
func socketControl(ctx context.Context, _, _ string, raw syscall.RawConn) error {
	h, _ := ctx.Value(hooksKey{}).(Hooks)
	if h.Protect == nil {
		return nil
	}
	var e error
	if err := raw.Control(func(fd uintptr) { e = h.Protect(ctx, int64(fd)) }); err != nil {
		return err
	}
	if e != nil {
		return errors.Join(errors.New("SOCKET_PROTECTION_FAILED"), e)
	}
	return nil
}
func bootstrapIPs(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	h, _ := ctx.Value(hooksKey{}).(Hooks)
	if h.Resolve != nil {
		ips, e := h.Resolve(ctx, host)
		if e != nil || len(ips) == 0 {
			if e != nil && (e.Error() == "BOOTSTRAP_DNS_TIMEOUT" || e.Error() == "DNS_CALLBACK_BUSY" || e.Error() == "BOOTSTRAP_DNS_FAILED") {
				return nil, e
			}
			return nil, errors.Join(errors.New("BOOTSTRAP_DNS_FAILED"), e)
		}
		return ips, nil
	}
	if h.Protect != nil {
		// Go's system resolver can use sockets that never pass the proxy dialer's
		// Control hook. Protect fallback bootstrap DNS too, before any bytes leave.
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{ControlContext: socketControl}
			return d.DialContext(ctx, network, address)
		}}
		return resolver.LookupIPAddr(ctx, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}
func outboundDial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if h, ok := ctx.Value(hooksKey{}).(Hooks); ok && h.Dial != nil {
		return h.Dial(ctx, network, address)
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := bootstrapIPs(ctx, host)
	if e != nil {
		return nil, e
	}
	d := net.Dialer{ControlContext: socketControl}
	return dialResolved(ctx, network, ips, port, d.DialContext)
}

// Literal addresses and one-family answers have no racing overhead. With both
// families, keep at most two dialers alive and join/close the losing attempt.
func dialResolved(ctx context.Context, network string, ips []net.IPAddr, port string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	var v4, v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			if !strings.HasSuffix(network, "6") {
				v4 = append(v4, ip)
			}
		} else if !strings.HasSuffix(network, "4") {
			v6 = append(v6, ip)
		}
	}
	attempt := func(ctx context.Context, addresses []net.IPAddr) (net.Conn, error) {
		var last error = errors.New("BOOTSTRAP_DNS_FAILED")
		for _, ip := range addresses {
			host := ip.IP.String()
			if ip.Zone != "" {
				host += "%" + ip.Zone
			}
			c, err := dial(ctx, network, net.JoinHostPort(host, port))
			if err == nil {
				return c, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}
	if len(v4) == 0 {
		return attempt(ctx, v6)
	}
	if len(v6) == 0 || !strings.HasPrefix(network, "tcp") {
		return attempt(ctx, append(v4, v6...))
	}
	race, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	launch := func(addresses []net.IPAddr) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			c, err := attempt(race, addresses)
			results <- result{c, err}
		}()
	}
	launch(v4)
	delay := time.NewTimer(250 * time.Millisecond)
	defer delay.Stop()
	second := false
	completed := 0
	var winner net.Conn
	var last error
	for winner == nil && completed < 2 {
		select {
		case r := <-results:
			completed++
			last = r.err
			winner = r.conn
			if winner == nil && !second {
				launch(v6)
				second = true
			}
		case <-delay.C:
			if !second {
				launch(v6)
				second = true
			}
		case <-ctx.Done():
			last = ctx.Err()
			completed = 2
		}
	}
	cancel()
	workers.Wait()
	for len(results) > 0 {
		r := <-results
		if r.conn != nil {
			r.conn.Close()
		}
	}
	if winner != nil && ctx.Err() != nil {
		winner.Close()
		return nil, ctx.Err()
	}
	return winner, last
}
func outboundPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	l := net.ListenConfig{Control: func(n, a string, r syscall.RawConn) error { return socketControl(ctx, n, a, r) }}
	return l.ListenPacket(ctx, network, address)
}
func outboundUDPAddress(ctx context.Context, address string) (*net.UDPAddr, error) {
	h, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := bootstrapIPs(ctx, h)
	if e != nil {
		return nil, e
	}
	n, e := strconv.Atoi(p)
	if e != nil {
		return nil, e
	}
	return &net.UDPAddr{IP: ips[0].IP, Port: n, Zone: ips[0].Zone}, nil
}
