package core

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

// Hooks let VPN hosts protect every outgoing socket and resolve through the
// underlying network before installing tunnel routes. Failures never fall back.
type Hooks struct {
	Protect func(context.Context, int64) error
	Resolve func(context.Context, string) ([]net.IPAddr, error)
}
type hooksKey struct{}

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
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := bootstrapIPs(ctx, host)
	if e != nil {
		return nil, e
	}
	d := net.Dialer{ControlContext: socketControl}
	var last error
	for _, ip := range ips {
		h := ip.IP.String()
		if ip.Zone != "" {
			h += "%" + ip.Zone
		}
		c, e := d.DialContext(ctx, network, net.JoinHostPort(h, port))
		if e == nil {
			return c, nil
		}
		last = e
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
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
