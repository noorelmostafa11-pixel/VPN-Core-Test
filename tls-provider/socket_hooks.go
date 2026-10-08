package main

/*
#include <stdint.h>
typedef int (*vpn_protect_cb)(int64_t, void*);
typedef int (*vpn_resolve_cb)(const char*, char*, int, void*);
static inline int invoke_protect(uintptr_t fn, int64_t fd, uintptr_t user) {
    return ((vpn_protect_cb)fn)(fd, (void*)user);
}
static inline int invoke_resolve(uintptr_t fn, const char* host, char* out, int cap, uintptr_t user) {
    return ((vpn_resolve_cb)fn)(host, out, cap, (void*)user);
}
*/
import "C"

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type hookSnapshot struct{ protect, resolve, user uintptr }

var socketHooks struct {
	sync.Mutex
	hooks    hookSnapshot
	active   int
	changing bool
	idle     *sync.Cond
	ctx      context.Context
	cancel   context.CancelFunc
}

func init() {
	socketHooks.idle = sync.NewCond(&socketHooks.Mutex)
	socketHooks.ctx, socketHooks.cancel = context.WithCancel(context.Background())
}
func providerContext() context.Context {
	socketHooks.Lock()
	defer socketHooks.Unlock()
	return socketHooks.ctx
}

//export vpn_socket_start
func vpn_socket_start() {
	socketHooks.Lock()
	defer socketHooks.Unlock()
	socketHooks.cancel()
	socketHooks.ctx, socketHooks.cancel = context.WithCancel(context.Background())
}

//export vpn_socket_cancel
func vpn_socket_cancel() {
	socketHooks.Lock()
	cancel := socketHooks.cancel
	socketHooks.Unlock()
	cancel()
}
func acquireHooks() (hookSnapshot, func(), bool) {
	socketHooks.Lock()
	defer socketHooks.Unlock()
	if socketHooks.changing || socketHooks.ctx.Err() != nil {
		return hookSnapshot{}, func() {}, false
	}
	h := socketHooks.hooks
	socketHooks.active++
	return h, func() { socketHooks.Lock(); socketHooks.active--; socketHooks.idle.Broadcast(); socketHooks.Unlock() }, true
}

//export vpn_socket_set_hooks
func vpn_socket_set_hooks(protect, resolve, user C.uintptr_t) {
	socketHooks.Lock()
	defer socketHooks.Unlock()
	socketHooks.changing = true
	for socketHooks.active != 0 {
		socketHooks.idle.Wait()
	}
	socketHooks.hooks = hookSnapshot{uintptr(protect), uintptr(resolve), uintptr(user)}
	socketHooks.changing = false
}

func socketControl(ctx context.Context, _, _ string, raw syscall.RawConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var denied, cancelled bool
	err := raw.Control(func(fd uintptr) {
		hooks, done, ok := acquireHooks()
		defer done()
		if !ok {
			cancelled = true
			return
		}
		if hooks.protect != 0 {
			denied = C.invoke_protect(C.uintptr_t(hooks.protect), C.int64_t(fd), C.uintptr_t(hooks.user)) != 1
		}
	})
	if err != nil {
		return err
	}
	if cancelled {
		return context.Canceled
	}
	if denied {
		return providerError(453)
	}
	return nil
}

func bootstrapIPs(ctx context.Context, hostname string) ([]net.IPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	hooks, done, ok := acquireHooks()
	if !ok {
		return nil, context.Canceled
	}
	defer done()
	if hooks.resolve != 0 {
		host := append([]byte(hostname), 0)
		out := make([]byte, 4096)
		n := int(C.invoke_resolve(C.uintptr_t(hooks.resolve), (*C.char)(unsafe.Pointer(&host[0])), (*C.char)(unsafe.Pointer(&out[0])), C.int(len(out)), C.uintptr_t(hooks.user)))
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n == -2 {
			return nil, providerError(455)
		}
		if n == -3 {
			return nil, context.Canceled
		}
		if n == -4 {
			return nil, providerError(456)
		}
		if n <= 0 || n >= len(out) {
			return nil, providerError(454)
		}
		var ips []net.IPAddr
		for _, item := range strings.Split(string(out[:n]), "\n") {
			if item == "" {
				continue
			}
			ip := net.ParseIP(item)
			if ip == nil || len(ips) >= 32 {
				return nil, providerError(454)
			}
			ips = append(ips, net.IPAddr{IP: ip})
		}
		if len(ips) == 0 {
			return nil, providerError(454)
		}
		return ips, nil
	}
	protected := hooks.protect != 0
	resolver := net.DefaultResolver
	if protected {
		// Protect Go's resolver sockets too. Android embedding provides the
		// underlying Network resolver above, avoiding /etc/resolv.conf.
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{ControlContext: socketControl}).DialContext(ctx, network, address)
		}}
	}
	return resolver.LookupIPAddr(ctx, hostname)
}

func outboundDial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	unwatch := context.AfterFunc(providerContext(), cancel)
	defer unwatch()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	socketHooks.Lock()
	custom := socketHooks.hooks.protect != 0 || socketHooks.hooks.resolve != 0
	socketHooks.Unlock()
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, ControlContext: socketControl}
	if !custom {
		return d.DialContext(deadline, network, address)
	}
	ips, err := bootstrapIPs(deadline, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		var conn net.Conn
		conn, err = d.DialContext(deadline, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func outboundPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		return socketControl(ctx, network, address, raw)
	}}
	return lc.ListenPacket(ctx, network, address)
}

func outboundUDPAddress(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, text, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("UDP port invalid")
	}
	ips, err := bootstrapIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	chosen := ips[0]
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			chosen = ip
			break
		}
	}
	return &net.UDPAddr{IP: chosen.IP, Zone: chosen.Zone, Port: port}, nil
}
