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

var socketHooks struct {
	sync.RWMutex
	protect, resolve, user uintptr
}

//export vpn_socket_set_hooks
func vpn_socket_set_hooks(protect, resolve, user C.uintptr_t) {
	socketHooks.Lock()
	defer socketHooks.Unlock()
	socketHooks.protect, socketHooks.resolve, socketHooks.user = uintptr(protect), uintptr(resolve), uintptr(user)
}

func socketControl(ctx context.Context, _, _ string, raw syscall.RawConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var denied bool
	err := raw.Control(func(fd uintptr) {
		socketHooks.RLock()
		defer socketHooks.RUnlock()
		if socketHooks.protect != 0 {
			denied = C.invoke_protect(C.uintptr_t(socketHooks.protect), C.int64_t(fd), C.uintptr_t(socketHooks.user)) != 1
		}
	})
	if err != nil {
		return err
	}
	if denied {
		return providerError(453)
	}
	return nil
}

func bootstrapIPs(ctx context.Context, hostname string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	socketHooks.RLock()
	if socketHooks.resolve != 0 {
		host := append([]byte(hostname), 0)
		out := make([]byte, 4096)
		n := int(C.invoke_resolve(C.uintptr_t(socketHooks.resolve), (*C.char)(unsafe.Pointer(&host[0])), (*C.char)(unsafe.Pointer(&out[0])), C.int(len(out)), C.uintptr_t(socketHooks.user)))
		socketHooks.RUnlock()
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
	protected := socketHooks.protect != 0
	socketHooks.RUnlock()
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
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	socketHooks.RLock()
	custom := socketHooks.protect != 0 || socketHooks.resolve != 0
	socketHooks.RUnlock()
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
	socketHooks.RLock()
	custom := socketHooks.protect != 0 || socketHooks.resolve != 0
	socketHooks.RUnlock()
	if !custom {
		return net.ResolveUDPAddr("udp", address)
	}
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
