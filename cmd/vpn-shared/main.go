//go:build cgo

// Optional C ABI compatibility shell. All protocol and packet work stays in Go.
package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef int (*vpn_core_socket_protector)(int64_t, void*);
typedef int (*vpn_core_resolver)(const char*, char*, int, void*);
static int call_protect(uintptr_t callback, int64_t fd, uintptr_t user) { return ((vpn_core_socket_protector)callback)(fd,(void*)user); }
static int call_resolve(uintptr_t callback, const char* host, char* out, int capacity, uintptr_t user) { return ((vpn_core_resolver)callback)(host,out,capacity,(void*)user); }
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

var runLock sync.Mutex
var current = struct {
	sync.Mutex
	cancel context.CancelFunc
	events [][]byte
}{}
var state atomic.Int32
var port atomic.Uint32
var pending atomic.Uint32
var callbackWorkers sync.WaitGroup
var resolverSlots = make(chan struct{}, 16)
var version = C.CString(core.Version)

func callbacks(protect, resolve, user uintptr) core.Hooks {
	var h core.Hooks
	if protect != 0 {
		h.Protect = func(ctx context.Context, fd int64) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			pending.Add(1)
			defer pending.Add(^uint32(0))
			if C.call_protect(C.uintptr_t(protect), C.int64_t(fd), C.uintptr_t(user)) != 1 {
				return errors.New("SOCKET_PROTECTION_FAILED")
			}
			return ctx.Err()
		}
	}
	if resolve != 0 {
		h.Resolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			select {
			case resolverSlots <- struct{}{}:
			default:
				return nil, errors.New("DNS_CALLBACK_BUSY")
			}
			type reply struct {
				ips []net.IPAddr
				err error
			}
			result := make(chan reply, 1)
			pending.Add(1)
			callbackWorkers.Add(1)
			go func() {
				runtime.LockOSThread() // Exit retires this callback-owned thread.
				defer callbackWorkers.Done()
				defer pending.Add(^uint32(0))
				defer func() { <-resolverSlots }()
				name := C.CString(host)
				defer C.free(unsafe.Pointer(name))
				data := C.malloc(65536)
				if data == nil {
					result <- reply{err: errors.New("BOOTSTRAP_DNS_FAILED")}
					return
				}
				defer C.free(data)
				n := int(C.call_resolve(C.uintptr_t(resolve), name, (*C.char)(data), 65536, C.uintptr_t(user)))
				if n < 0 || n >= 65536 {
					result <- reply{err: errors.New("BOOTSTRAP_DNS_FAILED")}
					return
				}
				var ips []net.IPAddr
				for _, item := range strings.Fields(string(C.GoBytes(data, C.int(n)))) {
					ip := net.ParseIP(item)
					if ip == nil {
						result <- reply{err: errors.New("BOOTSTRAP_DNS_FAILED")}
						return
					}
					ips = append(ips, net.IPAddr{IP: ip})
				}
				if len(ips) == 0 {
					result <- reply{err: errors.New("BOOTSTRAP_DNS_FAILED")}
					return
				}
				result <- reply{ips: ips}
			}()
			select {
			case <-ctx.Done():
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, errors.New("BOOTSTRAP_DNS_TIMEOUT")
				}
				return nil, ctx.Err()
			case r := <-result:
				return r.ips, r.err
			}
		}
	}

	return h
}
func runConfig(path string, h core.Hooks, fd, mtu int, name string) int {
	if !runLock.TryLock() {
		return 2
	}
	defer runLock.Unlock()
	state.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	current.Lock()
	current.cancel = cancel
	current.events = nil
	current.Unlock()
	defer func() {
		cancel()
		current.Lock()
		current.cancel = nil
		current.Unlock()
		callbackWorkers.Wait()
		port.Store(0)
		state.Store(0)
	}()
	cfg, err := core.ReadConfig(path)
	if err != nil {
		return 1
	}
	engine, err := core.NewEngine(ctx, cfg, h)
	if err != nil {
		return 1
	}
	defer engine.Close()
	var tunnel *core.Tunnel
	if fd >= 0 || name != "" {
		var device core.PacketDevice
		if fd >= 0 {
			device, err = core.OpenTUNFD(fd, mtu)
		} else {
			device, _, err = core.OpenTUN(name, mtu)
		}
		if err != nil {
			return 1
		}
		tunnel, err = engine.StartTUN(device, mtu)
		if err != nil {
			device.Close()
			return 1
		}
	} else {
		a, e := engine.StartSOCKS()
		if e != nil {
			return 1
		}
		port.Store(uint32(a.(*net.TCPAddr).Port))
	}
	state.Store(2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case e := <-engine.Events():
				if e.Event == "ready" || e.Event == "closed" {
					continue
				}
				b, _ := json.Marshal(e)
				current.Lock()
				if len(current.events) >= 256 {
					current.events = current.events[1:]
				}
				current.events = append(current.events, b)
				current.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
	if tunnel == nil {
		<-ctx.Done()
	} else {
		select {
		case <-ctx.Done():
		case <-tunnel.Done():
		}
	}
	state.Store(3)
	engine.Close()
	cancel()
	<-done
	if tunnel != nil && tunnel.Err() != nil {
		return 1
	}
	return 0
}

//export vpn_core_version
func vpn_core_version() *C.char { return version }

//export vpn_core_abi_version
func vpn_core_abi_version() C.uint32_t { return 2 }

//export vpn_core_get_state
func vpn_core_get_state() C.int { return C.int(state.Load()) }

//export vpn_core_get_listen_port
func vpn_core_get_listen_port() C.uint16_t { return C.uint16_t(port.Load()) }

//export vpn_core_pending_callbacks
func vpn_core_pending_callbacks() C.uint32_t { return C.uint32_t(pending.Load()) }

//export vpn_core_stop
func vpn_core_stop() {
	current.Lock()
	cancel := current.cancel
	current.Unlock()
	if cancel != nil {
		state.Store(3)
		port.Store(0)
		cancel()
	}
}

//export vpn_core_read_event
func vpn_core_read_event(output *C.char, capacity C.uint32_t) C.int {
	current.Lock()
	defer current.Unlock()
	if len(current.events) == 0 {
		return 0
	}
	b := current.events[0]
	if output == nil || uint64(capacity) < uint64(len(b)+1) {
		return -C.int(len(b) + 1)
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(output)), len(b)+1)
	copy(data, b)
	data[len(b)] = 0
	current.events = current.events[1:]
	return C.int(len(b))
}

//export vpn_core_run_config
func vpn_core_run_config(path *C.char, protect C.uintptr_t, resolve C.uintptr_t, user C.uintptr_t) C.int {
	if path == nil {
		return 1
	}
	return C.int(runConfig(C.GoString(path), callbacks(uintptr(protect), uintptr(resolve), uintptr(user)), -1, 1500, ""))
}

//export vpn_core_run_tun_fd_config
func vpn_core_run_tun_fd_config(path *C.char, fd, mtu C.int, protect, resolve, user C.uintptr_t) C.int {
	if path == nil {
		return 1
	}
	return C.int(runConfig(C.GoString(path), callbacks(uintptr(protect), uintptr(resolve), uintptr(user)), int(fd), int(mtu), ""))
}

//export vpn_core_run_native_tun_config
func vpn_core_run_native_tun_config(path, name *C.char, mtu C.int, protect, resolve, user C.uintptr_t) C.int {
	if path == nil || name == nil {
		return 1
	}
	return C.int(runConfig(C.GoString(path), callbacks(uintptr(protect), uintptr(resolve), uintptr(user)), -1, int(mtu), C.GoString(name)))
}

//export vpn_core_run
func vpn_core_run(argc C.int, argv **C.char) C.int {
	if argc < 1 || argc > 64 || argv == nil {
		return 1
	}
	args := unsafe.Slice(argv, int(argc))
	path := ""
	for i := 1; i < len(args); i++ {
		if args[i] == nil {
			return 1
		}
		switch C.GoString(args[i]) {
		case "--config":
			i++
			if i == len(args) || args[i] == nil {
				return 1
			}
			path = C.GoString(args[i])
		case "--version":
			fmt.Println("vpn-core", core.Version)
			return 0
		case "--self-test", "--check-components":
			if core.SelfTest() != nil {
				return 1
			}
			return 0
		default:
			return 1
		}
	}
	if path == "" {
		return 1
	}
	return C.int(runConfig(path, core.Hooks{}, -1, 1500, ""))
}
func main() {}
