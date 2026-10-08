package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHookLeaseDrainDoesNotHoldRegistryLock(t *testing.T) {
	vpn_socket_start()
	_, release, ok := acquireHooks()
	if !ok {
		t.Fatal("initial lease rejected")
	}
	finished := make(chan struct{})
	go func() { vpn_socket_set_hooks(0, 0, 0); close(finished) }()
	deadline := time.Now().Add(time.Second)
	for {
		socketHooks.Lock()
		changing := socketHooks.changing
		socketHooks.Unlock()
		if changing {
			break
		}
		if time.Now().After(deadline) {
			release()
			t.Fatal("setter did not begin drain")
		}
		time.Sleep(time.Millisecond)
	}
	if _, done, accepted := acquireHooks(); accepted {
		done()
		release()
		t.Fatal("new work accepted during drain")
	}
	// Cancel can still acquire the registry lock while the setter waits.
	cancelled := make(chan struct{})
	go func() { vpn_socket_cancel(); close(cancelled) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		release()
		t.Fatal("cancel blocked by registry lock")
	}
	select {
	case <-finished:
		release()
		t.Fatal("setter returned with an active lease")
	default:
	}
	release()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("lease did not drain")
	}
	vpn_socket_start()
}

func TestUDPBootstrapHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, address := range []string{"127.0.0.1:443", "bootstrap.invalid:443"} {
		if _, err := outboundUDPAddress(ctx, address); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: %v", address, err)
		}
	}
}
