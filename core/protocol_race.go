package core

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Protocol handshakes, rather than UDP socket creation, determine reachability.
// At most two attempts run together. All losing attempts are canceled and joined.
func raceProtocolClients(ctx context.Context, ips []net.IPAddr, open func(context.Context, net.IPAddr) (io.Closer, error)) (io.Closer, error) {
	var v4, v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	attempt := func(ctx context.Context, list []net.IPAddr) (io.Closer, error) {
		var last error = errors.New("BOOTSTRAP_DNS_FAILED")
		for i, ip := range list {
			if i == 16 {
				break
			}
			c, err := open(ctx, ip)
			if err == nil {
				return c, nil
			}
			last = err
			if ctx.Err() != nil || terminalRouteError(err) {
				break
			}
		}
		return nil, last
	}
	if len(v4) == 0 {
		return attempt(ctx, v6)
	}
	if len(v6) == 0 {
		return attempt(ctx, v4)
	}
	race, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		client io.Closer
		err    error
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	launch := func(list []net.IPAddr) {
		workers.Add(1)
		go func() { defer workers.Done(); c, err := attempt(race, list); results <- result{c, err} }()
	}
	launch(v4)
	delay := time.NewTimer(250 * time.Millisecond)
	defer delay.Stop()
	started, received := 1, 0
	var winner io.Closer
	var last error
	for winner == nil && received < 2 {
		select {
		case r := <-results:
			received++
			winner, last = r.client, r.err
			if r.err != nil && terminalRouteError(r.err) {
				cancel()
				received = 2
				break
			}
			if winner == nil && started == 1 {
				launch(v6)
				started++
			}
		case <-delay.C:
			if started == 1 {
				launch(v6)
				started++
			}
		case <-ctx.Done():
			last = ctx.Err()
			received = 2
		}
	}
	cancel()
	workers.Wait()
	for len(results) > 0 {
		r := <-results
		if r.client != nil {
			r.client.Close()
		}
		if r.err != nil && terminalRouteError(r.err) && !errors.Is(r.err, context.Canceled) {
			last = r.err
			if winner != nil {
				winner.Close()
				winner = nil
			}
		}
	}
	if winner != nil && ctx.Err() != nil {
		winner.Close()
		return nil, ctx.Err()
	}
	return winner, last
}
