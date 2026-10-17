package http

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/transport/internet/reality"
)

// The pinned REALITY server deliberately skips normal TLS ALPN selection.
// An authenticated empty ALPN uses this explicitly selected H2 transport's
// preface, like upstream XHTTP/gRPC. An explicit non-H2 ALPN is never accepted.
// Ordinary TLS retains its separate, mandatory h2 negotiation check.
func realityHTTP2ALPN(protocol string) bool { return protocol == "" || protocol == "h2" }

// The pinned server waits in five-second steps for its target detector. Finish
// that prerequisite before accepting H2 handshakes with four-second deadlines,
// rather than making the first real client a startup probe/retry candidate.
func waitRealityTarget(ctx context.Context, config *goreality.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	goreality.DetectPostHandshakeRecordsLens(config)
	startup, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		ready := true
		for name := range config.ServerNames {
			for alpn := range 3 {
				value, ok := goreality.GlobalPostHandshakeRecordsLens.Load(config.Dest + " " + name + " " + strconv.Itoa(alpn))
				_, complete := value.([]int)
				ready = ready && ok && complete
			}
		}
		if ready {
			return nil
		}
		select {
		case <-tick.C:
		case <-startup.Done():
			return fmt.Errorf("legacy HTTP/2 REALITY target initialization: %w", startup.Err())
		}
	}
}

// REALITY's server owns the target until its handshake/fallback completes.
// Bound that target too: closing only the inbound socket cannot join a worker
// blocked reading a silent target. This applies only to the added H2 pairing.
func boundedRealityConfig(ctx context.Context, config *reality.Config) *goreality.Config {
	security := config.GetREALITYConfig()
	dial := security.DialContext
	security.DialContext = func(handshake context.Context, network, address string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(handshake, 4*time.Second)
		defer cancel()
		target, err := dial(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		if err := target.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			target.Close()
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { target.Close() })
		return &realityTargetConn{Conn: target, stop: stop}, nil
	}
	return security
}

type realityTargetConn struct {
	net.Conn
	stop func() bool
}

func (c *realityTargetConn) Close() error { c.stop(); return c.Conn.Close() }

func (c *realityTargetConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}
