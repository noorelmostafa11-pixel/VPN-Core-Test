package core

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
)

type ownedConn struct {
	net.Conn
	e      *Engine
	once   sync.Once
	finish func()
}

func (c *ownedConn) Close() error {
	var err error
	c.once.Do(func() { c.finish(); err = c.Conn.Close(); c.e.untrack(c); c.e.release() })
	return err
}
func (c *ownedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (c *ownedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.e.down.Add(uint64(n))
	return n, err
}
func (c *ownedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.e.up.Add(uint64(n))
	return n, err
}

// DialContext applies this engine's routing, protection hooks and connection
// budget. Engine.Close owns the returned stream. Caller metadata is retained.
func (e *Engine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("SDK_NETWORK_UNSUPPORTED")
	}
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("DESTINATION_PORT")
	}
	e.mu.Lock()
	if e.closed || e.ctx.Err() != nil {
		e.mu.Unlock()
		return nil, net.ErrClosed
	}
	e.workers.Add(1)
	e.mu.Unlock()
	defer e.workers.Done()
	if !e.acquire() {
		return nil, errors.New("CONNECTION_LIMIT")
	}
	h, _ := e.ctx.Value(hooksKey{}).(Hooks)
	flow, cancel := context.WithCancel(WithHooks(ctx, h))
	stopParent := context.AfterFunc(e.ctx, cancel)
	finish := func() { stopParent(); cancel() }
	conn, err := e.dialTCP(flow, host, port)
	if err != nil {
		finish()
		e.release()
		return nil, err
	}
	owned := &ownedConn{Conn: conn, e: e, finish: finish}
	if !e.track(owned) {
		return nil, net.ErrClosed
	}
	context.AfterFunc(flow, func() { owned.Close() })
	e.accepted.Add(1)
	return owned, nil
}
