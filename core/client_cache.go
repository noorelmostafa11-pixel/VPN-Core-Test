package core

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

type runtimeKey struct{}
type cachedClient struct {
	client    io.Closer
	err       error
	ready     chan struct{}
	refs      int
	used      time.Time
	closeOnce sync.Once
}

func (e *cachedClient) close() {
	e.closeOnce.Do(func() {
		if e.client != nil {
			e.client.Close()
		}
	})
}

type clientCache struct {
	mu        sync.Mutex
	entries   map[string]*cachedClient
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	workers   sync.WaitGroup
	done      chan struct{}
	closeDone chan struct{}
}
type clientLease struct {
	entry *cachedClient
	cache *clientCache
	once  sync.Once
}

func (l *clientLease) Close() error {
	l.once.Do(func() { l.cache.mu.Lock(); l.entry.refs--; l.entry.used = time.Now(); l.cache.mu.Unlock() })
	return nil
}
func newClientCache(ctx context.Context) *clientCache {
	ctx, cancel := context.WithCancel(ctx)
	c := &clientCache{entries: map[string]*cachedClient{}, ctx: ctx, cancel: cancel, done: make(chan struct{}), closeDone: make(chan struct{})}
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.retireIdle(30 * time.Second)
			}
		}
	}()
	return c
}
func (c *clientCache) retireIdle(age time.Duration) {
	c.mu.Lock()
	var list []*cachedClient
	for key, entry := range c.entries {
		if entry.refs == 0 && entry.client != nil && time.Since(entry.used) >= age {
			delete(c.entries, key)
			list = append(list, entry)
		}
	}
	c.mu.Unlock()
	for _, client := range list {
		client.close()
	}
}
func (c *clientCache) get(ctx context.Context, key string, open func(context.Context) (io.Closer, error)) (*clientLease, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, context.Canceled
	}
	entry := c.entries[key]
	if entry != nil && entry.client != nil {
		if live, ok := entry.client.(interface{ IsClosed() bool }); ok && live.IsClosed() {
			delete(c.entries, key)
			old := entry
			c.workers.Add(1)
			c.mu.Unlock()
			old.close()
			c.workers.Done()
			return c.get(ctx, key, open)
		}
	}
	creator := entry == nil
	var retire *cachedClient
	if creator {
		wireFull := false
		if strings.HasPrefix(key, "wireguard:") {
			count := 0
			for k := range c.entries {
				if strings.HasPrefix(k, "wireguard:") {
					count++
				}
			}
			wireFull = count >= 8
		}
		if len(c.entries) >= 64 || wireFull {
			var oldestKey string
			var oldest *cachedClient
			for k, v := range c.entries {
				if wireFull && !strings.HasPrefix(k, "wireguard:") {
					continue
				}
				if v.refs == 0 && v.client != nil && (oldest == nil || v.used.Before(oldest.used)) {
					oldestKey, oldest = k, v
				}
			}
			if oldest == nil {
				c.mu.Unlock()
				return nil, errors.New("PROTOCOL_CLIENT_LIMIT")
			}
			delete(c.entries, oldestKey)
			retire = oldest
		}
		entry = &cachedClient{ready: make(chan struct{}), used: time.Now()}
		c.entries[key] = entry
		c.workers.Add(1)
	}
	entry.refs++
	lease := &clientLease{entry: entry, cache: c}
	c.mu.Unlock()
	if retire != nil {
		retire.close()
	}
	if creator {
		connect, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(c.ctx, cancel)
		client, err := open(connect)
		stop()
		cancel()
		c.mu.Lock()
		closed := c.closed
		if closed && err == nil {
			err = context.Canceled
		}
		entry.client, entry.err = client, err
		if err != nil {
			delete(c.entries, key)
		}
		close(entry.ready)
		c.mu.Unlock()
		if err != nil && client != nil {
			entry.close()
		}
		c.workers.Done()
	}
	select {
	case <-ctx.Done():
		lease.Close()
		return nil, ctx.Err()
	case <-entry.ready:
		if entry.err != nil {
			lease.Close()
			return nil, entry.err
		}
		return lease, nil
	}
}
func (c *clientCache) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		<-c.closeDone
		return nil
	}
	c.closed = true
	c.cancel()
	var list []*cachedClient
	for _, entry := range c.entries {
		if entry.client != nil {
			list = append(list, entry)
		}
	}
	c.mu.Unlock()
	for _, client := range list {
		client.close()
	}
	c.workers.Wait()
	<-c.done
	close(c.closeDone)
	return nil
}
func engineClientCache(ctx context.Context) *clientCache {
	e, _ := ctx.Value(runtimeKey{}).(*Engine)
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	if e.clients == nil {
		e.clients = newClientCache(e.ctx)
		e.closers[e.clients] = true
	}
	return e.clients
}
