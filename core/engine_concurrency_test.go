package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type blockingCloser struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *blockingCloser) Close() error {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return nil
}

func TestConcurrentCloseWaitsAndUnlistensBeforeHooksRetire(t *testing.T) {
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	cfg.ListenPort = 0
	e, _ := NewEngine(context.Background(), cfg, Hooks{})
	a, err := e.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	b := &blockingCloser{entered: make(chan struct{}), release: make(chan struct{})}
	e.track(b)
	var release sync.Once
	defer release.Do(func() { close(b.release) })
	closed := make(chan struct{}, 2)
	go func() { e.Close(); closed <- struct{}{} }()
	<-b.entered
	go func() { e.Close(); closed <- struct{}{} }()
	select {
	case <-closed:
		t.Fatal("Close returned before resource retirement")
	case <-time.After(20 * time.Millisecond):
	}
	if c, err := net.DialTimeout("tcp", a.String(), 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener remained open during slow cleanup")
	}
	release.Do(func() { close(b.release) })
	for i := 0; i < 2; i++ {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not join")
		}
	}
}

type untrackingCloser struct {
	engine *Engine
	done   chan struct{}
}

func (c *untrackingCloser) Close() error { c.engine.untrack(c); close(c.done); return nil }
func TestRejectedResourceCanUntrackDuringClose(t *testing.T) {
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	e, _ := NewEngine(context.Background(), cfg, Hooks{})
	e.Close()
	c := &untrackingCloser{engine: e, done: make(chan struct{})}
	go func() { e.track(c) }()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("rejected closer deadlocked on engine lock")
	}
}

func socksOracleConn(address string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	request := []byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 10, 1, 187}
	if err = writeAll(c, request[:3]); err == nil {
		var greeting [2]byte
		_, err = io.ReadFull(c, greeting[:])
		if err == nil && greeting != [2]byte{5, 0} {
			err = fmt.Errorf("SOCKS authentication: %x", greeting)
		}
	}
	if err == nil {
		err = writeAll(c, request[3:])
	}
	if err == nil {
		var response [10]byte
		_, err = io.ReadFull(c, response[:])
		if err == nil && response[1] != 0 {
			err = fmt.Errorf("SOCKS reply: %d", response[1])
		}
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func awaitActive(t *testing.T, e *Engine, n uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for e.Stats().Active != n {
		if time.Now().After(deadline) {
			t.Fatalf("active connections: %+v, want %d", e.Stats(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestConcurrentSOCKSAbovePreviousLimit(t *testing.T) {
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	cfg.ListenPort = 0
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	const count = 96
	ready := make(chan error, count)
	finished := make(chan error, count)
	begin := make(chan struct{})
	for i := 0; i < count; i++ {
		go func(i int) {
			c, err := socksOracleConn(a.String())
			ready <- err
			if err != nil {
				finished <- err
				return
			}
			defer c.Close()
			<-begin
			payload := bytes.Repeat([]byte{byte(i)}, 8192)
			for round := 0; round < 4 && err == nil; round++ {
				err = writeAll(c, payload)
				b := make([]byte, len(payload))
				if err == nil {
					_, err = io.ReadFull(c, b)
				}
				if err == nil && !bytes.Equal(b, payload) {
					err = fmt.Errorf("flow %d payload changed", i)
				}
			}
			finished <- err
		}(i)
	}
	var first error
	for i := 0; i < count; i++ {
		if err := <-ready; err != nil && first == nil {
			first = err
		}
	}
	active := e.Stats().Active
	close(begin)
	for i := 0; i < count; i++ {
		if err := <-finished; err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		t.Fatal(first)
	}
	if active != count {
		t.Fatalf("only %d of %d flows stayed open", active, count)
	}
	awaitActive(t, e, 0)
	if e.Stats().Rejected != 0 {
		t.Fatalf("unexpected rejection: %+v", e.Stats())
	}
}

func TestConnectionLimitRecoversAfterClose(t *testing.T) {
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	cfg.ListenPort = 0
	cfg.MaxConnections = 2
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	first, err := socksOracleConn(a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := socksOracleConn(a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	third, err := net.DialTimeout("tcp", a.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	third.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = third.Read(b[:]); err == nil {
		t.Fatal("overloaded flow stayed open")
	}
	third.Close()
	deadline := time.After(time.Second)
	for {
		select {
		case ev := <-e.Events():
			if ev.ReasonCode == "CONNECTION_LIMIT" {
				if ev.Active != 2 || ev.Limit != 2 || ev.Phase != "ADMISSION_FAILED" {
					t.Fatalf("incomplete overload diagnostic: %+v", ev)
				}
				first.Close()
				awaitActive(t, e, 1)
				c, err := socksOracleConn(a.String())
				if err != nil {
					t.Fatal(err)
				}
				c.Close()
				return
			}
		case <-deadline:
			t.Fatal("missing overload diagnostic")
		}
	}
}

func TestIdleCloseHasTransferSummary(t *testing.T) {
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	cfg.ListenPort = 0
	cfg.IdleTimeout = 100 * time.Millisecond
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.StartSOCKS()
	if err != nil {
		t.Fatal(err)
	}
	c, err := socksOracleConn(a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("abc"))
	var b [3]byte
	if _, err = io.ReadFull(c, b[:]); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err = c.Read(one[:]); err == nil {
		t.Fatal("idle connection stayed open")
	}
	deadline := time.After(time.Second)
	for {
		select {
		case ev := <-e.Events():
			if ev.Event == "failure" {
				t.Fatalf("normal idle retirement reported as failure: %+v", ev)
			}
			if ev.Event == "closed" {
				if ev.ReasonCode != "IDLE_TIMEOUT" || ev.Uploaded != 3 || ev.Downloaded != 3 || ev.DurationMS < 100 {
					t.Fatalf("bad transfer summary: %+v", ev)
				}
				return
			}
		case <-deadline:
			t.Fatal("missing close event")
		}
	}
}

func TestActivityInOneDirectionKeepsFlowAlive(t *testing.T) {
	cfg := defaults()
	cfg.Protocol, cfg.Server, cfg.Port, cfg.Security, cfg.Transport = "vless", "127.0.0.1", 443, "none", "raw"
	cfg.IdleTimeout = 100 * time.Millisecond
	e, _ := NewEngine(context.Background(), cfg, Hooks{})
	defer e.Close()
	client, reader := net.Pipe()
	server, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() { done <- e.relay(client, server) }()
	readError := make(chan error, 1)
	go func() { b := make([]byte, 10); _, err := io.ReadFull(reader, b); readError <- err }()
	for i := 0; i < 10; i++ {
		if _, err := writer.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := <-readError; err != nil {
		t.Fatal(err)
	}
	writer.Close()
	reader.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not join")
	}
}
