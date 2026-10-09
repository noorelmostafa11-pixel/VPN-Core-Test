package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// A blocking transport makes the race boundary deterministic; independent
// encrypted wire cases are in tests/test_tls_write_state.py.
type blockedWriteStream struct {
	entered, release, closed chan struct{}
	once                     sync.Once
	closeError               error
}

func (*blockedWriteStream) Read([]byte) (int, error) { return 0, errors.New("unused read") }
func (s *blockedWriteStream) Write(b []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return len(b), nil
}
func (s *blockedWriteStream) CloseWrite() error { close(s.closed); return s.closeError }

func TestSessionSerializesLocalShutdownWithWrite(t *testing.T) {
	u := &blockedWriteStream{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	s := &session{conn: newMemoryConn(), stream: u, state: 1, version: 0x0304}
	written := make(chan int, 1)
	go func() { written <- s.write([]byte("in-flight data")) }()
	<-u.entered
	shutdownStarted, stopped := make(chan struct{}), make(chan int, 1)
	go func() { close(shutdownStarted); stopped <- s.shutdown() }()
	<-shutdownStarted
	select {
	case <-u.closed:
		t.Fatal("CloseWrite overtook the in-flight write")
	case <-time.After(30 * time.Millisecond):
	}
	close(u.release)
	if <-written != len("in-flight data") || <-stopped != 0 {
		t.Fatal("in-flight write or serialized CloseWrite failed")
	}
	if s.write([]byte("late")) != -1 || s.state != 1 {
		t.Fatal("a local late write was accepted or poisoned the remaining read direction")
	}
	if s.shutdown() != 0 {
		t.Fatal("repeated shutdown must be idempotent")
	}
}

func TestSessionFailedShutdownCannotReenableWriteOrReplaceFirstError(t *testing.T) {
	u := &blockedWriteStream{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), closeError: providerError(318)}
	s := &session{conn: newMemoryConn(), stream: u, state: 1, version: 0x0304}
	if s.shutdown() != -1 || s.state != -1 || s.code != 318 {
		t.Fatal("CloseWrite error was not terminal")
	}
	if s.write([]byte("late")) != -1 || s.shutdown() != -1 {
		t.Fatal("failed session became writable or shutdown succeeded")
	}
	s.fail(305)
	if s.code != 318 {
		t.Fatal("later failure replaced the first TLS error")
	}
}
