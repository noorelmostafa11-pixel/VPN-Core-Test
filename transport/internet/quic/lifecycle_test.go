package quic

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestForkLegacyQUICActiveCancellationAndDeadlines(t *testing.T) {
	accepted := make(chan stat.Connection, 1)
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}}
	listener, err := Listen(context.Background(), xnet.LocalHostIP, 0, settings, func(conn stat.Connection) { accepted <- conn })
	if err != nil {
		t.Fatal(err)
	}
	l := listener.(*Listener)
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := Dial(ctx, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(l.Addr().(*net.UDPAddr).Port)), settings)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x51}); err != nil {
		t.Fatal(err)
	}
	var server stat.Connection
	select {
	case server = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("stream not advertised")
	}
	defer server.Close()
	if _, err := io.ReadFull(server, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read deadline ignored")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("read did not time out", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := server.Write([]byte("r")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(conn, got); err != nil || got[0] != 'r' {
		t.Fatal("read deadline not renewable", err)
	}
	writing := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 8<<20)); writing <- err }()
	// Reading one byte of this large upload proves the blocked writer started.
	if _, err := io.ReadFull(server, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-writing:
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal("write deadline ignored", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer remained blocked")
	}
	conn.SetWriteDeadline(time.Time{})
	reading := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); reading <- err }()
	cancel()
	select {
	case err := <-reading:
		if err == nil {
			t.Fatal("canceled read succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("context did not close owned session")
	}
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() { defer group.Done(); l.Close() }()
	}
	joined := make(chan struct{})
	go func() { group.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent close did not join")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.connections) != 0 {
		t.Fatal("closed listener retained sessions")
	}
}

func TestForkLegacyQUICHandshakeCancellation(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := Dial(ctx, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(blackhole.LocalAddr().(*net.UDPAddr).Port)), &internet.MemoryStreamConfig{ProtocolSettings: &Config{}})
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	blackhole.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _, err := blackhole.ReadFrom(make([]byte, 65536)); err != nil || n < 1200 {
		t.Fatal("fault did not reach QUIC Initial", n, err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC handshake ignored cancellation")
	}
}
