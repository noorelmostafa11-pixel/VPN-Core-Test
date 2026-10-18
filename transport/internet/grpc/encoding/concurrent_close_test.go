package encoding

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type closeGate struct {
	ctx                         context.Context
	started, release, closeSend chan struct{}
	active                      atomic.Bool
	closes                      atomic.Int32
	overlap                     atomic.Bool
}

func (g *closeGate) Context() context.Context { return g.ctx }
func (g *closeGate) SendMsg(any) error        { return nil }
func (g *closeGate) RecvMsg(any) error        { return io.EOF }
func (g *closeGate) send() error {
	g.active.Store(true)
	defer g.active.Store(false)
	close(g.started)
	<-g.ctx.Done()
	<-g.release
	return g.ctx.Err()
}

func (g *closeGate) CloseSend() error {
	if g.active.Load() {
		g.overlap.Store(true)
	}
	if g.closes.Add(1) == 1 {
		close(g.closeSend)
	}
	return nil
}

type gatedHunk struct{ *closeGate }

func (h gatedHunk) Send(*Hunk) error     { return h.send() }
func (h gatedHunk) Recv() (*Hunk, error) { return nil, io.EOF }

type gatedMultiHunk struct{ *closeGate }

func (h gatedMultiHunk) Send(*MultiHunk) error     { return h.send() }
func (h gatedMultiHunk) Recv() (*MultiHunk, error) { return nil, io.EOF }

func TestConcurrentGRPCSendClose(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "gun", true: "multi"}[multi], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			gate := &closeGate{ctx: ctx, started: make(chan struct{}), release: make(chan struct{}), closeSend: make(chan struct{})}
			var write func()
			var closer io.Closer
			if multi {
				h := NewMultiHunkReadWriter(gatedMultiHunk{gate}, cancel)
				closer = h
				write = func() { h.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("data"))}) }
			} else {
				h := NewHunkReadWriter(gatedHunk{gate}, cancel)
				closer = h
				write = func() { h.Write([]byte("data")) }
			}
			writeDone, closeDone := make(chan struct{}), make(chan struct{})
			go func() { write(); close(writeDone) }()
			<-gate.started
			go func() { closer.Close(); close(closeDone) }()
			<-ctx.Done() // Close has reached cancellation while Send is blocked.
			select {
			case <-gate.closeSend:
				gate.overlap.Store(true)
			case <-time.After(20 * time.Millisecond):
			}
			close(gate.release)
			for _, done := range []chan struct{}{writeDone, closeDone} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("close did not unblock and join")
				}
			}
			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() { defer wg.Done(); closer.Close() }()
			}
			wg.Wait()
			if gate.overlap.Load() || gate.closes.Load() != 1 {
				t.Fatal("CloseSend overlapped Send or ran repeatedly", gate.closes.Load())
			}
		})
	}
}
