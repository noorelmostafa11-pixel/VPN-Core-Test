package core_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type nodeSSHDialer struct {
	count   atomic.Int32
	written atomic.Int64
	read    atomic.Int64
	closed  atomic.Bool
}

type nodeSSHTrackedConn struct {
	net.Conn
	dialer *nodeSSHDialer
}

func (c *nodeSSHTrackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.dialer.read.Add(int64(n))
	return n, err
}

func (c *nodeSSHTrackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.dialer.written.Add(int64(n))
	return n, err
}
func (c *nodeSSHTrackedConn) Close() error { c.dialer.closed.Store(true); return c.Conn.Close() }

func (d *nodeSSHDialer) Dial(ctx context.Context, target xnet.Destination) (stat.Connection, error) {
	d.count.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.NetAddr())
	if err != nil {
		return nil, err
	}
	return &nodeSSHTrackedConn{Conn: conn, dialer: d}, nil
}

func (*nodeSSHDialer) DestIpAddress() xnet.IP                                { return nil }
func (*nodeSSHDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func nodeSSHClientObject(t *testing.T, peer *nodeSSHPeer) proxy.Outbound {
	t.Helper()
	instance := nodeSSHInstance(t, peer, "json", "synthetic", peer.pin, "", "")
	_, port, _ := net.SplitHostPort(peer.address)
	n, _ := strconv.Atoi(port)
	var config conf.SSHClientConfig
	data, _ := json.Marshal(map[string]any{"address": "127.0.0.1", "port": n, "username": "user", "password": "synthetic", "hostKey": peer.pin})
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	message, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	object, err := core.CreateObject(instance, message)
	if err != nil {
		t.Fatal(err)
	}
	return object.(proxy.Outbound)
}

func nodeSSHWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("SSH Process did not return with its workers joined")
		return nil
	}
}

func TestSSHOutboundCancellationJoinsBlockedWorkers(t *testing.T) {
	for _, mode := range []string{"stall-handshake", "stall-open", "block-upload", "block-download"} {
		t.Run(mode, func(t *testing.T) {
			peer := newNodeSSHPeer(t, mode, nil)
			client := nodeSSHClientObject(t, peer)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: xnet.TCPDestination(xnet.LocalHostIP, 443)}})
			uplink, writer := pipe.New(pipe.WithSizeLimit(32768))
			reader, downlink := pipe.New(pipe.WithSizeLimit(32768))
			defer writer.Interrupt()
			defer reader.Interrupt()
			dialer := &nodeSSHDialer{}
			done := make(chan error, 1)
			go func() { done <- client.Process(ctx, &transport.Link{Reader: uplink, Writer: downlink}, dialer) }()
			want := "open"
			if mode == "stall-handshake" {
				want = "accepted"
			}
			for {
				select {
				case stage := <-peer.stages:
					if stage == want {
						goto reached
					}
				case <-time.After(3 * time.Second):
					cancel()
					nodeSSHWait(t, done)
					t.Fatal("SSH fault stage did not fire")
				}
			}
		reached:
			var writeDone chan error
			if mode == "block-upload" || mode == "block-download" {
				buffered := &buf.BufferedReader{Reader: reader}
				greeting := make([]byte, len(nodeSSHGreeting))
				if _, err := buffered.Read(greeting); err != nil {
					cancel()
					nodeSSHWait(t, done)
					t.Fatal(err)
				}
				if !bytes.Equal(greeting, nodeSSHGreeting) {
					t.Fatal("SSH fault handshake did not complete")
				}
				if mode == "block-upload" {
					writeDone = make(chan error, 1)
					go func() {
						writeDone <- writer.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte{0x33}, 8*1024*1024)))
					}()
				}
				// Confirm payload pressure reached the actual SSH transport.
				// The peer never drains upload; this side never drains download.
				timeout := time.NewTimer(3 * time.Second)
				tick := time.NewTicker(5 * time.Millisecond)
				for mode == "block-upload" && dialer.written.Load() < 2*1024*1024 || mode == "block-download" && dialer.read.Load() < 128*1024 {
					select {
					case <-tick.C:
					case <-timeout.C:
						cancel()
						nodeSSHWait(t, done)
						t.Fatal("SSH backpressure fault did not fire")
					}
				}
				tick.Stop()
				timeout.Stop()
			}
			cancel()
			if err := nodeSSHWait(t, done); err == nil {
				t.Fatal("canceled SSH flow reported success")
			}
			if writeDone != nil {
				select {
				case <-writeDone:
				case <-time.After(time.Second):
					t.Fatal("SSH blocked uplink producer did not join")
				}
			}
			if dialer.count.Load() != 1 {
				t.Fatal("SSH retried a failed/canceled flow")
			}
			if !dialer.closed.Load() {
				t.Fatal("SSH Process returned without closing its owned transport")
			}
		})
	}
}

func TestSSHOutboundHalfClosePreservesDelayedResponse(t *testing.T) {
	peer := newNodeSSHPeer(t, "half-close", nil)
	client := nodeSSHClientObject(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: xnet.TCPDestination(xnet.LocalHostIP, 443)}})
	uplink, writer := pipe.New()
	reader, downlink := pipe.New()
	defer writer.Interrupt()
	defer reader.Interrupt()
	done := make(chan error, 1)
	go func() {
		done <- client.Process(ctx, &transport.Link{Reader: uplink, Writer: downlink}, &nodeSSHDialer{})
	}()
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, nodeSSHBody)); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	got := &buf.BufferedReader{Reader: reader}
	var output bytes.Buffer
	if _, err := output.ReadFrom(got); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, nodeSSHGreeting...), nodeSSHBody...)
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatal("SSH half-close truncated delayed server response")
	}
	if err := nodeSSHWait(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSSHOutboundRejectsUDPBeforeDial(t *testing.T) {
	peer := newNodeSSHPeer(t, "echo", nil)
	client := nodeSSHClientObject(t, peer)
	dialer := &nodeSSHDialer{}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.UDPDestination(xnet.LocalHostIP, 443)}})
	if err := client.Process(ctx, &transport.Link{}, dialer); err == nil || dialer.count.Load() != 0 || peer.accepts.Load() != 0 {
		t.Fatal("SSH UDP was aliased to TCP")
	}
}
