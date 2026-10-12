package core

import (
	"bytes"
	"context"
	"errors"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryDevice struct {
	in, out chan []byte
	stop    chan struct{}
	once    sync.Once
}

func (d *memoryDevice) ReadPacket(b []byte) (int, error) {
	select {
	case <-d.stop:
		return 0, net.ErrClosed
	case p := <-d.in:
		return copy(b, p), nil
	}
}
func (d *memoryDevice) WritePacket(b []byte) error {
	p := append([]byte{}, b...)
	select {
	case <-d.stop:
		return net.ErrClosed
	case d.out <- p:
		return nil
	}
}
func (d *memoryDevice) Close() error { d.once.Do(func() { close(d.stop) }); return nil }

// An independent minimal VLESS server validates the entire request, then echoes.
func vlessOracle(t *testing.T) (string, func()) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var peers []net.Conn
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			peers = append(peers, c)
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var h [18]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				if h[0] != 0 || h[17] != 0 {
					t.Error("bad VLESS header")
					return
				}
				var request [4]byte
				if _, e := io.ReadFull(c, request[:]); e != nil {
					return
				}
				if request[0] != 1 && request[0] != 2 {
					t.Error("bad command")
					return
				}
				size := 4
				if request[3] == 3 {
					size = 16
				} else if request[3] != 1 {
					t.Error("expected numeric TUN destination")
					return
				}
				addr := make([]byte, size)
				if _, e := io.ReadFull(c, addr); e != nil {
					return
				}
				if _, e := c.Write([]byte{0, 0}); e != nil {
					return
				}
				io.Copy(c, c)
			}()
		}
	}()
	uri := "vless://12345678-1234-4567-9234-567812345678@" + l.Addr().String() + "?security=none"
	return uri, func() {
		l.Close()
		<-stop
		mu.Lock()
		for _, c := range peers {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
}

func TestNativeTUNFlows(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, datagram := range []bool{false, true} {
			t.Run(itoa(boolInt(v6))+"/"+itoa(boolInt(datagram)), func(t *testing.T) {
				uri, stop := vlessOracle(t)
				defer stop()
				cfg, err := ParseURI(uri)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				engine, err := NewEngine(ctx, cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				device := &memoryDevice{in: make(chan []byte, 256), out: make(chan []byte, 256), stop: make(chan struct{})}
				tun, err := engine.StartTUN(device, 1500)
				if err != nil {
					t.Fatal(err)
				}
				defer tun.Close()
				client := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
				link := channel.New(256, 1500, "")
				defer link.Close()
				defer client.Close()
				if e := client.CreateNIC(1, link); e != nil {
					t.Fatal(e)
				}
				proto := ipv4.ProtocolNumber
				source := net.ParseIP("10.77.0.2").To4()
				destination := net.ParseIP("192.0.2.10").To4()
				bits := 32
				subnet := header.IPv4EmptySubnet
				if v6 {
					proto = ipv6.ProtocolNumber
					source = net.ParseIP("fd77::2").To16()
					destination = net.ParseIP("2001:db8::10").To16()
					bits = 128
					subnet = header.IPv6EmptySubnet
				}
				client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(source), PrefixLen: bits}}, stack.AddressProperties{})
				client.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
				var pumps sync.WaitGroup
				pumps.Add(2)
				go func() {
					defer pumps.Done()
					for {
						packet := link.ReadContext(ctx)
						if packet == nil {
							return
						}
						v := packet.ToView()
						p := append([]byte{}, v.AsSlice()...)
						v.Release()
						packet.DecRef()
						select {
						case device.in <- p:
						case <-ctx.Done():
							return
						}
					}
				}()
				go func() {
					defer pumps.Done()
					for {
						select {
						case b := <-device.out:
							p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
							link.InjectInbound(proto, p)
							p.DecRef()
						case <-ctx.Done():
							return
						}
					}
				}()
				defer func() { cancel(); pumps.Wait() }()
				target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(destination), Port: 443}
				var conn net.Conn
				if datagram {
					conn, err = gonet.DialUDP(client, nil, &target, proto)
				} else {
					conn, err = gonet.DialContextTCP(ctx, client, target, proto)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				payload := bytes.Repeat([]byte("native-tun-verified\x00\xff"), 100)
				if datagram {
					payload = payload[:1200]
				}
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				received := make([]byte, len(payload))
				if datagram {
					n, e := conn.Read(received)
					if e != nil || n != len(payload) {
						t.Fatalf("UDP read %d: %v", n, e)
					}
				} else {
					if _, err = io.ReadFull(conn, received); err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.Equal(payload, received) {
					t.Fatal("TUN payload mismatch")
				}
			})
		}
	}
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func TestSocketHooksFailClosed(t *testing.T) {
	cfg, _ := ParseURI("vless://12345678-1234-4567-9234-567812345678@127.0.0.1:1?security=none")
	for _, udp := range []bool{false, true} {
		ctx := WithHooks(context.Background(), Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
		var err error
		if udp {
			_, err = DialPacket(ctx, cfg, "example.test", 53)
		} else {
			_, err = Dial(ctx, cfg, "example.test", 443)
		}
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("SOCKET_PROTECTION_FAILED")) {
			t.Fatal(err)
		}
	}
	cfg.Server = "bootstrap.invalid"
	called := false
	ctx := WithHooks(context.Background(), Hooks{Resolve: func(context.Context, string) ([]net.IPAddr, error) { called = true; return nil, errors.New("denied") }})
	_, err := Dial(ctx, cfg, "example.test", 443)
	if !called || err == nil {
		t.Fatal("resolver failure was bypassed")
	}
}
func TestEngineStopAndRestart(t *testing.T) {
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	cfg.ListenPort = 0
	for i := 0; i < 10; i++ {
		e, err := NewEngine(context.Background(), cfg, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.StartSOCKS()
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Close(); err != nil {
			t.Fatal(err)
		}
		if e.Stats().Active != 0 {
			t.Fatal("leaked active flow")
		}
	}
}

func TestDefaultBootstrapDNSCannotBypassProtection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls atomic.Uint32
	ctx = WithHooks(ctx, Hooks{Protect: func(context.Context, int64) error { calls.Add(1); return errors.New("denied") }})
	_, err := bootstrapIPs(ctx, "bootstrap-protection-probe.invalid")
	if calls.Load() == 0 || err == nil || reasonCode(err) != "SOCKET_PROTECTION_FAILED" {
		t.Fatalf("default DNS bypassed protection: calls=%d err=%v", calls.Load(), err)
	}
}

func TestNativeUDPDownloadActivityKeepsFlowAlive(t *testing.T) {
	testNativeUDPActivityKeepsFlowAlive(t, false)
}
func TestNativeUDPUploadActivityKeepsFlowAlive(t *testing.T) {
	testNativeUDPActivityKeepsFlowAlive(t, true)
}
func testNativeUDPActivityKeepsFlowAlive(t *testing.T, uploadOnly bool) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 26)
		if _, err = io.ReadFull(c, header); err != nil {
			return
		}
		c.Write([]byte{0, 0})
		initial := make([]byte, 4)
		if _, err = io.ReadFull(c, initial); err != nil {
			return
		} // UDP length 2 + "go"
		if uploadOnly {
			for i := 1; i < 12; i++ {
				if _, err = io.ReadFull(c, initial); err != nil {
					return
				}
			}
			return
		}
		for i := 0; i < 12; i++ {
			if writeAll(c, []byte{0, 3, 'u', 'd', 'p'}) != nil {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	cfg, err := ParseURI("vless://12345678-1234-4567-9234-567812345678@" + l.Addr().String() + "?security=none")
	if err != nil {
		t.Fatal(err)
	}
	cfg.IdleTimeout = 150 * time.Millisecond
	cfg.NativeDNS = false // This fixture tests arbitrary datagrams, not DNS wire messages.
	e, _ := NewEngine(context.Background(), cfg, Hooks{})
	defer e.Close()
	tunnel := &Tunnel{engine: e, ctx: e.ctx}
	client, app := net.Pipe()
	defer app.Close()
	defer client.Close()
	flowDone := make(chan struct{})
	go func() { tunnel.udpFlow(client, "192.0.2.10", 53); close(flowDone) }()
	app.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = app.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if uploadOnly {
			if i > 0 {
				if _, err = app.Write([]byte("go")); err != nil {
					t.Fatalf("upload-only UDP retired despite activity at packet %d: %v", i, err)
				}
			}
			time.Sleep(30 * time.Millisecond)
			continue
		}
		var b [3]byte
		if _, err = io.ReadFull(app, b[:]); err != nil || string(b[:]) != "udp" {
			t.Fatalf("download-only UDP retired despite activity at packet %d: %v", i, err)
		}
	}
	<-peerDone
	select {
	case <-flowDone:
	case <-time.After(time.Second):
		t.Fatal("UDP flow did not join")
	}
}
