package core

import (
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
	"gvisor.dev/gvisor/pkg/waiter"
	"io"
	"net"
	"sync"
	"time"
)

// PacketDevice exchanges raw IPv4/IPv6 packets. A mobile VPN service can supply
// its established descriptor; desktop hosts can use OpenTUN.
type PacketDevice interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
}
type Tunnel struct {
	engine *Engine
	stack  *stack.Stack
	link   *channel.Endpoint
	device PacketDevice
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	done   chan struct{}
	errMu  sync.Mutex
	err    error
}

func (t *Tunnel) Done() <-chan struct{} { return t.done }
func (t *Tunnel) Err() error            { t.errMu.Lock(); defer t.errMu.Unlock(); return t.err }
func (t *Tunnel) fail(e error) {
	if t.ctx.Err() != nil {
		return
	}
	t.errMu.Lock()
	if t.err == nil {
		t.err = e
	}
	t.errMu.Unlock()
	t.cancel()
	t.device.Close()
}
func (t *Tunnel) shutdown() {
	t.once.Do(func() { t.cancel(); t.device.Close(); t.link.Close(); t.stack.Close() })
}
func (t *Tunnel) Close() error {
	t.shutdown()
	<-t.done
	return t.Err()
}

// StartTUN consumes device packets directly. No SOCKS listener or external
// tun-to-socks process is involved. The engine owns and closes the device.
func (e *Engine) StartTUN(device PacketDevice, mtu int) (*Tunnel, error) {
	if mtu < 1280 || mtu > 65535 {
		return nil, errors.New("TUN_MTU_INVALID")
	}
	ctx, cancel := context.WithCancel(e.ctx)
	t := &Tunnel{engine: e, device: device, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	t.link = channel.New(256, uint32(mtu), "")
	t.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}, HandleLocal: false})
	if err := t.stack.CreateNIC(1, t.link); err != nil {
		cancel()
		t.stack.Close()
		return nil, errors.New(err.String())
	}
	t.stack.SetSpoofing(1, true)
	t.stack.SetPromiscuousMode(1, true)
	t.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	recv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 65536, Max: 262144}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 65536, Max: 262144}
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &recv)
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &send)
	forward := tcp.NewForwarder(t.stack, 65536, e.config.MaxConnections, func(r *tcp.ForwarderRequest) {
		if !e.acquire() {
			r.Complete(true)
			return
		}
		id := r.ID()
		if !e.spawn(func() {
			defer e.release()
			var q waiter.Queue
			ep, err := r.CreateEndpoint(&q)
			if err != nil {
				r.Complete(true)
				return
			}
			r.Complete(false)
			client := gonet.NewTCPConn(&q, ep)
			if !e.track(client) {
				return
			}
			defer e.untrack(client)
			defer client.Close()
			stopClient := context.AfterFunc(ctx, func() { client.Close() })
			defer stopClient()
			server, dialErr := Dial(ctx, e.config, net.IP(id.LocalAddress.AsSlice()).String(), int(id.LocalPort))
			if dialErr != nil {
				e.emit(Event{Event: "failure", ReasonCode: reasonCode(dialErr)})
				return
			}
			if !e.track(server) {
				return
			}
			defer e.untrack(server)
			defer server.Close()
			stopServer := context.AfterFunc(ctx, func() { server.Close() })
			defer stopServer()
			e.relay(client, server)
		}) {
			e.release()
			r.Complete(true)
		}
	})
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forward.HandlePacket)
	t.stack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if !e.acquire() {
			return false
		}
		r := udp.NewForwarderRequest(t.stack, id, pkt)
		var q waiter.Queue
		ep, err := r.CreateEndpoint(&q)
		if err != nil {
			e.release()
			return false
		}
		client := gonet.NewUDPConn(&q, ep)
		if !e.track(client) {
			e.release()
			return false
		}
		if !e.spawn(func() {
			defer e.release()
			defer e.untrack(client)
			defer client.Close()
			t.udpFlow(client, net.IP(id.LocalAddress.AsSlice()).String(), int(id.LocalPort))
		}) {
			e.release()
			client.Close()
			return false
		}
		return true
	})
	go func() {
		defer e.untrack(t)
		defer close(t.done)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			b := make([]byte, mtu+256)
			for {
				n, err := device.ReadPacket(b)
				if err != nil {
					t.fail(err)
					return
				}
				if n < 1 || n > mtu {
					continue
				}
				proto := ipv4.ProtocolNumber
				switch b[0] >> 4 {
				case 4:
				case 6:
					proto = ipv6.ProtocolNumber
				default:
					continue
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte{}, b[:n]...))})
				t.link.InjectInbound(proto, pkt)
				pkt.DecRef()
			}
		}()
		go func() {
			defer workers.Done()
			for {
				pkt := t.link.ReadContext(ctx)
				if pkt == nil {
					return
				}
				view := pkt.ToView()
				err := device.WritePacket(view.AsSlice())
				view.Release()
				pkt.DecRef()
				if err != nil {
					t.fail(err)
					return
				}
			}
		}()
		<-ctx.Done()
		t.shutdown()
		workers.Wait()
		t.stack.Wait()
	}()
	if !e.track(t) {
		return nil, net.ErrClosed
	}
	return t, nil
}
func (t *Tunnel) udpFlow(client net.Conn, host string, port int) {
	server, err := DialPacket(t.ctx, t.engine.config, host, port)
	if err != nil {
		t.engine.emit(Event{Event: "failure", ReasonCode: reasonCode(err)})
		return
	}
	if !t.engine.track(server) {
		return
	}
	defer t.engine.untrack(server)
	defer server.Close()
	stopFlow := context.AfterFunc(t.ctx, func() { client.Close(); server.Close() })
	defer stopFlow()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			server.SetDeadline(time.Now().Add(t.engine.config.IdleTimeout))
			packet, err := server.ReadPacket()
			if err != nil {
				if isPacketRejected(err) {
					t.engine.emit(Event{Event: "udp_diagnostic", ReasonCode: reasonCode(err)})
					continue
				}
				client.Close()
				return
			}
			client.SetReadDeadline(time.Now().Add(t.engine.config.IdleTimeout))
			if _, err = client.Write(packet.Payload); err != nil {
				return
			}
			t.engine.down.Add(uint64(len(packet.Payload)))
		}
	}()
	b := make([]byte, 65536)
	for {
		client.SetReadDeadline(time.Now().Add(t.engine.config.IdleTimeout))
		n, err := client.Read(b)
		if err != nil {
			break
		}
		server.SetDeadline(time.Now().Add(t.engine.config.IdleTimeout))
		if err = server.WritePacket(b[:n]); err != nil {
			break
		}
		t.engine.up.Add(uint64(n))
	}
	server.Close()
	client.Close()
	<-done
}

var _ io.Closer = (*Tunnel)(nil)
