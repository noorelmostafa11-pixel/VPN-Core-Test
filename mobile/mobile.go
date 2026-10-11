// Package mobile offers gomobile-compatible Android/iOS packet and fd APIs.
package mobile

import (
	"context"
	"errors"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core"
	"net"
	"strings"
	"sync"
)

type Protector interface{ Protect(fd int64) bool }
type Resolver interface{ Resolve(host string) string }
type PacketReceiver interface{ ReceivePacket(packet []byte) }
type Session struct {
	engine *core.Engine
	device *packetDevice
	once   sync.Once
}

func hooks(p Protector, r Resolver) core.Hooks {
	var h core.Hooks
	if p != nil {
		h.Protect = func(ctx context.Context, fd int64) error {
			if !p.Protect(fd) {
				return errors.New("SOCKET_PROTECTION_FAILED")
			}
			return ctx.Err()
		}
	}
	if r != nil {
		h.Resolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			var ips []net.IPAddr
			for _, s := range strings.Fields(r.Resolve(host)) {
				ip := net.ParseIP(s)
				if ip == nil {
					return nil, errors.New("BOOTSTRAP_DNS_FAILED")
				}
				ips = append(ips, net.IPAddr{IP: ip})
			}
			if len(ips) == 0 {
				return nil, errors.New("BOOTSTRAP_DNS_FAILED")
			}
			return ips, ctx.Err()
		}
	}
	return h
}
func newEngine(uri string, p Protector, r Resolver) (*core.Engine, error) {
	c, e := core.ParseURI(uri)
	if e != nil {
		return nil, e
	}
	return core.NewEngine(context.Background(), c, hooks(p, r))
}

// StartFD duplicates a descriptor established by Android VpnService. The host
// retains the original descriptor and must provide its VpnService.protect hook.
func StartFD(uri string, fd, mtu int, p Protector, r Resolver) (*Session, error) {
	if p == nil {
		return nil, errors.New("SOCKET_PROTECTOR_REQUIRED")
	}
	e, err := newEngine(uri, p, r)
	if err != nil {
		return nil, err
	}
	device, err := core.OpenTUNFD(fd, mtu)
	if err != nil {
		e.Close()
		return nil, err
	}
	if _, err = e.StartTUN(device, mtu); err != nil {
		device.Close()
		e.Close()
		return nil, err
	}
	return &Session{engine: e}, nil
}

type packetDevice struct {
	input    chan []byte
	done     chan struct{}
	receiver PacketReceiver
	once     sync.Once
}

func (d *packetDevice) ReadPacket(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	case p := <-d.input:
		if len(p) > len(b) {
			return 0, errors.New("TUN_PACKET_SIZE")
		}
		return copy(b, p), nil
	}
}
func (d *packetDevice) WritePacket(b []byte) error {
	select {
	case <-d.done:
		return net.ErrClosed
	default:
		d.receiver.ReceivePacket(append([]byte{}, b...))
		return nil
	}
}
func (d *packetDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }

// StartPackets integrates NEPacketTunnelFlow or another OS packet service.
// The host owns routes and upstream socket/resolver policy. No external proxy
// or native packet translator is needed.
func StartPackets(uri string, mtu int, receiver PacketReceiver, p Protector, r Resolver) (*Session, error) {
	if receiver == nil {
		return nil, errors.New("PACKET_RECEIVER_REQUIRED")
	}
	e, err := newEngine(uri, p, r)
	if err != nil {
		return nil, err
	}
	d := &packetDevice{input: make(chan []byte, 256), done: make(chan struct{}), receiver: receiver}
	if _, err = e.StartTUN(d, mtu); err != nil {
		d.Close()
		e.Close()
		return nil, err
	}
	return &Session{engine: e, device: d}, nil
}
func (s *Session) InjectPacket(packet []byte) error {
	if s.device == nil {
		return errors.New("PACKET_API_REQUIRES_START_PACKETS")
	}
	if len(packet) < 1 || len(packet) > 65535 {
		return errors.New("TUN_PACKET_SIZE")
	}
	owned := append([]byte{}, packet...)
	select {
	case <-s.device.done:
		return net.ErrClosed
	case s.device.input <- owned:
		return nil
	default:
		return errors.New("TUN_INPUT_QUEUE_FULL")
	}
}
func (s *Session) Close() error           { s.once.Do(func() { s.engine.Close() }); return nil }
func (s *Session) UploadedBytes() int64   { return int64(s.engine.Stats().Uploaded) }
func (s *Session) DownloadedBytes() int64 { return int64(s.engine.Stats().Downloaded) }
func Version() string                     { return core.Version }
