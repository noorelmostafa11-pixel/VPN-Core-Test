package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	wc "golang.zx2c4.com/wireguard/conn"
)

// Every WireGuard UDP socket is protected before binding. The portable path
// uses one-packet batches and does not change host routes or process affinity.
type wireBind struct {
	ctx    context.Context
	mu     sync.Mutex
	v4, v6 net.PacketConn
	listen string
}

func (b *wireBind) BatchSize() int { return 1 }
func (b *wireBind) ParseEndpoint(s string) (wc.Endpoint, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wc.StdNetEndpoint{AddrPort: a}, nil
}
func (b *wireBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("WIREGUARD_MARK_UNSUPPORTED")
	}
	return nil
}
func (b *wireBind) Open(port uint16) ([]wc.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.v4 != nil || b.v6 != nil {
		return nil, 0, wc.ErrBindAlreadyOpen
	}
	var fns []wc.ReceiveFunc
	var last error
	for _, family := range []string{"udp4", "udp6"} {
		host := "0.0.0.0"
		if family == "udp6" {
			host = "::"
		}
		if b.listen != "" {
			ip := net.ParseIP(b.listen)
			if ip == nil {
				return nil, 0, errors.New("WIREGUARD_LISTEN_INVALID")
			}
			if (ip.To4() == nil) != (family == "udp6") {
				continue
			}
			host = b.listen
		}
		p, err := outboundPacket(b.ctx, family, net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			last = err
			if strings.Contains(err.Error(), "SOCKET_PROTECTION_FAILED") {
				if b.v4 != nil {
					b.v4.Close()
				}
				if b.v6 != nil {
					b.v6.Close()
				}
				b.v4, b.v6 = nil, nil
				return nil, 0, err
			}
			continue
		}
		configureDatagramBuffers(p)
		if family == "udp4" {
			b.v4 = p
		} else {
			b.v6 = p
		}
		port = uint16(p.LocalAddr().(*net.UDPAddr).Port)
		fns = append(fns, func(bufs [][]byte, sizes []int, endpoints []wc.Endpoint) (int, error) {
			n, a, err := p.ReadFrom(bufs[0])
			if err != nil {
				return 0, err
			}
			u, ok := a.(*net.UDPAddr)
			if !ok {
				return 0, errors.New("WIREGUARD_ADDRESS")
			}
			sizes[0] = n
			endpoints[0] = &wc.StdNetEndpoint{AddrPort: u.AddrPort()}
			return 1, nil
		})
	}
	if len(fns) == 0 {
		return nil, 0, last
	}
	return fns, port, nil
}
func (b *wireBind) Send(bufs [][]byte, ep wc.Endpoint) error {
	endpoint, ok := ep.(*wc.StdNetEndpoint)
	if !ok {
		return wc.ErrWrongEndpointType
	}
	b.mu.Lock()
	p := b.v6
	if endpoint.AddrPort.Addr().Is4() {
		p = b.v4
	}
	b.mu.Unlock()
	if p == nil {
		return net.ErrClosed
	}
	a := net.UDPAddrFromAddrPort(endpoint.AddrPort)
	for _, buf := range bufs {
		if _, err := p.WriteTo(buf, a); err != nil {
			return err
		}
	}
	return nil
}
func (b *wireBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.v4 != nil {
		b.v4.Close()
	}
	if b.v6 != nil {
		b.v6.Close()
	}
	b.v4, b.v6 = nil, nil
	return nil
}
