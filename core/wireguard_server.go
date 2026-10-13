package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"

	wd "golang.zx2c4.com/wireguard/device"
	wt "golang.zx2c4.com/wireguard/tun"
)

type WireGuardPeerConfig struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
}
type WireGuardServerConfig struct {
	PrivateKey string                `json:"private_key"`
	Peers      []WireGuardPeerConfig `json:"peers"`
	MTU        int                   `json:"mtu,omitempty"`
}

func validateWireServer(c ServerConfig) error {
	host, p, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil {
		return errors.New("SERVER_LISTEN_INVALID")
	}
	if _, err = number(p, 0, 65535); err != nil {
		return errors.New("SERVER_LISTEN_INVALID")
	}
	w := c.WireGuard
	if w == nil || len(w.Peers) < 1 || len(w.Peers) > 128 {
		return errors.New("WIREGUARD_SERVER_PEERS_INVALID")
	}
	if _, err = wireKey(w.PrivateKey); err != nil {
		return err
	}
	if w.MTU != 0 && (w.MTU < 1280 || w.MTU > 9000) {
		return errors.New("WIREGUARD_MTU_INVALID")
	}
	if c.Password != "" || len(c.UUIDs) > 0 || c.CertFile != "" || c.KeyFile != "" || len(c.Options) > 0 || c.Cipher != "" {
		return errors.New("WIREGUARD_SERVER_OPTIONS_INVALID")
	}
	keys := map[string]bool{}
	prefixes := map[netip.Prefix]bool{}
	for _, peer := range w.Peers {
		key, err := wireKey(peer.PublicKey)
		if err != nil || keys[key] {
			return errors.New("WIREGUARD_SERVER_PEERS_INVALID")
		}
		keys[key] = true
		if peer.PresharedKey != "" {
			if _, err = wireKey(peer.PresharedKey); err != nil {
				return err
			}
		}
		if len(peer.AllowedIPs) < 1 || len(peer.AllowedIPs) > 32 {
			return errors.New("WIREGUARD_ALLOWED_IP_INVALID")
		}
		for _, v := range peer.AllowedIPs {
			p, err := netip.ParsePrefix(v)
			if err != nil || prefixes[p.Masked()] {
				return errors.New("WIREGUARD_ALLOWED_IP_INVALID")
			}
			prefixes[p.Masked()] = true
		}
	}
	return nil
}

// Decrypted WireGuard packets enter the engine's native TCP/UDP forwarder.
// Responses return through WireGuard. Neither side creates an OS TUN device.
type wirePacketDevice struct {
	inbound, outbound chan []byte
	done              chan struct{}
	events            chan wt.Event
	mtu               int
	once              sync.Once
}

func newWirePacketDevice(mtu int) *wirePacketDevice {
	return &wirePacketDevice{inbound: make(chan []byte, 64), outbound: make(chan []byte, 64), done: make(chan struct{}), events: make(chan wt.Event), mtu: mtu}
}
func (p *wirePacketDevice) Name() (string, error)   { return "vpn-core-wireguard", nil }
func (p *wirePacketDevice) File() *os.File          { return nil }
func (p *wirePacketDevice) Events() <-chan wt.Event { return p.events }
func (p *wirePacketDevice) MTU() (int, error)       { return p.mtu, nil }
func (p *wirePacketDevice) BatchSize() int          { return 1 }
func (p *wirePacketDevice) Close() error {
	p.once.Do(func() { close(p.done); close(p.events) })
	return nil
}
func (p *wirePacketDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case b := <-p.inbound:
		if len(b) > len(buf) {
			return 0, errors.New("WIREGUARD_PACKET_BUFFER")
		}
		return copy(buf, b), nil
	}
}
func (p *wirePacketDevice) WritePacket(buf []byte) error {
	if len(buf) > p.mtu {
		return errors.New("WIREGUARD_PACKET_MTU")
	}
	b := append([]byte(nil), buf...)
	select {
	case <-p.done:
		return net.ErrClosed
	case p.outbound <- b:
		return nil
	}
}
func (p *wirePacketDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case b := <-p.outbound:
		if len(b) > len(bufs[0])-offset {
			return 0, errors.New("WIREGUARD_PACKET_BUFFER")
		}
		sizes[0] = copy(bufs[0][offset:], b)
		return 1, nil
	}
}
func (p *wirePacketDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if offset > len(buf) || len(buf)-offset > p.mtu {
			return i, errors.New("WIREGUARD_PACKET_MTU")
		}
		b := append([]byte(nil), buf[offset:]...)
		select {
		case <-p.done:
			return i, net.ErrClosed
		case p.inbound <- b:
		}
	}
	return len(bufs), nil
}

type wireServer struct {
	dev    *wd.Device
	tunnel *Tunnel
	once   sync.Once
}

func (s *wireServer) Close() error {
	s.once.Do(func() { s.dev.Close(); s.dev.JoinWorkers(); s.tunnel.Close() })
	return nil
}
func (e *Engine) startWireServer(c ServerConfig) (net.Addr, error) {
	if err := validateWireServer(c); err != nil {
		return nil, err
	}
	w := c.WireGuard
	mtu := w.MTU
	if mtu == 0 {
		mtu = 1420
	}
	packet := newWirePacketDevice(mtu)
	tunnel, err := e.startTUN(packet, mtu, true)
	if err != nil {
		packet.Close()
		return nil, err
	}
	host, p, _ := net.SplitHostPort(c.Listen)
	bind := &wireBind{ctx: e.ctx, listen: host}
	dev := wd.NewDeviceWithWorkers(packet, bind, &wd.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}, 2)
	server := &wireServer{dev: dev, tunnel: tunnel}
	private, _ := wireKey(w.PrivateKey)
	ipc := "private_key=" + private + "\nlisten_port=" + p + "\n"
	for _, peer := range w.Peers {
		public, _ := wireKey(peer.PublicKey)
		ipc += "public_key=" + public + "\n"
		if peer.PresharedKey != "" {
			key, _ := wireKey(peer.PresharedKey)
			ipc += "preshared_key=" + key + "\n"
		}
		for _, ip := range peer.AllowedIPs {
			ipc += "allowed_ip=" + ip + "\n"
		}
	}
	err = dev.IpcSet(ipc)
	if err == nil {
		err = dev.Up()
	}
	if err != nil {
		server.Close()
		return nil, err
	}
	bind.mu.Lock()
	listen := bind.v4
	if listen == nil {
		listen = bind.v6
	}
	bind.mu.Unlock()
	if listen == nil {
		server.Close()
		return nil, errors.New("WIREGUARD_LISTEN_FAILED")
	}
	if !e.track(server) {
		return nil, net.ErrClosed
	}
	if !e.track(listen) {
		e.untrack(server)
		server.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return listen.LocalAddr(), nil
}

func (c *wireClient) dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	names, err := c.network.LookupContextHost(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IPAddr, 0, len(names))
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			ips = append(ips, net.IPAddr{IP: ip})
		}
	}
	return dialResolved(ctx, "tcp", ips, strconv.Itoa(port), c.network.DialContext)
}
