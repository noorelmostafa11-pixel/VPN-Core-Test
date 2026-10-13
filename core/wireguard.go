package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	wd "golang.zx2c4.com/wireguard/device"
	wn "golang.zx2c4.com/wireguard/tun/netstack"
)

func parseWireGuardURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "wireguard", "raw", "wireguard"
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return c, errors.New("WIREGUARD_CONFIGURATION")
	}
	c.Password = u.User.Username()
	if _, ok := u.User.Password(); ok {
		return c, errors.New("WIREGUARD_CONFIGURATION")
	}
	c.Server, c.ServerName, c.Port = u.Hostname(), u.Hostname(), 51820
	if u.Port() != "" {
		c.Port, err = number(u.Port(), 1, 65535)
		if err != nil {
			return c, err
		}
	}
	if u.Path != "" && u.Path != "/" {
		return c, errors.New("WIREGUARD_CONFIGURATION")
	}
	c.Options = map[string]string{}
	for k, vs := range u.Query() {
		if len(vs) != 1 {
			return c, errors.New("WIREGUARD_CONFIGURATION")
		}
		c.Options[strings.ToLower(k)] = vs[0]
	}
	c.PublicKey = c.Options["public-key"]
	return c, c.Validate()
}
func wireKey(key string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 {
		return "", errors.New("WIREGUARD_KEY_INVALID")
	}
	var value byte
	for _, v := range b {
		value |= v
	}
	if value == 0 {
		return "", errors.New("WIREGUARD_KEY_INVALID")
	}
	return hex.EncodeToString(b), nil
}
func wireAddresses(text string) ([]netip.Addr, error) {
	if text == "" {
		return nil, errors.New("WIREGUARD_ADDRESS_REQUIRED")
	}
	var result []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, v := range strings.Split(text, ",") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			if p, e := netip.ParsePrefix(v); e == nil {
				a, err = p.Addr(), nil
			}
		}
		if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || seen[a] || len(result) == 8 {
			return nil, errors.New("WIREGUARD_ADDRESS_INVALID")
		}
		seen[a] = true
		result = append(result, a.Unmap())
	}
	return result, nil
}
func wireAllowed(text string) ([]netip.Prefix, error) {
	if text == "" {
		text = "0.0.0.0/0,::/0"
	}
	var out []netip.Prefix
	for _, v := range strings.Split(text, ",") {
		p, err := netip.ParsePrefix(v)
		if err != nil || len(out) == 128 {
			return nil, errors.New("WIREGUARD_ALLOWED_IP_INVALID")
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
func validateWireGuard(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || c.Security != "wireguard" || c.Transport != "raw" {
		return errors.New("WIREGUARD_CONFIGURATION")
	}
	if _, err := wireKey(c.Password); err != nil {
		return err
	}
	if _, err := wireKey(c.PublicKey); err != nil {
		return err
	}
	for k := range c.Options {
		if !contains([]string{"public-key", "preshared-key", "local-address", "dns", "allowed-ips", "mtu", "keepalive"}, k) {
			return errors.New("WIREGUARD_OPTION_UNSUPPORTED")
		}
	}
	if p := c.Options["preshared-key"]; p != "" {
		if _, err := wireKey(p); err != nil {
			return err
		}
	}
	if _, err := wireAddresses(c.Options["local-address"]); err != nil {
		return err
	}
	if _, err := wireAllowed(c.Options["allowed-ips"]); err != nil {
		return err
	}
	if d := c.Options["dns"]; d != "" {
		if _, err := wireAddresses(d); err != nil {
			return err
		}
	}
	if m := c.Options["mtu"]; m != "" {
		if _, err := number(m, 1280, 9000); err != nil {
			return errors.New("WIREGUARD_MTU_INVALID")
		}
	}
	if v := c.Options["keepalive"]; v != "" {
		if _, err := number(v, 0, 65535); err != nil {
			return errors.New("WIREGUARD_KEEPALIVE_INVALID")
		}
	}
	return nil
}

type wireClient struct {
	dev     *wd.Device
	network *wn.Net
	once    sync.Once
	cancel  context.CancelFunc
}

func (c *wireClient) Close() error {
	c.once.Do(func() { c.cancel(); c.dev.Close(); <-c.dev.Wait(); c.dev.JoinWorkers() })
	return nil
}
func (c *wireClient) IsClosed() bool {
	select {
	case <-c.dev.Wait():
		return true
	default:
		return false
	}
}
func newWireClient(ctx context.Context, c Config) (io.Closer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	ips, err := bootstrapIPs(ctx, c.Server)
	if err != nil {
		return nil, err
	}
	return sequentialProtocolClients(ctx, ips, func(attempt context.Context, ip net.IPAddr) (io.Closer, error) {
		local, _ := wireAddresses(c.Options["local-address"])
		var dns []netip.Addr
		if c.Options["dns"] != "" {
			dns, _ = wireAddresses(c.Options["dns"])
		}
		mtu := 1420
		if c.Options["mtu"] != "" {
			mtu, _ = strconv.Atoi(c.Options["mtu"])
		}
		tun, network, err := wn.CreateNetTUN(local, dns, mtu)
		if err != nil {
			return nil, err
		}
		// The owner closes the bind/device explicitly; retain hook values for later
		// rekeys rather than a setup timeout that has already expired.
		life, lifeCancel := context.WithCancel(context.WithoutCancel(attempt))
		bind := &wireBind{ctx: life}
		dev := wd.NewDeviceWithWorkers(tun, bind, &wd.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}, 2)
		client := &wireClient{dev: dev, network: network, cancel: lifeCancel}
		stopped := make(chan struct{})
		stop := context.AfterFunc(attempt, func() { client.Close(); close(stopped) })
		detach := func() {
			if !stop() {
				<-stopped
			}
		}
		private, _ := wireKey(c.Password)
		public, _ := wireKey(c.PublicKey)
		endpoint := net.JoinHostPort(ip.IP.String(), itoa(c.Port))
		if ip.Zone != "" {
			endpoint = net.JoinHostPort(ip.IP.String()+"%"+ip.Zone, itoa(c.Port))
		}
		ipc := "private_key=" + private + "\npublic_key=" + public + "\nendpoint=" + endpoint + "\n"
		if p := c.Options["preshared-key"]; p != "" {
			key, _ := wireKey(p)
			ipc += "preshared_key=" + key + "\n"
		}
		allowed, _ := wireAllowed(c.Options["allowed-ips"])
		for _, p := range allowed {
			ipc += "allowed_ip=" + p.String() + "\n"
		}
		if keep := c.Options["keepalive"]; keep != "" {
			ipc += "persistent_keepalive_interval=" + keep + "\n"
		}
		err = dev.IpcSet(ipc)
		if err == nil {
			err = dev.Up()
		}
		var pk wd.NoisePublicKey
		b, _ := hex.DecodeString(public)
		copy(pk[:], b)
		if err == nil {
			peer := dev.LookupPeer(pk)
			if peer == nil {
				err = errors.New("WIREGUARD_PEER_INVALID")
			} else {
				peer.SendKeepalive()
				ticker := time.NewTicker(20 * time.Millisecond)
				defer ticker.Stop()
				for dev.LastHandshake(pk).IsZero() && err == nil {
					select {
					case <-attempt.Done():
						err = attempt.Err()
					case <-ticker.C:
					}
				}
			}
		}
		detach()
		if err != nil || attempt.Err() != nil {
			client.Close()
			if attempt.Err() != nil {
				return nil, attempt.Err()
			}
			return nil, errors.Join(errors.New("WIREGUARD_HANDSHAKE_FAILED"), err)
		}
		return client, nil
	})
}
func getWireClient(ctx context.Context, c Config) (*wireClient, io.Closer, error) {
	b, _ := json.Marshal(c)
	hash := sha256.Sum256(b)
	key := "wireguard:" + hex.EncodeToString(hash[:])
	if route, ok := ctx.Value(routeReuseKey{}).(routeReuse); ok {
		key += fmt.Sprintf(":%p:%s", route.table, route.tag)
	}
	if cache := engineClientCache(ctx); cache != nil {
		lease, err := cache.get(ctx, key, func(ctx context.Context) (io.Closer, error) { return newWireClient(ctx, c) })
		if err != nil {
			return nil, nil, err
		}
		return lease.entry.client.(*wireClient), lease, nil
	}
	client, err := newWireClient(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	return client.(*wireClient), client, nil
}
func dialWireGuard(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if _, err := Address(host, port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	client, owner, err := getWireClient(ctx, c)
	if err != nil {
		return nil, err
	}
	conn, err := client.dialTCP(ctx, host, port)
	if err != nil {
		owner.Close()
		return nil, err
	}
	return &hyLeaseConn{Conn: conn, owner: owner}, nil
}
func dialWireGuardPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if _, err := Address(host, port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	client, owner, err := getWireClient(ctx, c)
	if err != nil {
		return nil, err
	}
	conn, err := client.network.DialContext(ctx, "udp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		owner.Close()
		return nil, err
	}
	address, _ := Address(host, port)
	return &directPackets{Conn: &hyLeaseConn{Conn: conn, owner: owner}, address: address}, nil
}
