package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	hy "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

func parseHysteriaURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "hysteria2", "quic", "tls"
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return c, errors.New("PARSE_INVALID: Hysteria authentication")
	}
	if u.Path != "" && u.Path != "/" {
		return c, errors.New("PARSE_INVALID: Hysteria path")
	}
	c.Password = u.User.Username()
	if password, ok := u.User.Password(); ok {
		c.Password += ":" + password
	}
	c.Server, c.ServerName = u.Hostname(), u.Hostname()
	c.Port = 443
	if u.Port() != "" {
		c.Port, err = number(u.Port(), 1, 65535)
		if err != nil {
			return c, err
		}
	}
	c.Options = map[string]string{}
	for key, values := range u.Query() {
		if len(values) != 1 {
			return c, errors.New("PARSE_INVALID: duplicate Hysteria option")
		}
		c.Options[strings.ToLower(key)] = values[0]
	}
	c.ServerName = option(c.Options, c.Server, "sni", "peer")
	c.Fingerprint = option(c.Options, "native", "fp", "fingerprint")
	c.ECH = c.Options["ech"]
	c.InsecureRequested = truth(option(c.Options, "", "insecure", "allowinsecure"))
	return c, c.Validate()
}
func validateHysteria(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || c.Password == "" || len(c.Password) > 4096 || c.Security != "tls" || c.Transport != "quic" {
		return errors.New("HYSTERIA_CONFIGURATION")
	}
	for key := range c.Options {
		if !contains([]string{"sni", "peer", "fp", "fingerprint", "ech", "insecure", "allowinsecure", "obfs", "obfs-password", "obfs_password", "upmbps", "downmbps", "congestion", "pinsha256", "pcs", "vcn"}, key) {
			return errors.New("HYSTERIA_OPTION_UNSUPPORTED")
		}
	}
	if c.Fingerprint != "" && c.Fingerprint != "native" && c.Fingerprint != "chrome" {
		return errors.New("HYSTERIA_FINGERPRINT_UNSUPPORTED")
	}
	if err := validateHysteriaObfs(c.Options); err != nil {
		return err
	}
	if _, err := c.tlsSettings(); err != nil {
		return err
	}
	if !contains([]string{"bbr", "reno"}, option(c.Options, "bbr", "congestion")) {
		return errors.New("HYSTERIA_CONGESTION_INVALID")
	}
	for _, name := range []string{"upmbps", "downmbps"} {
		if value := c.Options[name]; value != "" {
			if _, err := number(value, 1, 100000); err != nil {
				return errors.New("HYSTERIA_BANDWIDTH_INVALID")
			}
		}
	}
	return nil
}

type hyFactory struct {
	ctx     context.Context
	timeout time.Duration
	mu      sync.Mutex
	conn    net.PacketConn
	options map[string]string
}

func (f *hyFactory) New(addr net.Addr) (net.PacketConn, error) {
	network, address := "udp4", "0.0.0.0:0"
	if a, ok := addr.(*net.UDPAddr); ok && a.IP.To4() == nil {
		network, address = "udp6", "[::]:0"
	}
	conn, err := outboundPacket(f.ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn, err = wrapHysteriaPacket(conn, f.options)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(f.timeout))
	f.mu.Lock()
	f.conn = conn
	f.mu.Unlock()
	return conn, nil
}
func (f *hyFactory) close() {
	f.mu.Lock()
	conn := f.conn
	f.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}
func newHysteriaClient(ctx context.Context, c Config) (io.Closer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	settings, err := c.tlsSettings()
	if err != nil {
		return nil, err
	}
	roots, err := tlsRoots(settings)
	if err != nil {
		return nil, err
	}
	ips, err := bootstrapIPs(ctx, c.Server)
	if err != nil {
		return nil, err
	}
	config := hy.Config{Auth: c.Password, TLSConfig: hy.TLSConfig{ServerName: c.ServerName, RootCAs: roots}, QUICConfig: hy.QUICConfig{InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 262144, InitialConnectionReceiveWindow: 262144, MaxConnectionReceiveWindow: 1048576, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, DisableChromeParrot: c.Fingerprint != "chrome"}, CongestionConfig: hy.CongestionConfig{Type: option(c.Options, "bbr", "congestion")}}
	if c.ECH != "" {
		config.TLSConfig.ECHConfigList, err = resolveECH(ctx, c.ECH, c.ServerName, roots)
		if err != nil {
			return nil, err
		}
	}
	if len(settings.Pins) > 0 || len(settings.Names) > 0 {
		config.TLSConfig.InsecureSkipVerify = true
		config.TLSConfig.VerifyPeerCertificate = verifyConfigured(settings, roots)
	}
	for key, target := range map[string]*uint64{"upmbps": &config.BandwidthConfig.MaxTx, "downmbps": &config.BandwidthConfig.MaxRx} {
		if value := c.Options[key]; value != "" {
			n, _ := strconv.ParseUint(value, 10, 64)
			*target = n * 125000
		}
	}
	return raceProtocolClients(ctx, ips, func(attempt context.Context, ip net.IPAddr) (io.Closer, error) {
		factory := &hyFactory{ctx: attempt, timeout: c.ConnectTimeout, options: c.Options}
		canceled := make(chan struct{})
		stop := context.AfterFunc(attempt, func() { factory.close(); close(canceled) })
		cfg := config
		cfg.ConnFactory, cfg.ServerAddr = factory, &net.UDPAddr{IP: ip.IP, Zone: ip.Zone, Port: c.Port}
		client, _, err := hy.NewClientContext(attempt, &cfg)
		if !stop() {
			<-canceled
		}
		if err != nil {
			factory.close()
			return nil, errors.Join(errors.New("HYSTERIA_HANDSHAKE_FAILED"), err)
		}
		if attempt.Err() != nil {
			client.Close()
			return nil, attempt.Err()
		}
		factory.mu.Lock()
		factory.conn.SetDeadline(time.Time{})
		factory.mu.Unlock()
		return client, nil
	})
}

type hyLeaseConn struct {
	net.Conn
	owner io.Closer
	once  sync.Once
}

func (c *hyLeaseConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.owner.Close() })
	return err
}
func (c *hyLeaseConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}

type hyContextClient interface {
	hy.Client
	TCPContext(context.Context, string) (net.Conn, error)
	IsClosed() bool
}

func getHysteria(ctx context.Context, c Config) (hyContextClient, io.Closer, error) {
	b, _ := json.Marshal(c)
	hash := sha256.Sum256(b)
	key := "hysteria2:" + hex.EncodeToString(hash[:])
	if route, ok := ctx.Value(routeReuseKey{}).(routeReuse); ok {
		key += fmt.Sprintf(":%p:%s", route.table, route.tag)
	}
	if cache := engineClientCache(ctx); cache != nil {
		lease, err := cache.get(ctx, key, func(ctx context.Context) (io.Closer, error) { return newHysteriaClient(ctx, c) })
		if err != nil {
			return nil, nil, err
		}
		return lease.entry.client.(hyContextClient), lease, nil
	}
	client, err := newHysteriaClient(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	return client.(hyContextClient), client, nil
}
func dialHysteria(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if _, err := Address(host, port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	client, owner, err := getHysteria(ctx, c)
	if err != nil {
		return nil, err
	}
	conn, err := client.TCPContext(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		owner.Close()
		return nil, err
	}
	return &hyLeaseConn{Conn: conn, owner: owner}, nil
}

type hyPackets struct {
	conn       hy.HyUDPConn
	owner      io.Closer
	address    string
	mu         sync.Mutex
	writeMu    sync.Mutex
	readMu     sync.Mutex
	once       sync.Once
	timer      *time.Timer
	closed     bool
	generation uint64
}

func (s *hyPackets) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()
	s.finishClose()
	return nil
}
func (s *hyPackets) finishClose() {
	s.once.Do(func() {
		s.conn.Close()
		s.owner.Close()
	})
}
func (s *hyPackets) SetDeadline(deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.generation++
	generation := s.generation
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if !deadline.IsZero() {
		s.timer = time.AfterFunc(time.Until(deadline), func() {
			s.mu.Lock()
			if s.closed || generation != s.generation {
				s.mu.Unlock()
				return
			}
			s.closed = true
			s.mu.Unlock()
			s.finishClose()
		})
	}
	return nil
}
func (s *hyPackets) WritePacket(payload []byte) error {
	if len(payload) > 65507 {
		return errors.New("UDP_DATAGRAM_LENGTH")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return s.conn.Send(payload, s.address)
}

func validateHysteriaObfs(options map[string]string) error {
	mode := option(options, "none", "obfs")
	if !contains([]string{"none", "salamander", "gecko"}, mode) {
		return errors.New("HYSTERIA_OBFS_INVALID")
	}
	password := option(options, "", "obfs-password", "obfs_password")
	if mode != "none" && (len(password) < 4 || len(password) > 4096) {
		return errors.New("HYSTERIA_OBFS_PASSWORD_INVALID")
	}
	if mode == "none" && password != "" {
		return errors.New("HYSTERIA_OBFS_INVALID")
	}
	return nil
}
func wrapHysteriaPacket(conn net.PacketConn, options map[string]string) (net.PacketConn, error) {
	var wrapped net.PacketConn
	var err error
	password := []byte(option(options, "", "obfs-password", "obfs_password"))
	switch options["obfs"] {
	case "", "none":
		return conn, nil
	case "salamander":
		wrapped, err = obfs.WrapPacketConnSalamander(conn, password)
	case "gecko":
		wrapped, err = obfs.WrapPacketConnGecko(conn, obfs.GeckoOptions{Password: password})
	default:
		err = errors.New("HYSTERIA_OBFS_INVALID")
	}
	if err != nil {
		conn.Close()
	}
	return wrapped, err
}
func (s *hyPackets) ReadPacket() (Datagram, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return Datagram{}, net.ErrClosed
	}
	b, addr, err := s.conn.Receive()
	if err != nil {
		return Datagram{}, err
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return Datagram{}, errors.New("UDP_ADDRESS")
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return Datagram{}, errors.New("UDP_ADDRESS")
	}
	address, err := Address(host, port)
	return Datagram{Address: address, Payload: b}, err
}
func dialHysteriaPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if _, err := Address(host, port); err != nil {
		return nil, err
	}
	client, owner, err := getHysteria(ctx, c)
	if err != nil {
		return nil, err
	}
	conn, err := client.UDP()
	if err != nil {
		owner.Close()
		return nil, err
	}
	return &hyPackets{conn: conn, owner: owner, address: net.JoinHostPort(host, strconv.Itoa(port))}, nil
}
