package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ServerConfig is explicit and independent of the client's node URI. Client
// credentials and server certificates are never included in inspection output.
type ServerConfig struct {
	Protocol  string                 `json:"protocol"`
	Listen    string                 `json:"listen"`
	UUIDs     []string               `json:"uuids,omitempty"`
	Password  string                 `json:"password,omitempty"`
	Cipher    string                 `json:"cipher,omitempty"`
	CertFile  string                 `json:"cert_file,omitempty"`
	KeyFile   string                 `json:"key_file,omitempty"`
	Options   map[string]string      `json:"options,omitempty"`
	WireGuard *WireGuardServerConfig `json:"wireguard,omitempty"`
}
type serverSpec struct {
	config       ServerConfig
	users        map[[16]byte]bool
	passwordHash string
	tls          *tls.Config
	client       Config
}

func compileServer(c ServerConfig) (serverSpec, error) {
	if c.Protocol == "ssh" {
		_, err := compileSSHServer(c)
		return serverSpec{config: c}, err
	}
	if c.Protocol == "shadowtls" {
		return compileShadowServer(c)
	}
	s := serverSpec{config: c, users: map[[16]byte]bool{}}
	if c.Protocol == "wireguard" {
		return s, validateWireServer(c)
	}
	if c.WireGuard != nil {
		return s, errors.New("SERVER_OPTION_UNSUPPORTED")
	}
	if !contains([]string{"vless", "trojan", "ss", "hysteria", "hysteria2", "anytls", "tuic"}, c.Protocol) {
		return s, errors.New("SERVER_PROTOCOL_UNSUPPORTED")
	}
	host, p, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil {
		return s, errors.New("SERVER_LISTEN_INVALID")
	}
	if _, err = number(p, 0, 65535); err != nil {
		return s, errors.New("SERVER_LISTEN_INVALID")
	}
	if c.CertFile != "" || c.KeyFile != "" {
		pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return s, errors.New("SERVER_CERTIFICATE_INVALID")
		}
		s.tls = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}
	if c.Protocol == "trojan" && s.tls == nil {
		return s, errors.New("TROJAN_SERVER_TLS_REQUIRED")
	}
	if c.Protocol == "anytls" {
		if s.tls == nil {
			return s, errors.New("ANYTLS_SERVER_TLS_REQUIRED")
		}
		if err := validateAnyServer(c); err != nil {
			return s, err
		}
	}
	if c.Protocol == "tuic" {
		if s.tls == nil {
			return s, errors.New("TUIC_SERVER_TLS_REQUIRED")
		}
		if err := validateTUICServer(c); err != nil {
			return s, err
		}
	}
	if c.Protocol == "hysteria" {
		if s.tls == nil {
			return s, errors.New("HYSTERIA1_SERVER_TLS_REQUIRED")
		}
		if err := validateHysteria1Server(c); err != nil {
			return s, err
		}
	}
	if c.Protocol == "hysteria2" {
		if s.tls == nil {
			return s, errors.New("HYSTERIA_SERVER_TLS_REQUIRED")
		}
		if err := validateHysteriaServer(c); err != nil {
			return s, err
		}
	} else if c.Protocol != "hysteria" && c.Protocol != "anytls" && c.Protocol != "tuic" && len(c.Options) > 0 {
		return s, errors.New("SERVER_OPTION_UNSUPPORTED")
	}
	if c.Protocol == "vless" {
		if len(c.UUIDs) == 0 || len(c.UUIDs) > 128 {
			return s, errors.New("SERVER_USERS_INVALID")
		}
		for _, id := range c.UUIDs {
			uuid, err := uuidBytes(id)
			if err != nil || s.users[uuid] {
				return s, errors.New("SERVER_USERS_INVALID")
			}
			s.users[uuid] = true
		}
	} else {
		if c.Password == "" || len(c.Password) > 4096 {
			return s, errors.New("SERVER_PASSWORD_INVALID")
		}
		h := sha256.Sum224([]byte(c.Password))
		s.passwordHash = hex.EncodeToString(h[:])
	}
	if c.Protocol == "ss" {
		if !contains(ssMethods, c.Cipher) || strings.HasPrefix(c.Cipher, "2022-") {
			return s, errors.New("SERVER_SS_METHOD_UNSUPPORTED")
		}
		s.client = defaults()
		s.client.Protocol, s.client.Security, s.client.Transport, s.client.Password, s.client.Cipher = "ss", "none", "raw", c.Password, c.Cipher
	}
	return s, nil
}

// StartServer uses the same bounded flow budget, routing and lifecycle as TUN
// and local proxies. It does not change OS routes or firewall policy.
func (e *Engine) StartServer(c ServerConfig) (net.Addr, error) {
	s, err := compileServer(c)
	if err != nil {
		return nil, err
	}
	if c.Protocol == "shadowtls" {
		return e.startShadowServer(s)
	}
	if c.Protocol == "ssh" {
		return e.startSSHServer(c)
	}
	if c.Protocol == "hysteria" {
		return e.startHy1Server(s)
	}
	if c.Protocol == "hysteria2" {
		return e.startHysteriaServer(s)
	}
	if c.Protocol == "wireguard" {
		return e.startWireServer(c)
	}
	if c.Protocol == "anytls" {
		return e.startAnyServer(s)
	}
	if c.Protocol == "tuic" {
		return e.startTUICServer(s)
	}
	l, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return nil, err
	}
	if !e.track(l) {
		return nil, net.ErrClosed
	}
	if !e.spawn(func() {
		defer l.Close()
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			if !e.acquire() {
				raw.Close()
				continue
			}
			if !e.track(raw) {
				e.release()
				return
			}
			if !e.spawn(func() {
				defer e.release()
				defer e.untrack(raw)
				defer raw.Close()
				e.accepted.Add(1)
				raw.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
				conn := raw
				if s.tls != nil {
					secure := tls.Server(raw, s.tls)
					if secure.HandshakeContext(e.ctx) != nil {
						return
					}
					conn = secure
				}
				e.serveServer(conn, s)
			}) {
				e.release()
				raw.Close()
				return
			}
		}
	}) {
		l.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return l.Addr(), nil
}

func mappedServerAddress(reader io.Reader) ([]byte, error) {
	var h [3]byte
	if _, err := io.ReadFull(reader, h[:]); err != nil {
		return nil, err
	}
	var a []byte
	switch h[2] {
	case 1:
		a = make([]byte, 5)
		a[0] = 1
	case 3:
		a = make([]byte, 17)
		a[0] = 4
	case 2:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, err
		}
		if length[0] == 0 {
			return nil, errors.New("SERVER_ADDRESS_INVALID")
		}
		a = make([]byte, 2+int(length[0]))
		a[0], a[1] = 3, length[0]
	default:
		return nil, errors.New("SERVER_ADDRESS_INVALID")
	}
	offset := 1
	if a[0] == 3 {
		offset = 2
	}
	if _, err := io.ReadFull(reader, a[offset:]); err != nil {
		return nil, err
	}
	return append(a, h[0], h[1]), nil
}

func serverSSConn(raw net.Conn, c Config) (net.Conn, []byte, error) {
	p := newProtocol(c, false)
	spec := ssCipherSpec(c.Cipher)
	if p.none {
		a, err := readAddress(raw)
		return raw, a, err
	}
	p.master = masterKey(c.Password, spec.key)
	var prefix []byte
	var err error
	if p.stream {
		p.upIV = randomBytes(spec.iv)
		p.upCipher, err = ssStreamCipher(c.Cipher, p.master, p.upIV, false)
		prefix = p.upIV
	} else {
		p.upSalt = randomBytes(spec.key)
		p.upKey, err = subkey(p.master, p.upSalt, spec.key, false)
		if err == nil {
			p.upAEAD, err = cipherAEAD(p.method, p.upKey)
		}
		p.upIV = make([]byte, spec.iv)
		prefix = p.upSalt
	}
	if err != nil {
		return nil, nil, err
	}
	conn := &protocolConn{Conn: raw, p: p}
	a, err := readAddress(conn)
	if err != nil {
		return nil, nil, err
	}
	// Do not leak a salt/IV before validating the incoming encrypted address.
	if err = writeAll(raw, prefix); err != nil {
		return nil, nil, err
	}
	return conn, a, nil
}

func (e *Engine) serveServer(raw net.Conn, s serverSpec) {
	client := raw
	var address []byte
	var err error
	udp := false
	switch s.config.Protocol {
	case "vless":
		var header [18]byte
		if _, err = io.ReadFull(raw, header[:]); err != nil {
			return
		}
		var id [16]byte
		copy(id[:], header[1:17])
		if header[0] != 0 || !s.users[id] || header[17] != 0 {
			return
		}
		var command [1]byte
		if _, err = io.ReadFull(raw, command[:]); err != nil {
			return
		}
		if command[0] != 1 && command[0] != 2 {
			return
		}
		udp = command[0] == 2
		address, err = mappedServerAddress(raw)
	case "trojan":
		var header [59]byte
		if _, err = io.ReadFull(raw, header[:]); err != nil {
			return
		}
		if !bytesEqual(header[:56], []byte(s.passwordHash)) || header[56] != 13 || header[57] != 10 || header[58] != 1 && header[58] != 3 {
			return
		}
		udp = header[58] == 3
		address, err = readAddress(raw)
		if err == nil {
			var crlf [2]byte
			_, err = io.ReadFull(raw, crlf[:])
			if crlf != [2]byte{13, 10} {
				return
			}
		}
	case "ss":
		client, address, err = serverSSConn(raw, s.client)
	}
	if err != nil {
		return
	}
	host, port, err := decodeAddress(address)
	if err != nil {
		return
	}
	ctx := e.flowContext(e.ctx, raw.RemoteAddr(), host)
	if udp {
		if s.config.Protocol == "vless" && writeAll(raw, []byte{0, 0}) != nil {
			return
		}
		packets := &streamPackets{Conn: client, address: address, trojan: s.config.Protocol == "trojan"}
		e.serveServerPackets(ctx, packets)
		return
	}
	server, err := e.dialTCP(ctx, host, port)
	if err != nil {
		e.emit(dialFailure(e.next.Add(1), err))
		return
	}
	if !e.track(server) {
		return
	}
	defer e.untrack(server)
	defer server.Close()
	if s.config.Protocol == "vless" && writeAll(raw, []byte{0, 0}) != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	e.relay(client, server)
}

func (e *Engine) serveServerPackets(ctx context.Context, client *streamPackets) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client.SetDeadline(time.Time{})
	var mu sync.Mutex
	peers := map[string]PacketStream{}
	var workers sync.WaitGroup
	closePeers := func() {
		client.Close()
		mu.Lock()
		list := make([]PacketStream, 0, len(peers))
		for _, p := range peers {
			list = append(list, p)
		}
		mu.Unlock()
		for _, p := range list {
			p.Close()
		}
	}
	var activity atomic.Int64
	activity.Store(time.Now().UnixNano())
	finished, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		timer := time.NewTimer(e.config.IdleTimeout)
		defer timer.Stop()
		for {
			select {
			case <-finished:
				return
			case <-ctx.Done():
				closePeers()
				return
			case <-timer.C:
				idle := time.Since(time.Unix(0, activity.Load()))
				if idle >= e.config.IdleTimeout {
					cancel()
					closePeers()
					return
				}
				timer.Reset(e.config.IdleTimeout - idle)
			}
		}
	}()
	defer func() { close(finished); cancel(); closePeers(); workers.Wait(); <-watchDone }()
	for {
		packet, err := client.ReadPacket()
		if err != nil {
			return
		}
		key := string(packet.Address)
		mu.Lock()
		server := peers[key]
		count := len(peers)
		mu.Unlock()
		if server == nil {
			if count >= 16 {
				return
			}
			host, port, err := decodeAddress(packet.Address)
			if err != nil {
				return
			}
			server, err = e.dialPacket(e.flowContext(ctx, client.RemoteAddr(), host), host, port)
			if err != nil {
				continue
			}
			if !e.track(server) {
				return
			}
			mu.Lock()
			peers[key] = server
			mu.Unlock()
			workers.Add(1)
			go func(key string, s PacketStream) {
				defer workers.Done()
				defer e.untrack(s)
				defer s.Close()
				defer func() {
					mu.Lock()
					if peers[key] == s {
						delete(peers, key)
					}
					mu.Unlock()
				}()
				for {
					packet, err := s.ReadPacket()
					if err != nil {
						return
					}
					if client.trojan {
						client.writeMu.Lock()
						err = writeAll(client.Conn, join(packet.Address, word(len(packet.Payload)), []byte{13, 10}, packet.Payload))
						client.writeMu.Unlock()
					} else {
						err = client.WritePacket(packet.Payload)
					}
					if err != nil {
						cancel()
						client.Close()
						return
					}
					e.down.Add(uint64(len(packet.Payload)))
					activity.Store(time.Now().UnixNano())
				}
			}(key, server)
		}
		if err = server.WritePacket(packet.Payload); err != nil {
			server.Close()
			continue
		}
		e.up.Add(uint64(len(packet.Payload)))
		activity.Store(time.Now().UnixNano())
	}
}
