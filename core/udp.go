package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"lukechampine.com/blake3"
	"net"
	"sync"
	"time"
)

type Datagram struct{ Address, Payload []byte }
type PacketStream interface {
	ReadPacket() (Datagram, error)
	WritePacket([]byte) error
	Close() error
	SetDeadline(time.Time) error
}

func addressSize(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, nil
	}
	n := 0
	switch b[0] {
	case 1:
		n = 7
	case 4:
		n = 19
	case 3:
		if len(b) < 2 {
			return 0, nil
		}
		if b[1] == 0 {
			return 0, errors.New("UDP_ADDRESS")
		}
		n = int(b[1]) + 4
	default:
		return 0, errors.New("UDP_ADDRESS")
	}
	if len(b) < n {
		return 0, nil
	}
	if b[n-2] == 0 && b[n-1] == 0 {
		return 0, errors.New("UDP_PORT")
	}
	return n, nil
}
func decodeAddress(b []byte) (string, int, error) {
	n, e := addressSize(b)
	if e != nil || n == 0 {
		return "", 0, errors.New("DESTINATION_TRUNCATED")
	}
	host := ""
	if b[0] == 3 {
		host = string(b[2 : n-2])
		if !hostValid(host) {
			return "", 0, errors.New("UDP_ADDRESS")
		}
	} else {
		host = net.IP(b[1 : n-2]).String()
	}
	return host, getWord(b, n-2), nil
}
func readAddress(r io.Reader) ([]byte, error) {
	a := make([]byte, 1)
	if _, e := io.ReadFull(r, a); e != nil {
		return nil, e
	}
	n := 0
	switch a[0] {
	case 1:
		n = 6
	case 4:
		n = 18
	case 3:
		var l [1]byte
		if _, e := io.ReadFull(r, l[:]); e != nil {
			return nil, e
		}
		if l[0] == 0 {
			return nil, errors.New("ADDRESS_EMPTY")
		}
		a = append(a, l[0])
		n = int(l[0]) + 2
	default:
		return nil, errors.New("ADDRESS_TYPE")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return append(a, b...), e
}

type streamPackets struct {
	net.Conn
	address       []byte
	trojan, vmess bool
	writeMu       sync.Mutex
}

func (s *streamPackets) WritePacket(b []byte) error {
	if len(b) > 65507 {
		return errors.New("UDP_DATAGRAM_LENGTH")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.vmess {
		if len(b) == 0 {
			return errors.New("VMESS_UDP_EMPTY")
		}
		p := s.Conn.(*protocolConn)
		wire, e := p.p.vmFrame(b)
		if e != nil {
			return e
		}
		return writeAll(p.Conn, wire)
	}
	out := word(len(b))
	if s.trojan {
		out = join(s.address, out, []byte{13, 10})
	}
	return writeAll(s.Conn, append(out, b...))
}
func (s *streamPackets) ReadPacket() (Datagram, error) {
	a := s.address
	var e error
	if s.trojan {
		a, e = readAddress(s.Conn)
		if e != nil {
			return Datagram{}, e
		}
	}
	var l [2]byte
	if _, e = io.ReadFull(s.Conn, l[:]); e != nil {
		return Datagram{}, e
	}
	n := getWord(l[:], 0)
	if n > 65507 {
		return Datagram{}, errors.New("UDP_DATAGRAM_LENGTH")
	}
	if s.trojan {
		var crlf [2]byte
		if _, e = io.ReadFull(s.Conn, crlf[:]); e != nil {
			return Datagram{}, e
		}
		if crlf != [2]byte{13, 10} {
			return Datagram{}, errors.New("TROJAN_UDP_DELIMITER")
		}
	}
	b := make([]byte, n)
	_, e = io.ReadFull(s.Conn, b)
	return Datagram{a, b}, e
}

type replayWindow struct {
	max         uint64
	initialized bool
	seen        [2048]uint64
	valid       [2048]bool
}

func (r *replayWindow) accept(id uint64) error {
	if r.initialized && id <= r.max && r.max-id >= 2048 {
		return errors.New("SS_UDP_REPLAY")
	}
	slot := id % 2048
	if r.valid[slot] && r.seen[slot] == id {
		return errors.New("SS_UDP_REPLAY")
	}
	if !r.initialized || id > r.max {
		r.max = id
		r.initialized = true
	}
	r.seen[slot] = id
	r.valid[slot] = true
	return nil
}

type udpSession struct {
	replay replayWindow
	last   time.Time
}
type ssUDP struct {
	c               Config
	spec            ssSpec
	modern          bool
	keys            [][]byte
	master, session []byte
	counter         uint64
	sessions        map[string]*udpSession
	salts           map[[32]byte]bool
	order           [][32]byte
}

func newSSUDP(c Config) (*ssUDP, error) {
	s := &ssUDP{c: c, spec: ssCipherSpec(c.Cipher), modern: stringsHasModern(c.Cipher), sessions: map[string]*udpSession{}, salts: map[[32]byte]bool{}}
	if s.modern {
		keys, e := ssKeys(c)
		if e != nil {
			return nil, e
		}
		s.keys = keys
		s.master = keys[len(keys)-1]
		s.session = randomBytes(8)
	} else {
		s.master = masterKey(c.Password, s.spec.key)
	}
	return s, nil
}
func stringsHasModern(s string) bool { return len(s) >= 12 && s[:12] == "2022-blake3-" }
func (s *ssUDP) method() string {
	if s.modern {
		return s.c.Cipher[12:]
	}
	return s.c.Cipher
}
func (s *ssUDP) stream(b, iv []byte, decrypt bool) ([]byte, error) {
	c, e := ssStreamCipher(s.c.Cipher, s.master, iv, decrypt)
	if e != nil {
		return nil, e
	}
	out := make([]byte, len(b))
	c.XORKeyStream(out, b)
	return out, nil
}
func (s *ssUDP) seal(key, nonce, b []byte, method string) ([]byte, error) {
	a, e := cipherAEAD(method, key)
	if e != nil {
		return nil, e
	}
	return a.Seal(nil, nonce, b, nil), nil
}
func (s *ssUDP) open(key, nonce, b []byte, method string) ([]byte, error) {
	a, e := cipherAEAD(method, key)
	if e != nil {
		return nil, e
	}
	return a.Open(nil, nonce, b, nil)
}
func (s *ssUDP) encode(packet Datagram) ([]byte, error) {
	body := join(packet.Address, packet.Payload)
	var wire []byte
	var e error
	switch {
	case s.c.Cipher == "none" || s.c.Cipher == "plain":
		wire = body
	case s.spec.stream:
		iv := randomBytes(s.spec.iv)
		b, e := s.stream(body, iv, false)
		if e != nil {
			return nil, e
		}
		wire = join(iv, b)
	case !s.modern:
		salt := randomBytes(s.spec.key)
		key, e := subkey(s.master, salt, s.spec.key, false)
		if e != nil {
			return nil, e
		}
		b, e := s.seal(key, make([]byte, s.spec.iv), body, s.method())
		if e != nil {
			return nil, e
		}
		wire = join(salt, b)
	default:
		if s.counter == ^uint64(0) {
			return nil, errors.New("SS_UDP_COUNTER")
		}
		separate := join(s.session, wide(s.counter))
		s.counter++
		main := join([]byte{0}, wide(uint64(time.Now().Unix())), []byte{0, 0}, body)
		if s.method() == "chacha20-poly1305" {
			wire = randomBytes(24)
			b, e := s.seal(s.master, wire, join(separate, main), "xchacha20-ietf-poly1305")
			if e != nil {
				return nil, e
			}
			wire = append(wire, b...)
		} else {
			wire, e = aesECB(s.keys[0], separate, false)
			if e != nil {
				return nil, e
			}
			for i := 0; i+1 < len(s.keys); i++ {
				h := blake3.Sum256(s.keys[i+1])
				id := h[:16]
				for j := range id {
					id[j] ^= separate[j]
				}
				b, e := aesECB(s.keys[i], id, false)
				if e != nil {
					return nil, e
				}
				wire = append(wire, b...)
			}
			key, e := subkey(s.master, s.session, s.spec.key, true)
			if e != nil {
				return nil, e
			}
			b, e := s.seal(key, separate[4:], main, s.method())
			if e != nil {
				return nil, e
			}
			wire = append(wire, b...)
		}
	}
	if len(wire) > 65507 {
		return nil, errors.New("UDP_DATAGRAM_LENGTH")
	}
	return wire, e
}
func (s *ssUDP) decode(wire []byte) (Datagram, error) {
	var body, salt, separate []byte
	var e error
	switch {
	case s.c.Cipher == "none" || s.c.Cipher == "plain":
		body = wire
	case s.spec.stream:
		if len(wire) < s.spec.iv {
			return Datagram{}, errors.New("SS_UDP_TRUNCATED")
		}
		body, e = s.stream(wire[s.spec.iv:], wire[:s.spec.iv], true)
	case !s.modern:
		if len(wire) < s.spec.key+16 {
			return Datagram{}, errors.New("SS_UDP_TRUNCATED")
		}
		salt = wire[:s.spec.key]
		key, er := subkey(s.master, salt, s.spec.key, false)
		if er != nil {
			return Datagram{}, er
		}
		body, e = s.open(key, make([]byte, s.spec.iv), wire[s.spec.key:], s.method())
	default:
		if s.method() == "chacha20-poly1305" {
			if len(wire) < 40 {
				return Datagram{}, errors.New("SS_UDP_TRUNCATED")
			}
			plain, er := s.open(s.master, wire[:24], wire[24:], "xchacha20-ietf-poly1305")
			if er != nil {
				return Datagram{}, er
			}
			if len(plain) < 16 {
				return Datagram{}, errors.New("SS_UDP_TRUNCATED")
			}
			separate, body = plain[:16], plain[16:]
		} else {
			if len(wire) < 32 {
				return Datagram{}, errors.New("SS_UDP_TRUNCATED")
			}
			separate, e = aesECB(s.master, wire[:16], true)
			if e != nil {
				return Datagram{}, e
			}
			key, er := subkey(s.master, separate[:8], s.spec.key, true)
			if er != nil {
				return Datagram{}, er
			}
			body, e = s.open(key, separate[4:], wire[16:], s.method())
		}
		if e != nil {
			return Datagram{}, e
		}
		if bytesEqual(separate[:8], s.session) || len(body) < 19 || body[0] != 1 {
			return Datagram{}, errors.New("SS_UDP_RESPONSE_TYPE")
		}
		stamp, now := int64(binary.BigEndian.Uint64(body[1:9])), time.Now().Unix()
		if stamp < now-30 || stamp > now+30 || !bytesEqual(body[9:17], s.session) {
			return Datagram{}, errors.New("SS_UDP_SESSION")
		}
		padding := getWord(body, 17)
		if len(body) < 19+padding {
			return Datagram{}, errors.New("SS_UDP_TRUNCATED")
		}
		body = body[19+padding:]
	}
	if e != nil {
		return Datagram{}, e
	}
	n, e := addressSize(body)
	if e != nil || n == 0 {
		return Datagram{}, errors.New("SS_UDP_ADDRESS")
	}
	if _, _, e = decodeAddress(body[:n]); e != nil {
		return Datagram{}, e
	}
	if s.modern {
		key := string(separate[:8])
		entry := s.sessions[key]
		if entry == nil {
			now := time.Now()
			for k, v := range s.sessions {
				if now.Sub(v.last) > time.Minute {
					delete(s.sessions, k)
				}
			}
			if len(s.sessions) >= 64 {
				return Datagram{}, errors.New("SS_UDP_SESSION_LIMIT")
			}
			entry = &udpSession{}
			s.sessions[key] = entry
		}
		if e = entry.replay.accept(binary.BigEndian.Uint64(separate[8:])); e != nil {
			return Datagram{}, e
		}
		entry.last = time.Now()
	} else if len(salt) > 0 {
		id := sha256.Sum256(salt)
		if s.salts[id] {
			return Datagram{}, errors.New("SS_UDP_REPLAY")
		}
		s.salts[id] = true
		s.order = append(s.order, id)
		if len(s.order) > 4096 {
			delete(s.salts, s.order[0])
			s.order = s.order[1:]
		}
	}
	return Datagram{append([]byte{}, body[:n]...), append([]byte{}, body[n:]...)}, nil
}

type ssPackets struct {
	net.Conn
	codec   *ssUDP
	address []byte
	writeMu sync.Mutex
}

func (s *ssPackets) WritePacket(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	wire, e := s.codec.encode(Datagram{s.address, b})
	if e != nil {
		return e
	}
	_, e = s.Conn.Write(wire)
	return e
}
func (s *ssPackets) ReadPacket() (Datagram, error) {
	b := make([]byte, 65536)
	n, e := s.Conn.Read(b)
	if e != nil {
		return Datagram{}, e
	}
	packet, err := s.codec.decode(b[:n])
	if err != nil {
		return Datagram{}, packetRejected{err}
	}
	return packet, nil
}
func DialPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if c.Protocol == "ssh" {
		return nil, errors.New("SSH_TCP_ONLY")
	}
	if c.Protocol == "wireguard" {
		return dialWireGuardPacket(ctx, c, host, port)
	}
	if c.Protocol == "anytls" {
		return dialAnyTLSPacket(ctx, c, host, port)
	}
	if c.Routing != nil {
		return nil, errors.New("ROUTE_ENGINE_REQUIRED")
	}
	if c.Protocol == "hysteria2" {
		return dialHysteriaPacket(ctx, c, host, port)
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if isProxyProtocol(c.Protocol) {
		return dialProxyPacket(ctx, c, host, port)
	}
	a, e := Address(host, port)
	if e != nil {
		return nil, e
	}
	if c.Protocol == "ss" {
		codec, e := newSSUDP(c)
		if e != nil {
			return nil, e
		}
		conn, e := outboundDial(ctx, "udp", net.JoinHostPort(c.Server, itoa(c.Port)), c.ConnectTimeout)
		if e != nil {
			return nil, e
		}
		return &ssPackets{Conn: conn, codec: codec, address: a}, nil
	}
	conn, e := dialProtocol(ctx, c, host, port, true)
	if e != nil {
		return nil, e
	}
	return &streamPackets{Conn: conn, address: a, trojan: c.Protocol == "trojan", vmess: c.Protocol == "vmess"}, nil
}
