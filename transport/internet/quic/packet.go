package quic

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

// These packet layouts match the pinned main's packet_header.go. Readers strip
// the configured fixed-size camouflage, as the historical transport did; it is
// not authentication. AEAD (when selected) authenticates the inner QUIC packet.
type packetHeader struct {
	kind       string
	sequence   uint32
	id         uint16
	dtlsLength uint16
	dns        []byte
}

func newHeader(kind, domain string) (*packetHeader, error) {
	h := &packetHeader{kind: strings.ToLower(strings.TrimSpace(kind)), dtlsLength: 17}
	if h.kind == "wechat-video" {
		h.kind = "wechat"
	}
	switch h.kind {
	case "", "none", "srtp", "utp", "dtls", "wechat", "wireguard":
	case "dns":
		if domain == "" {
			domain = "www.example.com"
		}
		if len(domain) > 254 {
			return nil, errors.New("legacy QUIC: invalid DNS camouflage domain")
		}
		h.dns = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, errors.New("legacy QUIC: invalid DNS camouflage domain")
			}
			h.dns = append(h.dns, byte(len(label)))
			h.dns = append(h.dns, label...)
		}
		h.dns = append(h.dns, 0, 0, 1, 0, 1)
	default:
		return nil, errors.New("legacy QUIC: unsupported packet header")
	}
	if h.kind != "dns" && domain != "" {
		return nil, errors.New("legacy QUIC: domain requires DNS header")
	}
	var seed [6]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	h.sequence, h.id = binary.BigEndian.Uint32(seed[:4]), binary.BigEndian.Uint16(seed[4:])
	if h.kind == "dtls" {
		h.sequence = 0
	}
	return h, nil
}

func (h *packetHeader) size() int {
	switch h.kind {
	case "srtp", "utp", "wireguard":
		return 4
	case "dtls", "wechat":
		return 13
	case "dns":
		return len(h.dns)
	default:
		return 0
	}
}

func (h *packetHeader) appendTo(dst []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, h.size())...)
	p := dst[start:]
	h.sequence++
	switch h.kind {
	case "srtp":
		p[0], p[1] = 0xb5, 0xe8
		binary.BigEndian.PutUint16(p[2:], uint16(h.sequence))
	case "utp":
		binary.BigEndian.PutUint16(p, h.id)
		p[2] = 1
	case "wireguard":
		p[0] = 4
	case "wechat":
		copy(p, []byte{0xa1, 8, 0, 0, 0, 0, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30})
		binary.BigEndian.PutUint32(p[2:], h.sequence)
	case "dtls":
		p[0], p[1], p[2] = 23, 254, 253
		binary.BigEndian.PutUint16(p[3:], h.id)
		binary.BigEndian.PutUint32(p[7:], h.sequence-1)
		binary.BigEndian.PutUint16(p[11:], h.dtlsLength)
		h.dtlsLength += 17
		if h.dtlsLength > 100 {
			h.dtlsLength -= 50
		}
	case "dns":
		copy(p, h.dns)
		binary.BigEndian.PutUint16(p, uint16(h.sequence))
	}
	return dst
}

type packetConn struct {
	net.PacketConn
	header  *packetHeader
	auth    cipher.AEAD
	writeMu sync.Mutex
}

var packetBuffers = sync.Pool{New: func() any { return make([]byte, 65536) }}

func wrapPacket(raw net.PacketConn, config *Config) (*packetConn, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	header, err := config.packetHeader()
	if err != nil {
		return nil, err
	}
	auth, err := config.auth()
	if err != nil {
		return nil, err
	}
	return &packetConn{PacketConn: raw, header: header, auth: auth}, nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, nil, err
		}
		if n <= c.header.size() {
			continue
		}
		payload := buffer[c.header.size():n]
		if c.auth != nil {
			nonce := c.auth.NonceSize()
			if len(payload) < nonce+c.auth.Overhead() || len(payload)-nonce-c.auth.Overhead() > len(p) {
				continue
			}
			payload, err = c.auth.Open(payload[nonce:nonce], payload[:nonce], payload[nonce:], nil)
			if err != nil {
				continue
			}
		}
		if len(payload) > len(p) {
			continue
		}
		return copy(p, payload), addr, nil
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	overhead := c.header.size()
	if c.auth != nil {
		overhead += c.auth.NonceSize() + c.auth.Overhead()
	}
	if len(p) > 65507-overhead {
		return 0, errors.New("legacy QUIC: oversized UDP payload")
	}
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	wire := c.header.appendTo(buffer[:0])
	if c.auth == nil {
		wire = append(wire, p...)
	} else {
		start := len(wire)
		wire = wire[:start+c.auth.NonceSize()]
		nonce := wire[start:]
		if _, err := rand.Read(nonce); err != nil {
			return 0, err
		}
		wire = c.auth.Seal(wire, nonce, p, nil)
	}
	n, err := c.PacketConn.WriteTo(wire, addr)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) SetReadBuffer(n int) error {
	if socket, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return socket.SetReadBuffer(n)
	}
	return nil
}

func (c *packetConn) SetWriteBuffer(n int) error {
	if socket, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return socket.SetWriteBuffer(n)
	}
	return nil
}
