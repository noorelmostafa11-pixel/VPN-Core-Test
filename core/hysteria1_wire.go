package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errHy1Wire = errors.New("HYSTERIA1_WIRE_INVALID")

func hy1Text(r io.Reader, limit int) (string, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > limit {
		return "", errHy1Wire
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return string(b), err
}
func hy1AppendText(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}
func hy1Hello(ok byte, tx, rx uint64, message string) []byte {
	b := []byte{ok}
	b = binary.BigEndian.AppendUint64(b, tx)
	b = binary.BigEndian.AppendUint64(b, rx)
	return hy1AppendText(b, message)
}
func hy1ReadHello(r io.Reader) (byte, uint64, uint64, string, error) {
	var h [17]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, 0, 0, "", err
	}
	tx, rx := binary.BigEndian.Uint64(h[1:]), binary.BigEndian.Uint64(h[9:])
	message, err := hy1Text(r, 4096)
	if tx == 0 || rx == 0 || tx > 12500000000 || rx > 12500000000 {
		return 0, 0, 0, "", errHy1Wire
	}
	return h[0], tx, rx, message, err
}
func hy1Request(udp bool, host string, port int) ([]byte, error) {
	if _, err := Address(host, port); err != nil {
		return nil, err
	}
	b := []byte{0}
	if udp {
		b[0] = 1
	}
	b = hy1AppendText(b, host)
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}
func hy1ReadRequest(r io.Reader) (bool, string, int, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return false, "", 0, err
	}
	if typ[0] > 1 {
		return false, "", 0, errHy1Wire
	}
	host, err := hy1Text(r, 253)
	if err != nil {
		return false, "", 0, err
	}
	var port [2]byte
	if _, err = io.ReadFull(r, port[:]); err != nil {
		return false, "", 0, err
	}
	p := int(binary.BigEndian.Uint16(port[:]))
	// The original client opens UDP sessions with an unspecified destination.
	if typ[0] == 1 && host == "" && p == 0 {
		return true, "", 0, nil
	}
	_, err = Address(host, p)
	return typ[0] == 1, host, p, err
}
func hy1Response(ok bool, id uint32, message string) []byte {
	b := []byte{0}
	if ok {
		b[0] = 1
	}
	b = binary.BigEndian.AppendUint32(b, id)
	return hy1AppendText(b, message)
}
func hy1ReadResponse(r io.Reader) (uint32, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, err
	}
	_, err := hy1Text(r, 4096)
	if err != nil {
		return 0, err
	}
	if h[0] != 1 {
		return 0, errors.New("HYSTERIA1_DESTINATION_REJECTED")
	}
	return binary.BigEndian.Uint32(h[1:]), nil
}

type hy1Fragment struct {
	session       uint32
	id            uint16
	index, total  byte
	address, body []byte
}

func hy1ReadFragment(wire []byte) (hy1Fragment, error) {
	var f hy1Fragment
	r := bytes.NewReader(wire)
	var id [4]byte
	if _, err := io.ReadFull(r, id[:]); err != nil {
		return f, err
	}
	f.session = binary.BigEndian.Uint32(id[:])
	host, err := hy1Text(r, 253)
	if err != nil {
		return f, err
	}
	var h [8]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return f, err
	}
	f.address, err = Address(host, int(binary.BigEndian.Uint16(h[:])))
	if err != nil {
		return f, err
	}
	f.id, f.index, f.total = binary.BigEndian.Uint16(h[2:]), h[4], h[5]
	n := int(binary.BigEndian.Uint16(h[6:]))
	if n != r.Len() || n > 65507 || f.total == 0 || f.total > 128 || (f.total != 1 && (f.id == 0 || f.index >= f.total)) {
		return f, errHy1Wire
	}
	if f.total == 1 {
		f.index = 0
	}
	f.body = make([]byte, n)
	_, err = io.ReadFull(r, f.body)
	return f, err
}
func hy1Frames(session uint32, id uint16, address, body []byte) ([][]byte, error) {
	if len(body) > 65507 {
		return nil, errors.New("UDP_DATAGRAM_LENGTH")
	}
	host, port, err := decodeAddress(address)
	if err != nil {
		return nil, err
	}
	header := binary.BigEndian.AppendUint32(nil, session)
	header = hy1AppendText(header, host)
	header = binary.BigEndian.AppendUint16(header, uint16(port))
	// The 1000-byte advertised limit includes DATAGRAM type/length (3 bytes).
	chunk := 997 - len(header) - 6
	total := max(1, (len(body)+chunk-1)/chunk)
	if total > 128 || (total > 1 && id == 0) {
		return nil, errHy1Wire
	}
	frames := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		n := min(chunk, len(body))
		b := append([]byte(nil), header...)
		b = binary.BigEndian.AppendUint16(b, id)
		b = append(b, byte(i), byte(total))
		b = binary.BigEndian.AppendUint16(b, uint16(n))
		b = append(b, body[:n]...)
		body = body[n:]
		frames = append(frames, b)
	}
	return frames, nil
}

type hy1Assembly struct {
	address     []byte
	parts       [][]byte
	created     time.Time
	size, count int
}
type hy1Defrag struct {
	mu      sync.Mutex
	pending map[uint16]*hy1Assembly
	size    int
}

func (d *hy1Defrag) add(f hy1Fragment) (Datagram, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if f.total == 1 {
		return Datagram{Address: f.address, Payload: f.body}, true, nil
	}
	if d.pending == nil {
		d.pending = map[uint16]*hy1Assembly{}
	}
	for id, p := range d.pending {
		if time.Since(p.created) > 5*time.Second {
			d.size -= p.size
			delete(d.pending, id)
		}
	}
	p := d.pending[f.id]
	if p == nil {
		if len(d.pending) >= 8 {
			return Datagram{}, false, errors.New("HYSTERIA1_FRAGMENT_LIMIT")
		}
		p = &hy1Assembly{address: f.address, parts: make([][]byte, int(f.total)), created: time.Now()}
		d.pending[f.id] = p
	}
	if len(p.parts) != int(f.total) || !bytes.Equal(p.address, f.address) {
		return Datagram{}, false, errHy1Wire
	}
	if p.parts[f.index] != nil {
		return Datagram{}, false, nil
	}
	if p.size+len(f.body) > 65507 || d.size+len(f.body) > 131072 {
		return Datagram{}, false, errHy1Wire
	}
	p.parts[f.index] = append(make([]byte, 0, len(f.body)), f.body...)
	p.count++
	p.size += len(f.body)
	d.size += len(f.body)
	if p.count != len(p.parts) {
		return Datagram{}, false, nil
	}
	body := make([]byte, 0, p.size)
	for _, part := range p.parts {
		body = append(body, part...)
	}
	d.size -= p.size
	delete(d.pending, f.id)
	return Datagram{Address: p.address, Payload: body}, true, nil
}

// Wrapping intentionally hides UDP optimizations: xplus changes packet bytes.
type hy1XPlus struct {
	net.PacketConn
	key     []byte
	readMu  sync.Mutex
	readBuf []byte
}

func wrapHy1Packet(c net.PacketConn, options map[string]string) net.PacketConn {
	if options["obfs"] != "xplus" {
		return c
	}
	return &hy1XPlus{PacketConn: c, key: []byte(option(options, "", "obfsparam", "obfs-password"))}
}
func (c *hy1XPlus) WriteTo(b []byte, addr net.Addr) (int, error) {
	wire := make([]byte, len(b)+16)
	if _, err := rand.Read(wire[:16]); err != nil {
		return 0, err
	}
	key := sha256.Sum256(append(append([]byte(nil), c.key...), wire[:16]...))
	for i := range b {
		wire[i+16] = b[i] ^ key[i%32]
	}
	n, err := c.PacketConn.WriteTo(wire, addr)
	if err != nil {
		return 0, err
	}
	if n != len(wire) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}
func (c *hy1XPlus) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readBuf == nil {
		c.readBuf = make([]byte, 65535)
	}
	wire := c.readBuf
	for {
		n, addr, err := c.PacketConn.ReadFrom(wire)
		if err != nil {
			return 0, addr, err
		}
		if n <= 16 || n-16 > len(b) {
			continue
		}
		key := sha256.Sum256(append(append([]byte(nil), c.key...), wire[:16]...))
		for i := 0; i < n-16; i++ {
			b[i] = wire[i+16] ^ key[i%32]
		}
		return n - 16, addr, nil
	}
}
