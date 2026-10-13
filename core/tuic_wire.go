package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

var errTUICWire = errors.New("TUIC_INVALID_COMMAND")

func tuicAddress(a []byte) ([]byte, error) {
	if _, _, err := decodeAddress(a); err != nil {
		return nil, err
	}
	b := append([]byte(nil), a...)
	switch b[0] {
	case 1:
		b[0] = 1
	case 4:
		b[0] = 2
	case 3:
		b[0] = 0
	default:
		return nil, errTUICWire
	}
	return b, nil
}
func readTUICAddress(r io.Reader, allowNone bool) ([]byte, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return nil, err
	}
	switch kind[0] {
	case 0:
		kind[0] = 3
	case 1:
		kind[0] = 1
	case 2:
		kind[0] = 4
	case 255:
		if allowNone {
			return nil, nil
		}
		fallthrough
	default:
		return nil, errTUICWire
	}
	a, err := readAddress(io.MultiReader(bytes.NewReader(kind[:]), r))
	if err == nil {
		_, _, err = decodeAddress(a)
	}
	return a, err
}

type tuicFragment struct {
	assoc, id     uint16
	total, index  byte
	address, body []byte
}

func readTUICFragment(r io.Reader) (tuicFragment, error) {
	var h [8]byte
	var f tuicFragment
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return f, err
	}
	f.assoc = binary.BigEndian.Uint16(h[:])
	f.id = binary.BigEndian.Uint16(h[2:])
	f.total, f.index = h[4], h[5]
	if f.total == 0 || f.total > 128 || f.index >= f.total {
		return f, errTUICWire
	}
	a, err := readTUICAddress(r, f.index != 0)
	if err != nil || (f.index == 0 && a == nil) || (f.index != 0 && a != nil) {
		return f, errTUICWire
	}
	f.address = a
	n := int(binary.BigEndian.Uint16(h[6:]))
	if n > 65507 {
		return f, errTUICWire
	}
	f.body = make([]byte, n)
	_, err = io.ReadFull(r, f.body)
	return f, err
}
func tuicPacketFrames(assoc, id uint16, address, body []byte, native bool) ([][]byte, error) {
	if len(body) > 65507 {
		return nil, errors.New("UDP_DATAGRAM_LENGTH")
	}
	a, err := tuicAddress(address)
	if err != nil {
		return nil, err
	}
	chunk := 65507
	if native {
		chunk = 1000 - 10 - len(a)
	} // Below the minimum QUIC path MTU, even with a domain.
	total := (len(body) + chunk - 1) / chunk
	if total == 0 {
		total = 1
	}
	if total > 128 {
		return nil, errTUICWire
	}
	frames := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		addr := a
		if i != 0 {
			addr = []byte{255}
		}
		n := len(body)
		if n > chunk {
			n = chunk
		}
		wire := make([]byte, 10+len(addr)+n)
		wire[0], wire[1] = 5, 2
		binary.BigEndian.PutUint16(wire[2:], assoc)
		binary.BigEndian.PutUint16(wire[4:], id)
		wire[6], wire[7] = byte(total), byte(i)
		binary.BigEndian.PutUint16(wire[8:], uint16(n))
		copy(wire[10:], addr)
		copy(wire[10+len(addr):], body[:n])
		body = body[n:]
		frames = append(frames, wire)
	}
	return frames, nil
}

type tuicAssembly struct {
	total       byte
	parts       [][]byte
	address     []byte
	size, count int
	created     time.Time
}
type tuicDefrag struct {
	mu      sync.Mutex
	pending map[uint16]*tuicAssembly
	bytes   int
}

func (d *tuicDefrag) add(f tuicFragment) (Datagram, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if f.total == 1 {
		return Datagram{Address: f.address, Payload: f.body}, true, nil
	}
	if d.pending == nil {
		d.pending = map[uint16]*tuicAssembly{}
	}
	for id, p := range d.pending {
		if time.Since(p.created) > 5*time.Second {
			d.bytes -= p.size
			delete(d.pending, id)
		}
	}
	p := d.pending[f.id]
	if p == nil {
		if len(d.pending) >= 8 || d.bytes+len(f.body) > 131072 {
			return Datagram{}, false, errors.New("TUIC_FRAGMENT_LIMIT")
		}
		p = &tuicAssembly{total: f.total, parts: make([][]byte, int(f.total)), created: time.Now()}
		d.pending[f.id] = p
	}
	if p.total != f.total {
		return Datagram{}, false, errTUICWire
	}
	if p.parts[f.index] != nil {
		return Datagram{}, false, nil
	}
	if p.size+len(f.body) > 65507 || d.bytes+len(f.body) > 131072 {
		return Datagram{}, false, errTUICWire
	}
	// A non-nil zero-length slice distinguishes an empty fragment from a missing one.
	p.parts[f.index] = append(make([]byte, 0, len(f.body)), f.body...)
	p.count++
	p.size += len(f.body)
	d.bytes += len(f.body)
	if f.index == 0 {
		p.address = f.address
	}
	if p.count != int(p.total) {
		return Datagram{}, false, nil
	}
	body := make([]byte, 0, p.size)
	for _, part := range p.parts {
		body = append(body, part...)
	}
	d.bytes -= p.size
	delete(d.pending, f.id)
	return Datagram{Address: p.address, Payload: body}, true, nil
}
