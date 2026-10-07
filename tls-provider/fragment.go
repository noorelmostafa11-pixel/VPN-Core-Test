package main

import (
	"io"
	"net"
	"sync"
	"time"
)

type wireRange struct{ Lo, Hi int }

func (r wireRange) choose() int { return intRange{r.Lo, r.Hi}.choose() }

type wireMask struct {
	TLSHello          bool `json:"tlshello"`
	Packets, MaxSplit wireRange
	Lengths, Delays   []wireRange
}
type maskedConn struct {
	net.Conn
	mu     sync.Mutex
	masks  []wireMask
	counts []uint64
}
type wirePart struct {
	data  []byte
	delay int
}

func newMaskedConn(conn net.Conn, masks []wireMask) net.Conn {
	return &maskedConn{Conn: conn, masks: masks, counts: make([]uint64, len(masks))}
}
func (c *maskedConn) stage(index int, data []byte) []wirePart {
	m := c.masks[index]
	c.counts[index]++
	count := c.counts[index]
	begin, end := 0, len(data)
	if m.TLSHello {
		if count != 1 || len(data) < 6 || data[0] != 22 {
			return []wirePart{{data, 0}}
		}
		end = 5 + int(data[3])*256 + int(data[4])
		if end > len(data) {
			return []wirePart{{data, 0}}
		}
		begin = 5
	} else if m.Packets.Lo > 0 && (count < uint64(m.Packets.Lo) || count > uint64(m.Packets.Hi)) {
		return []wirePart{{data, 0}}
	}
	if len(m.Lengths) == 0 || len(m.Delays) == 0 {
		return []wirePart{{data, 0}}
	}
	parts := []wirePart{}
	offset, number, maximum := begin, 0, m.MaxSplit.choose()
	for offset < end {
		length := m.Lengths[min(number, len(m.Lengths)-1)].choose()
		n := min(length, end-offset)
		if maximum > 0 && number+1 >= maximum {
			n = end - offset
		}
		if n == 0 && number > 65536 {
			break
		}
		part := wirePart{delay: m.Delays[min(number, len(m.Delays)-1)].choose()}
		if m.TLSHello {
			part.data = []byte{data[0], data[1], data[2], byte(n >> 8), byte(n)}
		}
		part.data = append(part.data, data[offset:offset+n]...)
		parts = append(parts, part)
		offset += n
		number++
	}
	if end < len(data) {
		parts = append(parts, wirePart{data[end:], 0})
	}
	return parts
}
func (c *maskedConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := []wirePart{{data, 0}}
	for stage := range c.masks {
		next := []wirePart{}
		for _, part := range parts {
			split := c.stage(stage, part.data)
			if len(split) > 0 {
				split[len(split)-1].delay += part.delay
			}
			next = append(next, split...)
			if len(next) > 65536 {
				return 0, providerError(407)
			}
		}
		parts = next
	}
	for _, part := range parts {
		wire := part.data
		for len(wire) > 0 {
			n, err := c.Conn.Write(wire)
			if err != nil {
				return 0, err
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
			wire = wire[n:]
		}
		if part.delay > 0 {
			time.Sleep(time.Duration(part.delay) * time.Millisecond)
		}
	}
	return len(data), nil
}
