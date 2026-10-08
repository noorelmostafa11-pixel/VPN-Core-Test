// Project-owned mKCP wire codec and bounded ARQ stream. This is not the
// standard kcp-go wire format and imports no proxy-engine code.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type kcpOptions struct {
	Seed         *string `json:"seed"`
	MTU          int     `json:"mtu"`
	TTI          int     `json:"tti"`
	Header       string  `json:"header"`
	HeaderDomain string  `json:"header_domain"`
}

func (o kcpOptions) validate() (kcpOptions, error) {
	if o.MTU == 0 {
		o.MTU = 1350
	}
	if o.TTI == 0 {
		o.TTI = 50
	}
	if o.MTU < 576 || o.MTU > 1460 || o.TTI < 10 || o.TTI > 100 {
		return o, providerError(400)
	}
	if _, err := newPacketHeader(o.Header, o.HeaderDomain); err != nil {
		return o, providerError(400)
	}
	return o, nil
}

type kcpSegment struct {
	number, timestamp uint32
	payload           []byte
	sent              time.Time
	tries             int
}
type mkcpConn struct {
	socket                      net.Conn
	options                     kcpOptions
	aead                        cipher.AEAD
	header                      *packetHeader
	conv                        uint16
	mu                          sync.Mutex
	changed                     *sync.Cond
	up, down                    []byte
	err                         error
	writeEnd, readEnd           bool
	readDeadline, writeDeadline time.Time
	wake                        chan struct{}
	stop                        chan struct{}
	once                        sync.Once
}

func dialMKCP(ctx context.Context, address string, o kcpOptions) (*mkcpConn, error) {
	o, e := o.validate()
	if e != nil {
		return nil, e
	}
	raw, e := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if e != nil {
		return nil, e
	}
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	header, _ := newPacketHeader(o.Header, o.HeaderDomain)
	c := &mkcpConn{socket: raw, options: o, header: header, conv: binary.BigEndian.Uint16(b), wake: make(chan struct{}, 1), stop: make(chan struct{})}
	c.changed = sync.NewCond(&c.mu)
	if o.Seed != nil {
		key := sha256.Sum256([]byte(*o.Seed))
		block, _ := aes.NewCipher(key[:16])
		c.aead, _ = cipher.NewGCM(block)
	}
	go c.run()
	return c, nil
}
func (c *mkcpConn) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *mkcpConn) fail(e error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = e
		c.changed.Broadcast()
		c.mu.Unlock()
		close(c.stop)
		_ = c.socket.Close()
	})
}
func (c *mkcpConn) Close() error         { c.fail(net.ErrClosed); return nil }
func (c *mkcpConn) LocalAddr() net.Addr  { return c.socket.LocalAddr() }
func (c *mkcpConn) RemoteAddr() net.Addr { return c.socket.RemoteAddr() }
func (c *mkcpConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *mkcpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.changed.Broadcast()
	c.mu.Unlock()
	if !t.IsZero() {
		time.AfterFunc(max(time.Until(t), 0), func() { c.mu.Lock(); c.changed.Broadcast(); c.mu.Unlock() })
	}
	return nil
}
func (c *mkcpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.changed.Broadcast()
	c.mu.Unlock()
	if !t.IsZero() {
		time.AfterFunc(max(time.Until(t), 0), func() { c.mu.Lock(); c.changed.Broadcast(); c.mu.Unlock() })
	}
	return nil
}
func (c *mkcpConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.down) == 0 && c.err == nil && !c.readEnd {
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.changed.Wait()
	}
	if len(c.down) > 0 {
		n := copy(b, c.down)
		c.down = c.down[n:]
		c.signal()
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return 0, io.EOF
}
func (c *mkcpConn) Write(b []byte) (int, error) {
	if len(b) > bufferLimit {
		return 0, io.ErrShortBuffer
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.up)+len(b) > bufferLimit && c.err == nil && !c.writeEnd {
		if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.changed.Wait()
	}
	if c.err != nil {
		return 0, c.err
	}
	if c.writeEnd {
		return 0, io.ErrClosedPipe
	}
	c.up = append(c.up, b...)
	c.signal()
	return len(b), nil
}
func (c *mkcpConn) CloseWrite() error {
	c.mu.Lock()
	c.writeEnd = true
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *mkcpConn) seal(plain []byte) []byte {
	if c.aead != nil {
		nonce := make([]byte, c.aead.NonceSize())
		_, _ = rand.Read(nonce)
		return c.header.wrap(c.aead.Seal(nonce, nonce, plain, nil))
	}
	b := make([]byte, len(plain)+6)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(plain)))
	copy(b[6:], plain)
	h := fnv.New32a()
	_, _ = h.Write(b[4:])
	binary.BigEndian.PutUint32(b, h.Sum32())
	for i := 4; i < len(b); i++ {
		b[i] ^= b[i-4]
	}
	return c.header.wrap(b)
}
func (c *mkcpConn) open(packet []byte) ([]byte, error) {
	var err error
	packet, err = c.header.unwrap(packet)
	if err != nil {
		return nil, err
	}
	if c.aead != nil {
		n := c.aead.NonceSize()
		if len(packet) < n+c.aead.Overhead() {
			return nil, io.ErrUnexpectedEOF
		}
		return c.aead.Open(nil, packet[:n], packet[n:], nil)
	}
	if len(packet) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	b := append([]byte{}, packet...)
	for i := len(b) - 1; i >= 4; i-- {
		b[i] ^= b[i-4]
	}
	h := fnv.New32a()
	_, _ = h.Write(b[4:])
	if h.Sum32() != binary.BigEndian.Uint32(b) || int(binary.BigEndian.Uint16(b[4:6])) != len(b)-6 {
		return nil, errors.New("mKCP checksum")
	}
	return b[6:], nil
}
func (c *mkcpConn) run() {
	incoming := make(chan []byte, 64)
	go func() {
		b := make([]byte, 65536)
		for {
			n, e := c.socket.Read(b)
			if e != nil {
				c.fail(e)
				return
			}
			select {
			case incoming <- append([]byte{}, b[:n]...):
			case <-c.stop:
				return
			}
		}
	}()
	tick := time.NewTicker(time.Duration(c.options.TTI) * time.Millisecond)
	defer tick.Stop()
	start := time.Now()
	last := start
	pending := map[uint32]*kcpSegment{}
	received := map[uint32][]byte{}
	var nextSend, nextReceive, remoteWindow uint32
	remoteWindow = 64
	receivedBytes := 0
	rto := 300 * time.Millisecond
	var remoteFinal *uint32
	closeSent := false
	first := func() uint32 {
		n := nextSend
		for number := range pending {
			if number < n {
				n = number
			}
		}
		return n
	}
	packet := func(cmd, option byte, body []byte) bool {
		p := make([]byte, 4, len(body)+4)
		binary.BigEndian.PutUint16(p, c.conv)
		p[2], p[3] = cmd, option
		p = append(p, body...)
		if _, e := c.socket.Write(c.seal(p)); e != nil {
			c.fail(e)
			return false
		}
		return true
	}
	command := func(cmd, option byte) bool {
		b := make([]byte, 12)
		binary.BigEndian.PutUint32(b, first())
		binary.BigEndian.PutUint32(b[4:], nextReceive)
		binary.BigEndian.PutUint32(b[8:], uint32(rto.Milliseconds()))
		return packet(cmd, option, b)
	}
	ack := func(number, timestamp uint32) bool {
		c.mu.Lock()
		credit := max(1, (bufferLimit-len(c.down)-receivedBytes)/c.options.MTU)
		c.mu.Unlock()
		b := make([]byte, 17)
		binary.BigEndian.PutUint32(b, nextReceive+uint32(min(credit, 4096)))
		binary.BigEndian.PutUint32(b[4:], nextReceive)
		binary.BigEndian.PutUint32(b[8:], timestamp)
		b[12] = 1
		binary.BigEndian.PutUint32(b[13:], number)
		return packet(0, 0, b)
	}
	flush := func() bool {
		c.mu.Lock()
		for {
			b, ok := received[nextReceive]
			if !ok || len(c.down)+len(b) > bufferLimit {
				break
			}
			c.down = append(c.down, b...)
			receivedBytes -= len(b)
			delete(received, nextReceive)
			nextReceive++
		}
		if remoteFinal != nil && nextReceive >= *remoteFinal && len(received) == 0 {
			c.readEnd = true
		}
		c.changed.Broadcast()
		limit := c.options.MTU - 18 - 6
		if c.aead != nil {
			limit = c.options.MTU - 18 - c.aead.NonceSize() - c.aead.Overhead()
		}
		limit -= c.header.size()
		for len(c.up) > 0 && len(pending) < 64 && nextSend < remoteWindow {
			n := min(len(c.up), limit)
			pending[nextSend] = &kcpSegment{number: nextSend, payload: append([]byte{}, c.up[:n]...)}
			c.up = c.up[n:]
			nextSend++
		}
		end := c.writeEnd && len(c.up) == 0 && len(pending) == 0
		c.changed.Broadcast()
		c.mu.Unlock()
		for _, seg := range pending {
			if seg.sent.IsZero() || time.Since(seg.sent) >= rto {
				if seg.tries >= 30 {
					c.fail(errors.New("mKCP retransmission timeout"))
					return false
				}
				seg.timestamp = uint32(time.Since(start).Milliseconds())
				b := make([]byte, 14+len(seg.payload))
				binary.BigEndian.PutUint32(b, seg.timestamp)
				binary.BigEndian.PutUint32(b[4:], seg.number)
				binary.BigEndian.PutUint32(b[8:], first())
				binary.BigEndian.PutUint16(b[12:], uint16(len(seg.payload)))
				copy(b[14:], seg.payload)
				if !packet(1, 0, b) {
					return false
				}
				seg.sent = time.Now()
				seg.tries++
			}
		}
		if end && !closeSent {
			closeSent = true
			return command(3, 1)
		}
		return true
	}
	for {
		select {
		case <-c.stop:
			return
		case <-c.wake:
			if !flush() {
				return
			}
			if nextReceive > 0 {
				if !ack(nextReceive-1, 0) {
					return
				}
			}
		case <-tick.C:
			if time.Since(last) > 60*time.Second {
				c.fail(errors.New("mKCP idle timeout"))
				return
			}
			if !flush() {
				return
			}
			if closeSent {
				if !command(3, 1) {
					return
				}
			}
		case wire := <-incoming:
			plain, e := c.open(wire)
			if e != nil {
				continue
			}
			last = time.Now()
			for len(plain) >= 4 {
				if binary.BigEndian.Uint16(plain) != c.conv {
					break
				}
				cmd := plain[2]
				plain = plain[4:]
				switch cmd {
				case 1:
					if len(plain) < 14 {
						plain = nil
						break
					}
					timestamp, number := binary.BigEndian.Uint32(plain), binary.BigEndian.Uint32(plain[4:])
					size := int(binary.BigEndian.Uint16(plain[12:]))
					if size == 0 || size > c.options.MTU || len(plain) < 14+size {
						plain = nil
						break
					}
					b := plain[14 : 14+size]
					plain = plain[14+size:]
					if number < nextReceive {
						_ = ack(number, timestamp)
						continue
					}
					if number-nextReceive >= 4096 {
						continue
					}
					if _, ok := received[number]; !ok {
						if receivedBytes+len(b) > bufferLimit {
							continue
						}
						received[number] = append([]byte{}, b...)
						receivedBytes += len(b)
					}
					if !flush() {
						return
					}
					if !ack(number, timestamp) {
						return
					}
				case 0:
					if len(plain) < 13 {
						plain = nil
						break
					}
					window, next, timestamp := binary.BigEndian.Uint32(plain), binary.BigEndian.Uint32(plain[4:]), binary.BigEndian.Uint32(plain[8:])
					count := int(plain[12])
					if len(plain) < 13+count*4 || next > nextSend {
						plain = nil
						break
					}
					if window > remoteWindow {
						remoteWindow = window
					}
					for number := range pending {
						if number < next {
							delete(pending, number)
						}
					}
					for i := 0; i < count; i++ {
						number := binary.BigEndian.Uint32(plain[13+i*4:])
						delete(pending, number)
					}
					elapsed := uint32(time.Since(start).Milliseconds()) - timestamp
					if elapsed < 60000 {
						rto = max(100*time.Millisecond, min(2*time.Second, time.Duration(elapsed)*time.Millisecond*2+50*time.Millisecond))
					}
					plain = plain[13+count*4:]
					if !flush() {
						return
					}
				case 2, 3:
					if len(plain) < 12 {
						plain = nil
						break
					}
					final := binary.BigEndian.Uint32(plain)
					next := binary.BigEndian.Uint32(plain[4:])
					if next <= nextSend {
						for number := range pending {
							if number < next {
								delete(pending, number)
							}
						}
					}
					plain = plain[12:]
					if cmd == 2 {
						remoteFinal = &final
					}
					if !flush() {
						return
					}
				default:
					plain = nil
				}
			}
		}
	}
}
