package core

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
)

// Vision peels only the VLESS record AEAD. The parent TLS/carrier remains,
// and random mode keeps masking the five-byte origin TLS record headers.
func (c *vlessEncryptionConn) directTransport() net.Conn {
	if !c.randomMode {
		return c.Conn
	}
	return &encryptionDirectConn{Conn: c.Conn, encryption: c}
}

type encryptionDirectConn struct {
	net.Conn
	encryption *vlessEncryptionConn
	in, out    encryptionHeaderMask
}

type encryptionHeaderMask struct {
	header          [5]byte
	used, remaining int
}

func (s *encryptionHeaderMask) transform(data []byte, ctr cipher.Stream, incoming bool) error {
	if ctr == nil {
		return errors.New("VLESS_ENCRYPTION_DIRECT_STATE")
	}
	for len(data) > 0 {
		if s.remaining > 0 {
			n := min(s.remaining, len(data))
			s.remaining -= n
			data = data[n:]
			continue
		}
		n := min(5-s.used, len(data))
		if !incoming {
			copy(s.header[s.used:], data[:n])
		}
		ctr.XORKeyStream(data[:n], data[:n])
		if incoming {
			copy(s.header[s.used:], data[:n])
		}
		s.used += n
		data = data[n:]
		if s.used == 5 {
			s.used = 0
			s.remaining = getWord(s.header[:], 3)
			if s.header[0] < 20 || s.header[0] > 23 || s.header[1] != 3 || s.header[2] != 3 || s.remaining < 1 || s.remaining > 18432 {
				return errors.New("VLESS_ENCRYPTION_DIRECT_RECORD")
			}
		}
	}
	return nil
}

func (c *encryptionDirectConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p := c.encryption
	p.readMu.Lock()
	defer p.readMu.Unlock()
	if len(p.readBuf) > 0 {
		n := copy(b, p.readBuf)
		p.readBuf = p.readBuf[n:]
		return n, nil
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if maskErr := c.in.transform(b[:n], p.inCTR, true); maskErr != nil {
			return 0, p.failed(maskErr)
		}
	}
	return n, err
}

func (c *encryptionDirectConn) Write(b []byte) (int, error) {
	p := c.encryption
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.writeErr != nil {
		return 0, p.writeErr
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), 8192)
		if cap(p.writeWire) < 8192 {
			p.writeWire = make([]byte, 8192)
		}
		wire := p.writeWire[:n]
		copy(wire, b[:n])
		if err := c.out.transform(wire, p.outCTR, false); err != nil {
			p.writeErr = p.failed(err)
			return total, p.writeErr
		}
		if err := writeAll(c.Conn, wire); err != nil {
			p.writeErr = p.failed(err)
			return total, p.writeErr
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

func (c *encryptionDirectConn) CloseWrite() error {
	p := c.encryption
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.writeErr = io.ErrClosedPipe
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
