// Project-owned legacy RPRX record transport. The initial handshake and every
// outer encrypted record are authenticated by the pinned TLS library.
package main

import (
	"encoding/binary"
	"errors"
	utls "github.com/refraction-networking/utls"
	"io"
	"net"
	"sync"
)

type legacyXTLS struct {
	net.Conn
	tls                        *utls.UConn
	raw                        *memoryConn
	direct                     bool
	upMu                       sync.Mutex
	downRemaining, upRemaining int
	downRaw, upRaw             bool
	downBuffer, upHeader       []byte
	upRecordRemaining          int
}

func appRecordLength(b []byte) int {
	if len(b) < 5 || b[0] != 23 || b[1] != 3 || b[2] != 3 {
		return 0
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if n < 17 || n > 16640 {
		return 0
	}
	return n + 5
}
func (p *legacyXTLS) Read(b []byte) (int, error) {
	if len(p.downBuffer) > 0 {
		n := copy(b, p.downBuffer)
		p.downBuffer = p.downBuffer[n:]
		return n, nil
	}
	if !p.downRaw {
		n, err := p.tls.Read(b)
		if n > 0 {
			if p.downRemaining == 0 {
				p.downRemaining = appRecordLength(b[:n])
			}
			if p.downRemaining > 0 {
				p.downRemaining -= n
				if p.downRemaining < 0 {
					return 0, errors.New("legacy record transition boundary")
				}
				if p.downRemaining == 0 {
					p.downRaw = true
				}
			}
		}
		return n, err
	}
	if p.direct {
		return p.raw.Read(b)
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(p.raw, header); err != nil {
		return 0, err
	}
	n := appRecordLength(header)
	if n == 0 {
		return 0, errors.New("legacy raw record framing")
	}
	record := make([]byte, n)
	copy(record, header)
	if _, err := io.ReadFull(p.raw, record[5:]); err != nil {
		return 0, err
	}
	if n == 24 {
		data, kind, err := p.tls.ProjectDecodeRecord(append([]byte{}, record...))
		if err == nil {
			if kind == 21 && len(data) == 2 && data[1] == 0 {
				return 0, io.EOF
			}
			return 0, errors.New("legacy unexpected authenticated control")
		}
	}
	p.tls.ProjectAdvanceInbound()
	count := copy(b, record)
	p.downBuffer = record[count:]
	return count, nil
}
func (p *legacyXTLS) rawWrite(data []byte) error {
	if !p.direct {
		left := data
		for len(left) > 0 {
			if p.upRecordRemaining == 0 {
				n := min(5-len(p.upHeader), len(left))
				p.upHeader = append(p.upHeader, left[:n]...)
				left = left[n:]
				if len(p.upHeader) < 5 {
					break
				}
				size := appRecordLength(p.upHeader)
				if size == 0 {
					return errors.New("legacy raw record framing")
				}
				p.upRecordRemaining = size - 5
				p.upHeader = nil
				p.tls.ProjectAdvanceOutbound()
			}
			n := min(p.upRecordRemaining, len(left))
			p.upRecordRemaining -= n
			left = left[n:]
		}
	}
	for len(data) > 0 {
		n, err := p.raw.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		data = data[n:]
	}
	return nil
}
func (p *legacyXTLS) Write(data []byte) (int, error) {
	p.upMu.Lock()
	defer p.upMu.Unlock()
	size := len(data)
	if p.upRaw {
		return size, p.rawWrite(data)
	}
	if p.upRemaining == 0 {
		p.upRemaining = appRecordLength(data)
	}
	if p.upRemaining == 0 {
		return p.tls.Write(data)
	}
	n := min(p.upRemaining, len(data))
	if _, err := p.tls.Write(data[:n]); err != nil {
		return 0, err
	}
	p.upRemaining -= n
	if p.upRemaining == 0 {
		p.upRaw = true
		if n < size {
			if err := p.rawWrite(data[n:]); err != nil {
				return n, err
			}
		}
	}
	return size, nil
}
func (p *legacyXTLS) CloseWrite() error {
	p.upMu.Lock()
	defer p.upMu.Unlock()
	if p.direct && p.upRaw {
		return nil
	}
	if len(p.upHeader) > 0 || p.upRecordRemaining > 0 {
		return errors.New("legacy truncated inner record")
	}
	return p.tls.CloseWrite()
}
