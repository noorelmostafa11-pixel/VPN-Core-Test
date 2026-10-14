package core

import (
	"crypto/cipher"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptionAEAD(context, key []byte, useAES bool) (*recordAEAD, error) {
	if useAES {
		return newRecordAEAD(context, key)
	}
	a, err := chacha20poly1305.New(deriveBLAKE3(context, key))
	return &recordAEAD{AEAD: a}, err
}

// A stream owns only one bounded input record and direction-local cipher state.
// Reads and writes run on the caller's workers; Close wakes underlying I/O.
type vlessEncryptionConn struct {
	net.Conn
	readMu, writeMu         sync.Mutex
	readCipher, writeCipher *recordAEAD
	inCTR, outCTR           cipher.Stream
	united                  []byte
	readBuf                 []byte
	readWire, writeWire     []byte
	readErr, writeErr       error
	pendingRandom           bool
	randomMode, useAES      bool
	cacheID                 *[32]byte
}

func (c *vlessEncryptionConn) failed(err error) error {
	if err != nil && err != io.EOF {
		if c.cacheID != nil {
			forgetTicket(*c.cacheID)
		}
		c.Conn.Close()
	}
	return err
}

func nonceFull(a *recordAEAD) bool {
	for _, value := range a.nonce {
		if value != 255 {
			return false
		}
	}
	return true
}

func (c *vlessEncryptionConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.pendingRandom {
		random, err := readN(c.Conn, 16)
		if err == nil {
			c.readCipher, err = encryptionAEAD(random, c.united, c.useAES)
		}
		if err == nil && c.randomMode {
			c.inCTR, err = keyCTR(c.united, random)
		}
		if err != nil {
			c.readErr = c.failed(err)
			return 0, c.readErr
		}
		c.pendingRandom = false
	}
	if len(c.readBuf) == 0 {
		var header [5]byte
		_, err := io.ReadFull(c.Conn, header[:])
		if err == nil && c.inCTR != nil {
			c.inCTR.XORKeyStream(header[:], header[:])
		}
		n := int(header[3])<<8 | int(header[4])
		if err == nil && (header[0] != 23 || header[1] != 3 || header[2] != 3 || n < 17 || n > 16640) {
			err = providerError(502)
		}
		if err == nil {
			if cap(c.readWire) < n {
				c.readWire = make([]byte, n)
			} else {
				c.readWire = c.readWire[:n]
			}
			_, err = io.ReadFull(c.Conn, c.readWire)
		}
		if err == nil {
			if nonceFull(c.readCipher) {
				var zero [12]byte
				// Rekey context uses ciphertext before in-place authentication.
				next, nextErr := encryptionAEAD(join(header[:], c.readWire), c.united, c.useAES)
				c.readBuf, err = c.readCipher.Open(c.readWire[:0], zero[:], c.readWire, header[:])
				if err != nil {
					err = providerError(501)
				}
				if err == nil {
					c.readCipher, err = next, nextErr
				}
			} else {
				nonce, nextErr := c.readCipher.next()
				if nextErr != nil {
					err = nextErr
				} else {
					c.readBuf, err = c.readCipher.Open(c.readWire[:0], nonce, c.readWire, header[:])
					if err != nil {
						err = providerError(501)
					}
				}
			}
		}
		if err != nil {
			c.readErr = c.failed(err)
			return 0, c.readErr
		}
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *vlessEncryptionConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(b) > 0 {
		n := min(8192, len(b))
		if cap(c.writeWire) < 8213 {
			c.writeWire = make([]byte, 8213)
		}
		header := c.writeWire[:5]
		copy(header, []byte{23, 3, 3, byte((n + 16) >> 8), byte(n + 16)})
		var wire []byte
		var err error
		if nonceFull(c.writeCipher) {
			var zero [12]byte
			wire = c.writeCipher.Seal(header, zero[:], b[:n], header)
			c.writeCipher, err = encryptionAEAD(wire, c.united, c.useAES)
		} else {
			nonce, nextErr := c.writeCipher.next()
			if nextErr != nil {
				err = nextErr
			} else {
				wire = c.writeCipher.Seal(header, nonce, b[:n], header)
			}
		}
		if err == nil {
			if c.outCTR != nil {
				c.outCTR.XORKeyStream(header, header)
			}
			err = writeAll(c.Conn, wire)
		}
		if err != nil {
			c.writeErr = c.failed(err)
			return total, c.writeErr
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

func (c *vlessEncryptionConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeErr = io.ErrClosedPipe
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
