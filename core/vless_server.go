package core

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

const vlessVisionFlow = "xtls-rprx-vision"

func compileVLESSServer(s *serverSpec) error {
	for key, value := range s.config.Options {
		switch key {
		case "flow":
			if value != "" && value != vlessVisionFlow {
				return errors.New("VLESS_SERVER_OPTION_UNSUPPORTED")
			}
			s.vlessFlow = value
		case "decryption":
			if value != "none" {
				var err error
				s.encryption, err = compileVLESSDecryption(value)
				if err != nil {
					return err
				}
			}
		default:
			return errors.New("VLESS_SERVER_OPTION_UNSUPPORTED")
		}
	}
	if s.vlessFlow != "" {
		if s.tls == nil && s.encryption == nil {
			return errors.New("VLESS_VISION_SERVER_TLS_REQUIRED")
		}
		if s.tls != nil {
			s.tls.MinVersion, s.tls.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
			s.tls.SessionTicketsDisabled = true
		}
	}
	return nil
}

// VLESS addons are a one-byte-length protobuf message. Parse only its flow
// field and skip bounded scalar/bytes fields, without a protobuf dependency.
func vlessAddonFlow(data []byte) (string, error) {
	if len(data) > 255 {
		return "", errors.New("VLESS_SERVER_ADDON_INVALID")
	}
	flow, seen := "", false
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
			return "", errors.New("VLESS_SERVER_ADDON_INVALID")
		}
		data = data[n:]
		field, kind := tag>>3, tag&7
		if (field == 1 || field == 2) && kind != 2 {
			return "", errors.New("VLESS_SERVER_ADDON_INVALID")
		}
		switch kind {
		case 0:
			_, n = binary.Uvarint(data)
		case 1:
			n = 8
		case 5:
			n = 4
		case 2:
			length, size := binary.Uvarint(data)
			if size <= 0 || length > uint64(len(data)-size) {
				return "", errors.New("VLESS_SERVER_ADDON_INVALID")
			}
			n = size + int(length)
			if field == 1 {
				value := data[size:n]
				if seen || len(value) > 64 || !utf8.Valid(value) {
					return "", errors.New("VLESS_SERVER_ADDON_INVALID")
				}
				flow, seen = string(value), true
			}
		default:
			return "", errors.New("VLESS_SERVER_ADDON_INVALID")
		}
		if n <= 0 || n > len(data) {
			return "", errors.New("VLESS_SERVER_ADDON_INVALID")
		}
		data = data[n:]
	}
	return flow, nil
}

func vlessServerHeader(raw net.Conn, s serverSpec) (net.Conn, []byte, bool, bool, error) {
	var header [18]byte
	if _, err := io.ReadFull(raw, header[:]); err != nil {
		return nil, nil, false, false, err
	}
	var id [16]byte
	copy(id[:], header[1:17])
	if header[0] != 0 || !s.users[id] {
		return nil, nil, false, false, errors.New("VLESS_SERVER_AUTHENTICATION")
	}
	addon := make([]byte, int(header[17]))
	if _, err := io.ReadFull(raw, addon); err != nil {
		return nil, nil, false, false, err
	}
	flow, err := vlessAddonFlow(addon)
	if err != nil {
		return nil, nil, false, false, err
	}
	var command [1]byte
	if _, err = io.ReadFull(raw, command[:]); err != nil {
		return nil, nil, false, false, err
	}
	if command[0] < 1 || command[0] > 3 || flow != "" && flow != s.vlessFlow || command[0] == 1 && flow != s.vlessFlow || command[0] == 2 && flow != "" {
		return nil, nil, false, false, errors.New("VLESS_SERVER_FLOW_INVALID")
	}
	var address []byte
	if command[0] != 3 {
		address, err = mappedServerAddress(raw)
		if err != nil {
			return nil, nil, false, false, err
		}
	}
	client := raw
	if flow == vlessVisionFlow {
		var wire *directConn
		if encrypted, ok := raw.(*vlessEncryptionConn); ok && s.encryption != nil {
			wire = &directConn{Conn: encrypted, raw: encrypted.directTransport()}
		} else if secured, ok := raw.(*directConn); ok {
			if tlsConn, ok := secured.Conn.(*tls.Conn); ok && tlsConn.ConnectionState().Version == tls.VersionTLS13 {
				wire = secured
			}
		}
		if wire == nil {
			return nil, nil, false, false, errors.New("VISION_DIRECT_SECURITY")
		}
		client = newVisionServerConn(wire, id)
	}
	return client, address, command[0] == 2, command[0] == 3, nil
}

// A direction-local TLS boundary tracker needs only five bytes of state. It
// lets a direct transition wait for a complete origin TLS application record,
// even when server socket reads split its header or ciphertext.
type visionTLSBoundary struct {
	header               [5]byte
	used, remaining      int
	invalid, application bool
}

func (t *visionTLSBoundary) consume(data []byte) {
	for len(data) > 0 && !t.invalid {
		if t.remaining > 0 {
			n := min(t.remaining, len(data))
			t.remaining -= n
			data = data[n:]
			continue
		}
		n := min(5-t.used, len(data))
		copy(t.header[t.used:], data[:n])
		t.used += n
		data = data[n:]
		if t.used != 5 {
			continue
		}
		t.used = 0
		t.remaining = getWord(t.header[:], 3)
		if t.header[0] < 20 || t.header[0] > 23 || t.header[1] != 3 || t.header[2] != 3 || t.remaining == 0 || t.remaining > 18432 {
			t.invalid = true
			return
		}
		if t.header[0] == 23 {
			t.application = true
		}
	}
}

type visionServerConn struct {
	*directConn
	readMu, writeMu                           sync.Mutex
	decoder, probe                            vision
	tls13                                     atomic.Bool
	boundary                                  visionTLSBoundary
	readBuf                                   []byte
	readErr                                   error
	firstWrite, writeDone, writeRaw, writeEnd bool
	buffer                                    [32768]byte
}

func newVisionServerConn(wire *directConn, id [16]byte) *visionServerConn {
	cfg := Config{UUID: id, Transport: "raw"}
	return &visionServerConn{directConn: wire, decoder: vision{c: cfg, enabled: true, prefix: true, needHeader: true, probeDone: true}, firstWrite: true}
}
func (c *visionServerConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		n, err := c.directConn.Read(c.buffer[:])
		c.decoder.tls13 = c.tls13.Load()
		plain, decodeErr := c.decoder.decode(c.buffer[:n])
		if decodeErr != nil {
			return 0, decodeErr
		}
		if c.decoder.direct {
			c.switchDirectRead()
			c.decoder.direct = false
		}
		c.readBuf, c.readErr = plain, err
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
func (c *visionServerConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEnd {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), 16384)
		body := b[:n]
		wire := body
		target := c.directConn.Conn
		command := byte(0)
		if c.writeRaw {
			target = c.raw
		} else if !c.writeDone {
			c.probe.probe(body)
			if c.probe.tls13 {
				c.tls13.Store(true)
			}
			c.boundary.consume(body)
			if c.probe.tls13 && !c.boundary.invalid && c.boundary.application && c.boundary.remaining == 0 && c.boundary.used == 0 {
				command = 2
			} else if c.probe.probeDone && !c.probe.tls13 {
				command = 1
			}
			wire = c.decoder.frame(command, body, c.firstWrite)
		}
		if err := writeAll(target, wire); err != nil {
			return total, err
		}
		if !c.writeDone {
			c.firstWrite = false
			c.writeDone = command != 0
			c.writeRaw = command == 2
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
func (c *visionServerConn) Close() error { return c.raw.Close() }
func (c *visionServerConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeEnd = true
	target := c.directConn.Conn
	if c.writeRaw {
		target = c.raw
	}
	if w, ok := target.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
