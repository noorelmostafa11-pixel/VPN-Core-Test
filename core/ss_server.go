package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

// Listener-local keys and replay state. No maintenance worker exists for TCP;
// expired entries are removed only when the bounded cache needs room.
type ssServerState struct {
	codec *ssUDP
	udp   bool
	mu    sync.Mutex
	salts map[[32]byte]time.Time
}

func newSSServerState(c Config, options map[string]string) (*ssServerState, error) {
	udp := true
	for k, v := range options {
		if k != "udp" || (v != "true" && v != "false") {
			return nil, errors.New("SS_SERVER_OPTION_UNSUPPORTED")
		}
		udp = v == "true"
	}
	codec, err := newSSUDP(c)
	if err != nil {
		return nil, err
	}
	return &ssServerState{codec: codec, udp: udp, salts: map[[32]byte]time.Time{}}, nil
}
func (s *ssServerState) rememberSalt(salt []byte) error {
	id := sha256.Sum256(salt)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if expires, ok := s.salts[id]; ok && expires.After(now) {
		return errors.New("SS_SERVER_SALT_REPLAY")
	}
	if len(s.salts) >= 8192 {
		for k, expires := range s.salts {
			if !expires.After(now) {
				delete(s.salts, k)
			}
		}
		if len(s.salts) >= 8192 {
			return errors.New("SS_SERVER_REPLAY_LIMIT")
		}
	}
	s.salts[id] = now.Add(time.Minute)
	return nil
}

type ssServerChunks struct {
	raw       io.ReadWriter
	aead      cipher.AEAD
	nonce     []byte
	exhausted bool
}

func newSSServerChunks(raw io.ReadWriter, s *ssServerState, salt []byte) (*ssServerChunks, error) {
	key, err := subkey(s.codec.master, salt, s.codec.spec.key, true)
	if err != nil {
		return nil, err
	}
	aead, err := cipherAEAD(s.codec.method(), key)
	if err != nil {
		return nil, err
	}
	return &ssServerChunks{raw: raw, aead: aead, nonce: make([]byte, 12)}, nil
}
func (c *ssServerChunks) open(n int) ([]byte, error) {
	if c.exhausted {
		return nil, errors.New("SS_NONCE_EXHAUSTED")
	}
	if n < 1 || n > 65535 {
		return nil, errors.New("SS_CHUNK_LENGTH")
	}
	wire := make([]byte, n+c.aead.Overhead())
	if _, err := io.ReadFull(c.raw, wire); err != nil {
		return nil, err
	}
	plain, err := c.aead.Open(nil, c.nonce, wire, nil)
	if err != nil {
		return nil, err
	}
	c.exhausted = nonceAdvance(c.nonce) != nil
	return plain, nil
}
func (c *ssServerChunks) seal(plain []byte) ([]byte, error) {
	if c.exhausted {
		return nil, errors.New("SS_NONCE_EXHAUSTED")
	}
	if len(plain) == 0 || len(plain) > 65535 {
		return nil, errors.New("SS_CHUNK_LENGTH")
	}
	wire := c.aead.Seal(nil, c.nonce, plain, nil)
	c.exhausted = nonceAdvance(c.nonce) != nil
	return wire, nil
}

func ssServerReset(conn net.Conn) {
	// SIP022 requires a uniform failed-header close. Use RST on the actual TCP
	// socket, including when an optional native TLS layer wraps it.
	for depth := 0; depth < 4; depth++ {
		if tcp, ok := conn.(interface{ SetLinger(int) error }); ok {
			tcp.SetLinger(0)
			return
		}
		if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = wrapped.NetConn()
			continue
		}
		return
	}
}

func ss2022ServerConn(raw net.Conn, s *ssServerState) (result net.Conn, address []byte, err error) {
	accepted := false
	defer func() {
		if !accepted {
			ssServerReset(raw)
		}
	}()
	codec := s.codec
	// Exactly one socket read for salt, identity headers and fixed AEAD chunk.
	// Reject partial probes rather than revealing each parser boundary.
	prefix := make([]byte, codec.spec.key+16*(len(codec.keys)-1)+27)
	n, err := raw.Read(prefix)
	if err != nil || n != len(prefix) {
		return nil, nil, errors.New("SS2022_SERVER_INITIAL_READ")
	}
	salt := prefix[:codec.spec.key]
	pos := codec.spec.key
	for i := 0; i+1 < len(codec.keys); i++ {
		key := make([]byte, 32)
		blake3.DeriveKey(key, "shadowsocks 2022 identity subkey", join(codec.keys[i], salt))
		identity, err := aesECB(key[:codec.spec.key], prefix[pos:pos+16], true)
		if err != nil {
			return nil, nil, err
		}
		expected := blake3.Sum256(codec.keys[i+1])
		if !bytesEqual(identity, expected[:16]) {
			return nil, nil, errors.New("SS2022_SERVER_IDENTITY")
		}
		pos += 16
	}
	in, err := newSSServerChunks(raw, s, salt)
	if err != nil {
		return nil, nil, err
	}
	fixed, err := in.aead.Open(nil, in.nonce, prefix[pos:], nil)
	if err != nil {
		return nil, nil, errors.New("SS2022_SERVER_HEADER_AUTH")
	}
	in.exhausted = nonceAdvance(in.nonce) != nil
	stamp, now := int64(binary.BigEndian.Uint64(fixed[1:9])), time.Now().Unix()
	if fixed[0] != 0 || stamp < now-30 || stamp > now+30 {
		return nil, nil, errors.New("SS2022_SERVER_TIMESTAMP")
	}
	variable, err := in.open(int(binary.BigEndian.Uint16(fixed[9:])))
	if err != nil {
		return nil, nil, err
	}
	reader := bytes.NewReader(variable)
	address, err = readAddress(reader)
	if err != nil {
		return nil, nil, err
	}
	if err = ssRequestAddress(address); err != nil {
		return nil, nil, err
	}
	var pad [2]byte
	if _, err = io.ReadFull(reader, pad[:]); err != nil {
		return nil, nil, err
	}
	padding := int(binary.BigEndian.Uint16(pad[:]))
	if padding > 900 || padding > reader.Len() {
		return nil, nil, errors.New("SS2022_SERVER_PADDING")
	}
	reader.Seek(int64(padding), io.SeekCurrent)
	if padding == 0 && reader.Len() == 0 {
		return nil, nil, errors.New("SS2022_SERVER_EMPTY_HEADER")
	}
	if err = s.rememberSalt(salt); err != nil {
		return nil, nil, err
	}
	buffer := variable[len(variable)-reader.Len():]
	accepted = true
	return &ss2022ServerStream{Conn: raw, state: s, in: in, requestSalt: append([]byte(nil), salt...), readBuf: buffer}, address, nil
}

func ssRequestAddress(address []byte) error {
	_, _, err := decodeAddress(address)
	if err != nil && len(address) > 4 && address[0] == 3 && string(address[2:len(address)-2]) == uotV2Host && getWord(address, len(address)-2) == 0 {
		// UOT uses a virtual destination with port zero. Its outer server
		// handler decides whether UOT is enabled before any UDP is forwarded.
		return nil
	}
	return err
}

type ss2022ServerStream struct {
	net.Conn
	state                *ssServerState
	in, out              *ssServerChunks
	requestSalt, readBuf []byte
	writeMu              sync.Mutex
	writeEnd             bool
}

func (c *ss2022ServerStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.readBuf) == 0 {
		length, err := c.in.open(2)
		if err != nil {
			return 0, err
		}
		c.readBuf, err = c.in.open(int(binary.BigEndian.Uint16(length)))
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
func (c *ss2022ServerStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEnd {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), 65535)
		var wire, header []byte
		var err error
		if c.out == nil {
			salt := randomBytes(c.state.codec.spec.key)
			c.out, err = newSSServerChunks(c.Conn, c.state, salt)
			if err != nil {
				return total, err
			}
			fixed := join([]byte{1}, wide(uint64(time.Now().Unix())), c.requestSalt, word(n))
			header, err = c.out.seal(fixed)
			wire = append(salt, header...)
		} else {
			header, err = c.out.seal(word(n))
			wire = header
		}
		if err != nil {
			return total, err
		}
		body, err := c.out.seal(p[:n])
		if err != nil {
			return total, err
		}
		if err = writeAll(c.Conn, append(wire, body...)); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *ss2022ServerStream) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeEnd = true
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
