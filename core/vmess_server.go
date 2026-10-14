package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"time"
)

var errVMServer = errors.New("VMESS_SERVER_REQUEST_INVALID")

type vmServerUser struct {
	id      [16]byte
	command []byte
	auth    cipher.Block
	legacy  [][]byte
}
type vmLegacyTicket struct {
	user  *vmServerUser
	stamp uint64
}
type vmServerAuth struct {
	users       []*vmServerUser
	mu          sync.Mutex
	legacyEpoch int64
	legacy      map[[16]byte]vmLegacyTicket
	replays     map[[32]byte]time.Time
}

func newVMServerAuth(c ServerConfig) (*vmServerAuth, error) {
	if c.Password != "" || c.Cipher != "" || len(c.UUIDs) == 0 || len(c.UUIDs) > 128 {
		return nil, errors.New("VMESS_SERVER_CONFIGURATION")
	}
	alter := 0
	for k, v := range c.Options {
		if k != "alter-id" {
			return nil, errors.New("VMESS_SERVER_OPTION_UNSUPPORTED")
		}
		var err error
		alter, err = number(v, 0, 64)
		if err != nil {
			return nil, errors.New("VMESS_LEGACY_ID_INVALID")
		}
	}
	if alter > 0 && len(c.UUIDs)*(alter+1) > 256 {
		return nil, errors.New("VMESS_LEGACY_ID_LIMIT")
	}
	a := &vmServerAuth{replays: map[[32]byte]time.Time{}}
	seen := map[[16]byte]bool{}
	for _, text := range c.UUIDs {
		id, err := uuidBytes(text)
		if err != nil || seen[id] {
			return nil, errors.New("SERVER_USERS_INVALID")
		}
		seen[id] = true
		command := md5Bytes(join(id[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")))
		block, _ := aes.NewCipher(vmessKDF(command, []byte("AES Auth ID Encryption"))[:16])
		u := &vmServerUser{id: id, command: command, auth: block}
		if alter > 0 {
			prior := append([]byte(nil), id[:]...)
			u.legacy = append(u.legacy, prior)
			for i := 0; i < alter; i++ {
				material := join(prior, []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
				next := md5Bytes(material)
				for bytesEqual(next, prior) {
					material = append(material, []byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2")...)
					next = md5Bytes(material)
				}
				u.legacy = append(u.legacy, next)
				prior = next
			}
		}
		a.users = append(a.users, u)
	}
	return a, nil
}
func (a *vmServerAuth) replay(key []byte) error {
	id := sha256.Sum256(key)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if expires, ok := a.replays[id]; ok && expires.After(now) {
		return errors.New("VMESS_SERVER_REPLAY")
	}
	if len(a.replays) >= 8192 {
		for id, expires := range a.replays {
			if !expires.After(now) {
				delete(a.replays, id)
			}
		}
		if len(a.replays) >= 8192 {
			return errors.New("VMESS_SERVER_REPLAY_LIMIT")
		}
	}
	// Keep identities for the complete +/-120-second authentication horizon.
	a.replays[id] = now.Add(241 * time.Second)
	return nil
}
func (a *vmServerAuth) identify(auth [16]byte) (*vmServerUser, uint64, bool, error) {
	now := time.Now().Unix()
	for _, u := range a.users {
		var plain [16]byte
		u.auth.Decrypt(plain[:], auth[:])
		if binary.BigEndian.Uint32(plain[12:]) != crc32.ChecksumIEEE(plain[:12]) {
			continue
		}
		stamp := binary.BigEndian.Uint64(plain[:8])
		if stamp > uint64(now+120) || stamp < uint64(now-120) {
			return nil, 0, false, errors.New("VMESS_SERVER_TIMESTAMP")
		}
		if err := a.replay(join([]byte("auth"), u.id[:], auth[:])); err != nil {
			return nil, 0, false, err
		}
		return u, stamp, true, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Legacy HMAC timestamp lookup is opt-in and refreshed on demand. It has
	// no timer/goroutine and never performs a timestamp search per connection.
	if a.legacyEpoch != now/10 || a.legacy == nil {
		index := map[[16]byte]vmLegacyTicket{}
		base := now / 10 * 10
		for _, u := range a.users {
			for _, key := range u.legacy {
				for stamp := base - 130; stamp <= base+130; stamp++ {
					h := hmac.New(md5.New, key)
					h.Write(wide(uint64(stamp)))
					var id [16]byte
					copy(id[:], h.Sum(nil))
					index[id] = vmLegacyTicket{u, uint64(stamp)}
				}
			}
		}
		a.legacy, a.legacyEpoch = index, now/10
	}
	ticket, ok := a.legacy[auth]
	if !ok {
		return nil, 0, false, errors.New("VMESS_SERVER_AUTHENTICATION_FAILED")
	}
	if ticket.stamp < uint64(now-120) || ticket.stamp > uint64(now+120) {
		return nil, 0, false, errors.New("VMESS_SERVER_TIMESTAMP")
	}
	return ticket.user, ticket.stamp, false, nil
}

func vmServerHeader(raw net.Conn, auth *vmServerAuth) (*vmServerConn, []byte, bool, error) {
	var id [16]byte
	if _, err := io.ReadFull(raw, id[:]); err != nil {
		return nil, nil, false, err
	}
	user, stamp, modern, err := auth.identify(id)
	if err != nil {
		return nil, nil, false, err
	}
	var plain io.Reader
	var packet []byte
	if modern {
		var prefix [26]byte
		if _, err = io.ReadFull(raw, prefix[:]); err != nil {
			return nil, nil, false, err
		}
		nonce := prefix[18:]
		open := func(label, ivlabel string, wire []byte) ([]byte, error) {
			a, _ := cipherAEAD("aes-128-gcm", vmessKDF(user.command, []byte(label), id[:], nonce)[:16])
			return a.Open(nil, vmessKDF(user.command, []byte(ivlabel), id[:], nonce)[:12], wire, id[:])
		}
		length, err := open("VMess Header AEAD Key_Length", "VMess Header AEAD Nonce_Length", prefix[:18])
		if err != nil {
			return nil, nil, false, errors.New("VMESS_SERVER_LENGTH_AUTH")
		}
		n := int(binary.BigEndian.Uint16(length))
		// MUX omits the destination: 38 fixed bytes + four checksum bytes.
		// Header padding is optional, so a valid XUDP request can be 42 bytes.
		if n < 42 || n > 512 {
			return nil, nil, false, errVMServer
		}
		wire := make([]byte, n+16)
		if _, err = io.ReadFull(raw, wire); err != nil {
			return nil, nil, false, err
		}
		packet, err = open("VMess Header AEAD Key", "VMess Header AEAD Nonce", wire)
		if err != nil {
			return nil, nil, false, errors.New("VMESS_SERVER_HEADER_AUTH")
		}
		plain = bytes.NewReader(packet)
	} else {
		b, _ := aes.NewCipher(user.command)
		ts := wide(stamp)
		plain = &cipher.StreamReader{S: cipher.NewCFBDecrypter(b, md5Bytes(join(ts, ts, ts, ts))), R: raw}
	}
	// Record exactly the parsed plaintext before validating its checksum.
	var transcript bytes.Buffer
	r := io.TeeReader(plain, &transcript)
	var fixed [38]byte
	if _, err = io.ReadFull(r, fixed[:]); err != nil {
		return nil, nil, false, err
	}
	opts, security, cmd := fixed[34], fixed[35]&15, fixed[37]
	if fixed[0] != 1 || fixed[36] != 0 || (cmd != 1 && cmd != 2 && cmd != 3) || opts&^byte(0x1d) != 0 || (opts&8 != 0 && opts&4 == 0) {
		return nil, nil, false, errVMServer
	}
	if security != 1 && security != 3 && security != 4 && security != 5 {
		return nil, nil, false, errVMServer
	}
	if opts&1 == 0 && (security != 5 || cmd != 1 || opts != 0) {
		return nil, nil, false, errVMServer
	}
	if opts&16 != 0 && security != 3 && security != 4 {
		return nil, nil, false, errVMServer
	}
	var address []byte
	if cmd != 3 {
		address, err = mappedServerAddress(r)
		if err != nil {
			return nil, nil, false, err
		}
	}
	padding := make([]byte, int(fixed[35]>>4))
	if _, err = io.ReadFull(r, padding); err != nil {
		return nil, nil, false, err
	}
	var sum [4]byte
	if _, err = io.ReadFull(plain, sum[:]); err != nil {
		return nil, nil, false, err
	}
	if !bytesEqual(sum[:], fnv32(transcript.Bytes())) {
		return nil, nil, false, errors.New("VMESS_SERVER_CHECKSUM")
	}
	if modern && transcript.Len()+4 != len(packet) {
		return nil, nil, false, errVMServer
	}
	if err = auth.replay(join([]byte("session"), user.id[:], fixed[1:33])); err != nil {
		return nil, nil, false, err
	}
	upKey, upIV := append([]byte(nil), fixed[17:33]...), append([]byte(nil), fixed[1:17]...)
	digest := shaBytes
	if !modern {
		digest = md5Bytes
	}
	downKey, downIV := digest(upKey)[:16], digest(upIV)[:16]
	in, err := newVMServerBody(raw, upKey, upIV, upKey, upIV, opts, security, false)
	if err != nil {
		return nil, nil, false, err
	}
	out, err := newVMServerBody(raw, downKey, downIV, upKey, upIV, opts, security, true)
	if err != nil {
		return nil, nil, false, err
	}
	conn := &vmServerConn{Conn: raw, in: in, out: out, udp: cmd == 2, mux: cmd == 3}
	header := []byte{fixed[33], 0, 0, 0}
	if modern {
		seal := func(label, ivlabel string, data []byte) []byte {
			a, _ := cipherAEAD("aes-128-gcm", vmessKDF(downKey, []byte(label))[:16])
			return a.Seal(nil, vmessKDF(downIV, []byte(ivlabel))[:12], data, nil)
		}
		header = join(seal("AEAD Resp Header Len Key", "AEAD Resp Header Len IV", word(4)), seal("AEAD Resp Header Key", "AEAD Resp Header IV", header))
	} else {
		block, _ := aes.NewCipher(downKey)
		responseCipher := cipher.NewCFBEncrypter(block, downIV)
		responseCipher.XORKeyStream(header, header)
		if security == 1 {
			conn.out.stream = responseCipher
		}
	}
	conn.response = header
	return conn, address, cmd == 2, nil
}

type vmServerBody struct {
	raw               io.ReadWriter
	iv, lengthIV      []byte
	options, security byte
	sequence          uint32
	aead, lengthAEAD  cipher.AEAD
	stream            cipher.Stream
	shake             *sha3.SHAKE
}

func vmChaChaKey(key []byte) []byte { first := md5Bytes(key); return join(first, md5Bytes(first)) }
func newVMServerBody(raw io.ReadWriter, key, iv, requestKey, requestIV []byte, options, security byte, writing bool) (*vmServerBody, error) {
	b := &vmServerBody{raw: raw, iv: iv, lengthIV: requestIV, options: options, security: security}
	if options&4 != 0 {
		b.shake = sha3.NewSHAKE128()
		b.shake.Write(iv)
	}
	method := "aes-128-gcm"
	switch security {
	case 1:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if writing {
			b.stream = cipher.NewCFBEncrypter(block, iv)
		} else {
			b.stream = cipher.NewCFBDecrypter(block, iv)
		}
	case 3:
		var err error
		b.aead, err = cipherAEAD(method, key)
		if err != nil {
			return nil, err
		}
	case 4:
		method = "chacha20-poly1305"
		var err error
		b.aead, err = cipherAEAD(method, vmChaChaKey(key))
		if err != nil {
			return nil, err
		}
	}
	if options&16 != 0 {
		lengthKey := vmessKDF(requestKey, []byte("auth_len"))[:16]
		if security == 4 {
			lengthKey = vmChaChaKey(lengthKey)
		}
		var err error
		b.lengthAEAD, err = cipherAEAD(method, lengthKey)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}
func (b *vmServerBody) nextMask() uint16 {
	var n [2]byte
	b.shake.Read(n[:])
	return binary.BigEndian.Uint16(n[:])
}
func (b *vmServerBody) padding() int {
	if b.options&8 != 0 {
		return int(b.nextMask() % 64)
	}
	return 0
}
func (b *vmServerBody) read() ([]byte, error) {
	if (b.aead != nil || b.lengthAEAD != nil) && b.sequence >= 65536 {
		return nil, errors.New("VMESS_NONCE_EXHAUSTED")
	}
	sizeBytes := 2
	if b.lengthAEAD != nil {
		sizeBytes = 18
	}
	wire := make([]byte, sizeBytes)
	reader := io.Reader(b.raw)
	if b.stream != nil {
		reader = &cipher.StreamReader{S: b.stream, R: reader}
	}
	if _, err := io.ReadFull(reader, wire); err != nil {
		return nil, err
	}
	padding := b.padding()
	n := 0
	if b.lengthAEAD != nil {
		nonce, _ := vmNonce(b.lengthIV, b.sequence)
		plain, err := b.lengthAEAD.Open(nil, nonce, wire, nil)
		if err != nil {
			return nil, errors.New("VMESS_SERVER_CHUNK_LENGTH_AUTH")
		}
		n = int(binary.BigEndian.Uint16(plain)) + 16
	} else {
		n = int(binary.BigEndian.Uint16(wire))
		if b.shake != nil {
			n ^= int(b.nextMask())
		}
	}
	overhead := 0
	if b.aead != nil {
		overhead = b.aead.Overhead()
	}
	if b.security == 1 {
		overhead = 4
	}
	if n < overhead+padding || n > 65535 {
		return nil, errVMServer
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	data = data[:n-padding]
	if b.aead != nil {
		nonce, _ := vmNonce(b.iv, b.sequence)
		var err error
		data, err = b.aead.Open(nil, nonce, data, nil)
		if err != nil {
			return nil, errors.New("VMESS_SERVER_PAYLOAD_AUTH")
		}
	} else if b.security == 1 {
		if !bytesEqual(data[:4], fnv32(data[4:])) {
			return nil, errors.New("VMESS_SERVER_CFB_CHECKSUM")
		}
		data = data[4:]
	}
	b.sequence++
	if len(data) == 0 {
		return nil, io.EOF
	}
	return data, nil
}
func (b *vmServerBody) write(data []byte) error {
	if (b.aead != nil || b.lengthAEAD != nil) && b.sequence >= 65536 {
		return errors.New("VMESS_NONCE_EXHAUSTED")
	}
	padding := b.padding()
	payload := data
	if b.aead != nil {
		nonce, _ := vmNonce(b.iv, b.sequence)
		payload = b.aead.Seal(nil, nonce, data, nil)
	} else if b.security == 1 {
		payload = join(fnv32(data), data)
	}
	n := len(payload) + padding
	if n > 65535 {
		return errors.New("VMESS_CHUNK_LENGTH")
	}
	var header []byte
	if b.lengthAEAD != nil {
		nonce, _ := vmNonce(b.lengthIV, b.sequence)
		header = b.lengthAEAD.Seal(nil, nonce, word(n-16), nil)
	} else {
		size := uint16(n)
		if b.shake != nil {
			size ^= b.nextMask()
		}
		header = word(int(size))
	}
	wire := join(header, payload, randomBytes(padding))
	if b.stream != nil {
		b.stream.XORKeyStream(wire, wire)
	}
	b.sequence++
	return writeAll(b.raw, wire)
}

type vmServerConn struct {
	net.Conn
	in, out           *vmServerBody
	response, readBuf []byte
	udp               bool
	mux               bool
	writeMu           sync.Mutex
	writeEnd          bool
}

func (c *vmServerConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.in.options&1 == 0 {
		return c.Conn.Read(p)
	}
	for len(c.readBuf) == 0 {
		data, err := c.in.read()
		if err != nil {
			return 0, err
		}
		if c.udp {
			if len(data) > 65507 {
				return 0, errors.New("UDP_DATAGRAM_LENGTH")
			}
			data = join(word(len(data)), data)
		}
		c.readBuf = data
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
func (c *vmServerConn) sendResponse() error {
	if c.response == nil {
		return nil
	}
	if err := writeAll(c.Conn, c.response); err != nil {
		return err
	}
	c.response = nil
	return nil
}
func (c *vmServerConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEnd {
		return 0, io.ErrClosedPipe
	}
	if err := c.sendResponse(); err != nil {
		return 0, err
	}
	if c.out.options&1 == 0 {
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), 16000)
		if err := c.out.write(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *vmServerConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEnd {
		return nil
	}
	c.writeEnd = true
	if err := c.sendResponse(); err != nil {
		return err
	}
	if c.out.options&1 != 0 {
		if err := c.out.write(nil); err != nil {
			return err
		}
	}
	if close, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return close.CloseWrite()
	}
	return nil
}
func (c *vmServerConn) writePacket(body []byte) error {
	if len(body) == 0 || len(body) > 65507 {
		return errors.New("VMESS_UDP_LENGTH")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEnd {
		return io.ErrClosedPipe
	}
	if err := c.sendResponse(); err != nil {
		return err
	}
	return c.out.write(body)
}
