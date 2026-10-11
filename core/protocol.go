package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"lukechampine.com/blake3"
	"net"
	"strings"
	"sync"
	"time"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return b
}
func md5Bytes(b []byte) []byte { h := md5.Sum(b); return h[:] }
func shaBytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func join(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func word(n int) []byte    { return []byte{byte(n >> 8), byte(n)} }
func wide(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func fnv32(b []byte) []byte {
	h := fnv.New32a()
	h.Write(b)
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, h.Sum32())
	return v
}
func vmessKDF(key []byte, paths ...[]byte) []byte {
	f := func() hash.Hash { return sha256.New() }
	for _, p := range append([][]byte{[]byte("VMess AEAD KDF")}, paths...) {
		prior, k := f, p
		f = func() hash.Hash { return hmac.New(prior, k) }
	}
	h := f()
	h.Write(key)
	return h.Sum(nil)
}
func masterKey(password string, n int) []byte {
	var out, last []byte
	for len(out) < n {
		last = md5Bytes(join(last, []byte(password)))
		out = append(out, last...)
	}
	return out[:n]
}
func cipherAEAD(method string, key []byte) (cipher.AEAD, error) {
	switch method {
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		return chacha20poly1305.New(key)
	case "xchacha20-ietf-poly1305":
		return chacha20poly1305.NewX(key)
	default:
		b, e := aes.NewCipher(key)
		if e != nil {
			return nil, e
		}
		return cipher.NewGCM(b)
	}
}
func aesECB(key, data []byte, decrypt bool) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil || len(data)%16 != 0 {
		return nil, errors.New("AES block parameters")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		if decrypt {
			b.Decrypt(out[i:], data[i:])
		} else {
			b.Encrypt(out[i:], data[i:])
		}
	}
	return out, nil
}

type ssSpec struct {
	key, iv int
	stream  bool
}

var ssMethods = []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-ofb", "aes-192-ofb", "aes-256-ofb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "rc4", "rc4-md5", "salsa20", "chacha20", "chacha20-ietf", "table", "none", "plain", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}

func ssCipherSpec(method string) ssSpec {
	switch method {
	case "none", "plain":
		return ssSpec{}
	case "table", "rc4":
		return ssSpec{16, 0, true}
	case "rc4-md5":
		return ssSpec{16, 16, true}
	case "salsa20", "chacha20":
		return ssSpec{32, 8, true}
	case "chacha20-ietf":
		return ssSpec{32, 12, true}
	case "bf-cfb", "cast5-cfb", "idea-cfb", "rc2-cfb":
		return ssSpec{16, 8, true}
	case "des-cfb":
		return ssSpec{8, 8, true}
	case "seed-cfb":
		return ssSpec{16, 16, true}
	}
	name := strings.TrimPrefix(method, "2022-blake3-")
	n := 32
	if strings.Contains(name, "-128-") {
		n = 16
	} else if strings.Contains(name, "-192-") {
		n = 24
	}
	stream := strings.HasSuffix(name, "-cfb") || strings.HasSuffix(name, "-ctr") || strings.HasSuffix(name, "-ofb")
	iv := 12
	if stream {
		iv = 16
	} else if name == "xchacha20-ietf-poly1305" {
		iv = 24
	}
	return ssSpec{n, iv, stream}
}
func ssKeys(c Config) ([][]byte, error) {
	if !strings.HasPrefix(c.Cipher, "2022-blake3-") {
		return nil, nil
	}
	spec := ssCipherSpec(c.Cipher)
	var keys [][]byte
	for _, s := range strings.Split(c.Password, ":") {
		if s == "" || strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-") != "" {
			return nil, errors.New("SS2022_PSK_ENCODING")
		}
		b, e := decode64(s)
		if e != nil || len(b) != spec.key {
			return nil, errors.New("SS2022_PSK_LENGTH")
		}
		keys = append(keys, b)
	}
	if len(keys) > 8 {
		return nil, errors.New("SS2022_PSK_COUNT")
	}
	if c.Cipher == "2022-blake3-chacha20-poly1305" && len(keys) > 1 {
		return nil, errors.New("SS2022_IDENTITY_CIPHER")
	}
	return keys, nil
}
func subkey(key, salt []byte, n int, modern bool) ([]byte, error) {
	if modern {
		out := make([]byte, 32)
		blake3.DeriveKey(out, "shadowsocks 2022 session subkey", join(key, salt))
		return out[:n], nil
	}
	return hkdf.Key(sha1.New, key, salt, "ss-subkey", n)
}
func mappedAddress(address []byte) []byte {
	kind := byte(3)
	if address[0] == 1 {
		kind = 1
	} else if address[0] == 3 {
		kind = 2
	}
	return join(address[len(address)-2:], []byte{kind}, address[1:len(address)-2])
}
func nonceAdvance(n []byte) error {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return nil
		}
	}
	return errors.New("SS_NONCE_EXHAUSTED")
}

var saltReplay = struct {
	sync.Mutex
	seen  map[[32]byte]bool
	order [][32]byte
}{seen: map[[32]byte]bool{}}

func checkSalt(key, salt []byte) error {
	id := sha256.Sum256(join(key, salt))
	saltReplay.Lock()
	defer saltReplay.Unlock()
	if saltReplay.seen[id] {
		return errors.New("SS_SALT_REPLAY")
	}
	saltReplay.seen[id] = true
	saltReplay.order = append(saltReplay.order, id)
	if len(saltReplay.order) > 4096 {
		delete(saltReplay.seen, saltReplay.order[0])
		saltReplay.order = saltReplay.order[1:]
	}
	return nil
}

type protocol struct {
	c                                                                                  Config
	udp, modern, stream, none, vmZero, vmCFB, header, responseDone, haveLength, closed bool
	input, upKey, downKey, upIV, downIV, upSalt, master, legacy                        []byte
	upCipher, downCipher, responseCipher                                               cipher.Stream
	upAEAD, downAEAD                                                                   cipher.AEAD
	countUp, countDown                                                                 uint32
	response                                                                           byte
	size                                                                               int
	method                                                                             string
	vision                                                                             vision
}

func newProtocol(c Config, udp bool) *protocol {
	p := &protocol{c: c, udp: udp}
	p.vision = vision{c: c, enabled: !udp && strings.HasPrefix(c.Flow, "xtls-rprx-vision"), prefix: true, needHeader: true}
	if c.Protocol == "vmess" {
		p.vmZero = c.Cipher == "zero" && !udp
		p.vmCFB = c.Cipher == "aes-128-cfb"
		p.method = "aes-128-gcm"
		if c.Cipher == "none" || p.vmZero {
			p.method = "none"
		} else if c.Cipher == "chacha20-poly1305" {
			p.method = c.Cipher
		}
	}
	if c.Protocol == "ss" {
		p.modern = strings.HasPrefix(c.Cipher, "2022-blake3-")
		p.stream = ssCipherSpec(c.Cipher).stream
		p.none = c.Cipher == "none" || c.Cipher == "plain"
		p.method = strings.TrimPrefix(c.Cipher, "2022-blake3-")
	}
	return p
}
func (p *protocol) open(address []byte) ([]byte, error) {
	cmd := byte(1)
	if p.udp {
		cmd = 2
	}
	switch p.c.Protocol {
	case "trojan":
		if p.udp {
			cmd = 3
		}
		return join([]byte(p.c.PasswordHash), []byte{13, 10, cmd}, address, []byte{13, 10}), nil
	case "vless":
		var addon []byte
		if !p.udp && p.c.Flow != "" {
			flow := strings.TrimSuffix(p.c.Flow, "-udp443")
			if flow == "xtls-rprx-splice" {
				flow = "xtls-rprx-direct"
			}
			addon = join([]byte{10, byte(len(flow))}, []byte(flow))
		}
		b := join([]byte{0}, p.c.UUID[:], []byte{byte(len(addon))}, addon, []byte{cmd}, mappedAddress(address))
		if p.vision.enabled {
			b = append(b, p.vision.frame(0, nil, true)...)
		}
		return b, nil
	case "vmess":
		return p.vmessHeader(address)
	case "ss":
		if p.none {
			return address, nil
		}
		spec := ssCipherSpec(p.c.Cipher)
		var keys [][]byte
		var e error
		if p.modern {
			keys, e = ssKeys(p.c)
			if e != nil {
				return nil, e
			}
			p.master = keys[len(keys)-1]
		} else {
			p.master = masterKey(p.c.Password, spec.key)
		}
		if p.stream {
			p.upIV = randomBytes(spec.iv)
			p.upCipher, e = ssStreamCipher(p.c.Cipher, p.master, p.upIV, false)
			if e != nil {
				return nil, e
			}
			data := make([]byte, len(address))
			p.upCipher.XORKeyStream(data, address)
			return join(p.upIV, data), nil
		}
		p.upSalt = randomBytes(spec.key)
		p.upKey, e = subkey(p.master, p.upSalt, spec.key, p.modern)
		if e != nil {
			return nil, e
		}
		p.upIV = make([]byte, spec.iv)
		p.upAEAD, e = cipherAEAD(p.method, p.upKey)
		if e != nil {
			return nil, e
		}
		out := append([]byte{}, p.upSalt...)
		if p.modern {
			for i := 0; i+1 < len(keys); i++ {
				key := make([]byte, 32)
				blake3.DeriveKey(key, "shadowsocks 2022 identity subkey", join(keys[i], p.upSalt))
				h := blake3.Sum256(keys[i+1])
				b, e := aesECB(key[:spec.key], h[:16], false)
				if e != nil {
					return nil, e
				}
				out = append(out, b...)
			}
			pad := randomBytes(1 + int(randomBytes(1)[0])*3)
			variable := join(address, word(len(pad)), pad)
			fixed := join([]byte{0}, wide(uint64(time.Now().Unix())), word(len(variable)))
			out = append(out, p.upAEAD.Seal(nil, p.upIV, fixed, nil)...)
			nonceAdvance(p.upIV)
			out = append(out, p.upAEAD.Seal(nil, p.upIV, variable, nil)...)
			nonceAdvance(p.upIV)
			return out, nil
		}
		b, e := p.ssFrame(address)
		return append(out, b...), e
	}
	return nil, errors.New("PROTOCOL_INVALID")
}
func (p *protocol) vmessHeader(address []byte) ([]byte, error) {
	r := randomBytes(33)
	p.upIV = append([]byte{}, r[:16]...)
	p.upKey = append([]byte{}, r[16:32]...)
	p.response = r[32]
	digest := shaBytes
	if p.c.AlterID > 0 {
		digest = md5Bytes
	}
	p.downKey = digest(p.upKey)[:16]
	p.downIV = digest(p.upIV)[:16]
	if p.c.AlterID > 0 {
		b, _ := aes.NewCipher(p.downKey)
		p.responseCipher = cipher.NewCFBDecrypter(b, p.downIV)
	}
	if p.vmCFB {
		b, _ := aes.NewCipher(p.upKey)
		p.upCipher = cipher.NewCFBEncrypter(b, p.upIV)
	}
	opt, sec := byte(1), byte(3)
	if p.vmZero {
		opt = 0
	}
	if p.vmCFB {
		sec = 1
	} else if p.method == "none" {
		sec = 5
	} else if p.method == "chacha20-poly1305" {
		sec = 4
	}
	cmd := byte(1)
	if p.udp {
		cmd = 2
	}
	header := join([]byte{1}, p.upIV, p.upKey, []byte{p.response, opt, sec, 0, cmd}, mappedAddress(address))
	header = append(header, fnv32(header)...)
	primary := append([]byte{}, p.c.UUID[:]...)
	command := md5Bytes(join(primary, []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")))
	var out []byte
	if p.c.AlterID > 0 {
		auth := primary
		selection := intRange{1, p.c.AlterID}.choose()
		for i := 0; i < selection; i++ {
			material := join(auth, []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
			next := md5Bytes(material)
			for bytesEqual(next, auth) {
				material = append(material, []byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2")...)
				next = md5Bytes(material)
			}
			auth = next
		}
		stamp := wide(uint64(time.Now().Unix()))
		h := hmac.New(md5.New, auth)
		h.Write(stamp)
		out = h.Sum(nil)
		b, _ := aes.NewCipher(command)
		iv := md5Bytes(join(stamp, stamp, stamp, stamp))
		encrypted := make([]byte, len(header))
		cipher.NewCFBEncrypter(b, iv).XORKeyStream(encrypted, header)
		out = append(out, encrypted...)
	} else {
		auth := join(wide(uint64(time.Now().Unix())), randomBytes(4))
		crc := make([]byte, 4)
		binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE(auth))
		auth = append(auth, crc...)
		auth, _ = aesECB(vmessKDF(command, []byte("AES Auth ID Encryption"))[:16], auth, false)
		nonce := randomBytes(8)
		seal := func(label, ivlabel string, data []byte) []byte {
			a, _ := cipherAEAD("aes-128-gcm", vmessKDF(command, []byte(label), auth, nonce)[:16])
			return a.Seal(nil, vmessKDF(command, []byte(ivlabel), auth, nonce)[:12], data, auth)
		}
		out = join(auth, seal("VMess Header AEAD Key_Length", "VMess Header AEAD Nonce_Length", word(len(header))), nonce, seal("VMess Header AEAD Key", "VMess Header AEAD Nonce", header))
	}
	if p.method == "chacha20-poly1305" {
		a := md5Bytes(p.upKey)
		p.upKey = join(a, md5Bytes(a))
	}
	if p.method != "none" && !p.vmCFB {
		p.upAEAD, _ = cipherAEAD(p.method, p.upKey)
	}
	return out, nil
}
func bytesEqual(a, b []byte) bool { return hmac.Equal(a, b) }
func (p *protocol) ssFrame(data []byte) ([]byte, error) {
	out := p.upAEAD.Seal(nil, p.upIV, word(len(data)), nil)
	if e := nonceAdvance(p.upIV); e != nil {
		return nil, e
	}
	out = append(out, p.upAEAD.Seal(nil, p.upIV, data, nil)...)
	return out, nonceAdvance(p.upIV)
}
func vmNonce(iv []byte, count uint32) ([]byte, error) {
	if count >= 65536 {
		return nil, errors.New("VMESS_NONCE_EXHAUSTED")
	}
	return join(word(int(count)), iv[2:12]), nil
}
func (p *protocol) vmFrame(data []byte) ([]byte, error) {
	payload := data
	if p.vmCFB {
		payload = join(fnv32(data), data)
	} else if p.method != "none" {
		nonce, e := vmNonce(p.upIV, p.countUp)
		if e != nil {
			return nil, e
		}
		payload = p.upAEAD.Seal(nil, nonce, data, nil)
	}
	p.countUp++
	out := join(word(len(payload)), payload)
	if p.vmCFB {
		p.upCipher.XORKeyStream(out, out)
	}
	return out, nil
}
func (p *protocol) encode(data []byte) ([]byte, error) {
	if p.c.Protocol == "vless" {
		return p.vision.encode(data), nil
	}
	if p.c.Protocol == "trojan" || p.none || p.vmZero {
		return data, nil
	}
	if p.stream {
		out := make([]byte, len(data))
		p.upCipher.XORKeyStream(out, data)
		return out, nil
	}
	var out []byte
	maximum := 16368
	if p.c.Protocol == "ss" {
		maximum = 16383
		if p.modern {
			maximum = 65535
		}
	}
	for len(data) > 0 {
		n := min(len(data), maximum)
		var b []byte
		var e error
		if p.c.Protocol == "ss" {
			b, e = p.ssFrame(data[:n])
		} else {
			b, e = p.vmFrame(data[:n])
		}
		if e != nil {
			return nil, e
		}
		out = append(out, b...)
		data = data[n:]
	}
	return out, nil
}
func (p *protocol) finish() ([]byte, error) {
	if p.c.Protocol == "vmess" && !p.vmZero {
		return p.vmFrame(nil)
	}
	return nil, nil
}
func (p *protocol) pop(n int) []byte { b := p.input[:n]; p.input = p.input[n:]; return b }
func (p *protocol) decode(wire []byte) ([]byte, error) {
	if p.c.Protocol == "trojan" || p.none {
		return wire, nil
	}
	p.input = append(p.input, wire...)
	if len(p.input) > 1048576 {
		return nil, errors.New("PROTOCOL_INPUT_LIMIT")
	}
	var out []byte
	if p.c.Protocol == "vless" {
		if !p.header {
			if len(p.input) < 2 {
				return nil, nil
			}
			if p.input[0] != 0 {
				return nil, errors.New("VLESS_RESPONSE_VERSION")
			}
			n := int(p.input[1]) + 2
			if len(p.input) < n {
				return nil, nil
			}
			p.pop(n)
			p.header = true
		}
		return p.vision.decode(p.pop(len(p.input)))
	}
	if p.c.Protocol == "ss" {
		spec := ssCipherSpec(p.c.Cipher)
		if !p.header {
			n := spec.key
			if p.stream {
				n = spec.iv
			}
			if len(p.input) < n {
				return nil, nil
			}
			iv := append([]byte{}, p.pop(n)...)
			var e error
			if p.stream {
				p.downCipher, e = ssStreamCipher(p.c.Cipher, p.master, iv, true)
			} else {
				if !p.modern {
					if bytesEqual(iv, p.upSalt) {
						return nil, errors.New("SS_SALT_REFLECTION")
					}
					if e = checkSalt(p.master, iv); e != nil {
						return nil, e
					}
				}
				p.downKey, e = subkey(p.master, iv, spec.key, p.modern)
				if e == nil {
					p.downAEAD, e = cipherAEAD(p.method, p.downKey)
				}
				p.downIV = make([]byte, spec.iv)
			}
			if e != nil {
				return nil, e
			}
			p.header = true
		}
		if p.stream {
			out = make([]byte, len(p.input))
			p.downCipher.XORKeyStream(out, p.pop(len(p.input)))
			return out, nil
		}
		if p.modern && !p.responseDone {
			n := 11 + spec.key + 16
			if len(p.input) < n {
				return nil, nil
			}
			b, e := p.downAEAD.Open(nil, p.downIV, p.pop(n), nil)
			if e != nil {
				return nil, errors.New("SS2022_RESPONSE_HEADER_AUTH")
			}
			nonceAdvance(p.downIV)
			stamp, now := int64(binary.BigEndian.Uint64(b[1:9])), time.Now().Unix()
			if b[0] != 1 || stamp < now-30 || stamp > now+30 || !bytesEqual(b[9:9+spec.key], p.upSalt) {
				return nil, errors.New("SS2022_RESPONSE_AUTH")
			}
			p.size = int(binary.BigEndian.Uint16(b[9+spec.key:]))
			if p.size == 0 {
				return nil, errors.New("SS2022_RESPONSE_LENGTH")
			}
			p.haveLength, p.responseDone = true, true
		}
		for {
			if !p.haveLength {
				if len(p.input) < 18 {
					break
				}
				b, e := p.downAEAD.Open(nil, p.downIV, p.pop(18), nil)
				if e != nil {
					return nil, errors.New("SS_RESPONSE_LENGTH_AUTH")
				}
				nonceAdvance(p.downIV)
				p.size = int(binary.BigEndian.Uint16(b))
				if p.size == 0 || !p.modern && p.size > 16383 {
					return nil, errors.New("SS_CHUNK_LENGTH")
				}
				p.haveLength = true
			}
			if len(p.input) < p.size+16 {
				break
			}
			b, e := p.downAEAD.Open(nil, p.downIV, p.pop(p.size+16), nil)
			if e != nil {
				return nil, errors.New("SS_RESPONSE_PAYLOAD_AUTH")
			}
			nonceAdvance(p.downIV)
			out = append(out, b...)
			p.haveLength = false
		}
		return out, nil
	}
	if !p.header {
		if p.c.AlterID > 0 {
			if len(p.input) < 4 {
				return nil, nil
			}
			b := make([]byte, 4)
			p.responseCipher.XORKeyStream(b, p.pop(4))
			if !bytesEqual(b, []byte{p.response, 0, 0, 0}) {
				return nil, errors.New("VMESS_LEGACY_RESPONSE_AUTH")
			}
			if p.vmCFB {
				p.downCipher = p.responseCipher
			}
		} else {
			open := func(label, ivlabel string, data []byte) ([]byte, error) {
				a, e := cipherAEAD("aes-128-gcm", vmessKDF(p.downKey, []byte(label))[:16])
				if e != nil {
					return nil, e
				}
				return a.Open(nil, vmessKDF(p.downIV, []byte(ivlabel))[:12], data, nil)
			}
			if !p.haveLength {
				if len(p.input) < 18 {
					return nil, nil
				}
				b, e := open("AEAD Resp Header Len Key", "AEAD Resp Header Len IV", p.pop(18))
				if e != nil {
					return nil, errors.New("VMESS_RESPONSE_LENGTH_AUTH")
				}
				p.size = int(binary.BigEndian.Uint16(b))
				if p.size < 4 || p.size > 1024 {
					return nil, errors.New("VMESS_RESPONSE_LENGTH")
				}
				p.haveLength = true
			}
			if len(p.input) < p.size+16 {
				return nil, nil
			}
			b, e := open("AEAD Resp Header Key", "AEAD Resp Header IV", p.pop(p.size+16))
			if e != nil || !bytesEqual(b, []byte{p.response, 0, 0, 0}) {
				return nil, errors.New("VMESS_RESPONSE_AUTH")
			}
			p.haveLength = false
		}
		p.header = true
		if p.method == "chacha20-poly1305" {
			a := md5Bytes(p.downKey)
			p.downKey = join(a, md5Bytes(a))
		}
		if p.vmCFB && p.c.AlterID == 0 {
			b, _ := aes.NewCipher(p.downKey)
			p.downCipher = cipher.NewCFBDecrypter(b, p.downIV)
		}
		if p.method != "none" && !p.vmCFB {
			p.downAEAD, _ = cipherAEAD(p.method, p.downKey)
		}
	}
	if p.vmZero {
		return p.pop(len(p.input)), nil
	}
	if p.vmCFB {
		plain := make([]byte, len(p.input))
		p.downCipher.XORKeyStream(plain, p.pop(len(p.input)))
		p.legacy = append(p.legacy, plain...)
		p.input = p.legacy
		p.legacy = nil
	}
	for len(p.input) >= 2 {
		n := int(binary.BigEndian.Uint16(p.input))
		limit := 16384
		if p.udp {
			limit = 65535
		}
		if n > limit {
			return nil, errors.New("VMESS_CHUNK_LENGTH")
		}
		if len(p.input) < n+2 {
			break
		}
		p.pop(2)
		b := p.pop(n)
		if p.vmCFB {
			if len(b) < 4 || !bytesEqual(b[:4], fnv32(b[4:])) {
				return nil, errors.New("VMESS_CFB_CHECKSUM")
			}
			b = b[4:]
		} else if p.method != "none" {
			nonce, e := vmNonce(p.downIV, p.countDown)
			if e != nil {
				return nil, e
			}
			b, e = p.downAEAD.Open(nil, nonce, b, nil)
			if e != nil {
				return nil, errors.New("VMESS_RESPONSE_PAYLOAD_AUTH")
			}
		}
		p.countDown++
		if len(b) == 0 {
			p.closed = true
			if len(p.input) > 0 {
				return nil, errors.New("VMESS_DATA_AFTER_EOF")
			}
			break
		}
		if p.udp {
			out = append(out, word(len(b))...)
		}
		out = append(out, b...)
	}
	if p.vmCFB {
		p.legacy = p.input
		p.input = nil
	}
	return out, nil
}

type protocolConn struct {
	scratch [32768]byte
	net.Conn
	p       *protocol
	readBuf []byte
	readErr error
	writeMu sync.Mutex
}

func (c *protocolConn) Read(b []byte) (int, error) {
	for len(c.readBuf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if c.p.closed {
			return 0, io.EOF
		}
		wire := c.scratch[:]
		n, e := c.Conn.Read(wire)
		plain, de := c.p.decode(wire[:n])
		if de != nil {
			return 0, de
		}
		if c.p.vision.direct {
			if raw, ok := c.Conn.(interface{ switchDirectRead() }); ok {
				raw.switchDirectRead()
				c.p.vision.direct = false
			} else {
				return 0, errors.New("VISION_DIRECT_SECURITY")
			}
		}
		c.readBuf = plain
		if e != nil {
			c.readErr = e
		}
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		b = b[n:]
	}
	return nil
}
func (c *protocolConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(b) > 0 {
		n := min(len(b), 32768)
		wire, e := c.p.encode(b[:n])
		if e == nil {
			e = writeAll(c.Conn, wire)
		}
		if e != nil {
			return total, e
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
func (c *protocolConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire, e := c.p.finish()
	if e == nil {
		e = writeAll(c.Conn, wire)
	}
	if e != nil {
		return e
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
