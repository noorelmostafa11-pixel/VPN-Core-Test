package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"net"

	"encoding/binary"

	"errors"
	"io"
	"lukechampine.com/blake3"
	"strconv"
	"strings"
	"sync"
	"time"
)

type encryptionConfig struct {
	mode    string
	resume  bool
	keys    [][]byte
	padding [][3]int
}

func parseEncryption(text string) (encryptionConfig, error) {
	var c encryptionConfig
	parts := strings.Split(text, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return c, providerError(500)
	}
	c.mode = parts[1]
	if c.mode != "native" && c.mode != "xorpub" && c.mode != "random" {
		return c, providerError(500)
	}
	if parts[2] != "1rtt" && parts[2] != "0rtt" {
		return c, providerError(500)
	}
	c.resume = parts[2] == "0rtt"
	seenKey := false
	totalPadding := 0
	for _, part := range parts[3:] {
		if len(part) < 20 {
			if seenKey {
				return c, providerError(500)
			}
			fields := strings.Split(part, "-")
			if len(fields) != 3 {
				return c, providerError(500)
			}
			var p [3]int
			for i, value := range fields {
				n, err := strconv.Atoi(value)
				if err != nil || n < 0 || n > 65535 {
					return c, providerError(500)
				}
				p[i] = n
			}
			if p[0] > 100 {
				return c, providerError(500)
			}
			if len(c.padding) == 0 && (p[0] < 100 || p[1] < 35 || p[2] < 35) {
				return c, providerError(500)
			}
			if len(c.padding)%2 == 0 {
				totalPadding += max(p[1], p[2])
			}
			if totalPadding > 65553 || len(c.padding) > 16 {
				return c, providerError(500)
			}
			c.padding = append(c.padding, p)
			continue
		}
		seenKey = true
		key, err := decodeKey(part)
		if err != nil || (len(key) != 32 && len(key) != 1184) || len(c.keys) >= 8 {
			return c, providerError(500)
		}
		if len(key) == 1184 {
			if _, err = mlkem.NewEncapsulationKey768(key); err != nil {
				return c, providerError(500)
			}
		} else {
			if _, err = ecdh.X25519().NewPublicKey(key); err != nil {
				return c, providerError(500)
			}
		}
		c.keys = append(c.keys, key)
	}
	if len(c.keys) == 0 {
		return c, providerError(500)
	}
	return c, nil
}
func deriveBLAKE3(context, key []byte) []byte {
	out := make([]byte, 32)
	blake3.DeriveKey(out, string(context), key)
	return out
}
func keyCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(deriveBLAKE3([]byte("VLESS"), key))
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

type recordAEAD struct {
	cipher.AEAD
	nonce [12]byte
}

func newRecordAEAD(context, key []byte) (*recordAEAD, error) {
	block, err := aes.NewCipher(deriveBLAKE3(context, key))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	return &recordAEAD{AEAD: aead}, err
}
func (a *recordAEAD) next() ([]byte, error) {
	for i := 11; i >= 0; i-- {
		a.nonce[i]++
		if a.nonce[i] != 0 {
			return a.nonce[:], nil
		}
	}
	return nil, providerError(506)
}
func (a *recordAEAD) seal(plain, aad []byte) ([]byte, error) {
	nonce, err := a.next()
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plain, aad), nil
}
func (a *recordAEAD) open(wire, aad []byte) ([]byte, error) {
	nonce, err := a.next()
	if err != nil {
		return nil, err
	}
	plain, err := a.Open(nil, nonce, wire, aad)
	if err != nil {
		return nil, providerError(501)
	}
	return plain, nil
}
func encLength(value int) []byte { return []byte{byte(value >> 8), byte(value)} }
func readN(r io.Reader, n int) ([]byte, error) {
	if n < 0 || n > 65553 {
		return nil, providerError(502)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

type savedTicket struct {
	pfs, ticket []byte
	expires     time.Time
}

var ticketMu sync.Mutex
var tickets = map[[32]byte]savedTicket{}

func getTicket(id [32]byte) savedTicket {
	ticketMu.Lock()
	defer ticketMu.Unlock()
	saved := tickets[id]
	if !time.Now().Before(saved.expires) {
		delete(tickets, id)
		return savedTicket{}
	}
	saved.pfs = append([]byte(nil), saved.pfs...)
	saved.ticket = append([]byte(nil), saved.ticket...)
	return saved
}
func putTicket(id [32]byte, saved savedTicket) {
	ticketMu.Lock()
	defer ticketMu.Unlock()
	for key, ticket := range tickets {
		if !time.Now().Before(ticket.expires) {
			delete(tickets, key)
		}
	}
	if len(tickets) >= 1024 {
		for key := range tickets {
			delete(tickets, key)
			break
		}
	}
	tickets[id] = saved
}
func forgetTicket(id [32]byte) { ticketMu.Lock(); delete(tickets, id); ticketMu.Unlock() }

type encryptionSession struct {
	mu                   sync.Mutex
	wire                 net.Conn
	up, down             *byteQueue
	state, code          int
	config               encryptionConfig
	cacheID              [32]byte
	united               []byte
	upCipher, downCipher *recordAEAD
	upCTR, downCTR       cipher.Stream
	pendingRandom        bool
	deadline             time.Time
	accepted, encoded    uint64
	uploadDone           bool
}

func (s *encryptionSession) fail(err error) {
	code := 503
	var pe providerError
	if errors.As(err, &pe) {
		code = int(pe)
	}
	s.mu.Lock()
	s.state = -1
	s.code = code
	s.mu.Unlock()
	_ = s.wire.Close()
	s.up.close(err)
	s.down.close(err)
	forgetTicket(s.cacheID)
}
func (s *encryptionSession) writeWire(data []byte) error { _, err := s.wire.Write(data); return err }
func (s *encryptionSession) clientPrefix() (iv, nfs, relays []byte, err error) {
	iv = make([]byte, 16)
	if _, err = rand.Read(iv); err != nil {
		return
	}
	var prior cipher.Stream
	for index, key := range s.config.keys {
		var public []byte
		if len(key) == 32 {
			var sk *ecdh.PrivateKey
			sk, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return
			}
			var pk *ecdh.PublicKey
			pk, err = ecdh.X25519().NewPublicKey(key)
			if err != nil {
				return
			}
			nfs, err = sk.ECDH(pk)
			if err != nil {
				return
			}
			public = append([]byte(nil), sk.PublicKey().Bytes()...)
		} else {
			var pk *mlkem.EncapsulationKey768
			pk, err = mlkem.NewEncapsulationKey768(key)
			if err != nil {
				return
			}
			nfs, public = pk.Encapsulate()
		}
		if s.config.mode != "native" {
			var mask cipher.Stream
			mask, err = keyCTR(key, iv)
			if err != nil {
				return
			}
			mask.XORKeyStream(public, public)
		}
		if prior != nil {
			prior.XORKeyStream(public[:32], public[:32])
		}
		relays = append(relays, public...)
		if index+1 < len(s.config.keys) {
			prior, err = keyCTR(nfs, iv)
			if err != nil {
				return
			}
			hash := blake3.Sum256(s.config.keys[index+1])
			tag := make([]byte, 32)
			prior.XORKeyStream(tag, hash[:])
			relays = append(relays, tag...)
		}
	}
	return
}
func (s *encryptionSession) padding(a *recordAEAD, prefix []byte) ([]byte, []int, []time.Duration, error) {
	rules := s.config.padding
	if len(rules) == 0 {
		rules = [][3]int{{100, 111, 1111}, {75, 0, 111}, {50, 0, 3333}}
	}
	lengths := []int{}
	gaps := []time.Duration{}
	total := 0
	for index, p := range rules {
		value := 0
		if (intRange{0, 100}).choose() <= p[0] {
			value = intRange{min(p[1], p[2]), max(p[1], p[2])}.choose()
		}
		if index%2 == 0 {
			lengths = append(lengths, value)
			total += value
		} else {
			gaps = append(gaps, time.Duration(value)*time.Millisecond)
		}
	}
	if total < 35 || total > 65553 {
		return nil, nil, nil, providerError(500)
	}
	length, err := a.seal(encLength(total-18), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	padding, err := a.seal(make([]byte, total-34), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	message := append(prefix, length...)
	message = append(message, padding...)
	lengths[0] += len(prefix)
	return message, lengths, gaps, nil
}
func (s *encryptionSession) sendPadding(message []byte, lengths []int, gaps []time.Duration) error {
	for i, n := range lengths {
		if n > 0 {
			if err := s.writeWire(message[:n]); err != nil {
				return err
			}
			message = message[n:]
		}
		if i < len(gaps) && gaps[i] > 0 {
			if time.Now().Add(gaps[i]).After(s.deadline) {
				return providerError(504)
			}
			time.Sleep(gaps[i])
		}
	}
	return nil
}
func (s *encryptionSession) handshake() error {
	iv, nfs, relays, err := s.clientPrefix()
	if err != nil {
		return err
	}
	nfsAEAD, err := newRecordAEAD(iv, nfs)
	if err != nil {
		return err
	}
	prefix := append(append([]byte(nil), iv...), relays...)
	saved := savedTicket{}
	if s.config.resume {
		saved = getTicket(s.cacheID)
	}
	if len(saved.ticket) == 16 {
		length, err := nfsAEAD.seal(encLength(32), nil)
		if err != nil {
			return err
		}
		encrypted, err := nfsAEAD.seal(saved.ticket, nil)
		if err != nil {
			return err
		}
		prefix = append(prefix, length...)
		prefix = append(prefix, encrypted...)
		s.united = append(saved.pfs, nfs...)
		s.upCipher, err = newRecordAEAD(encrypted, s.united)
		if err != nil {
			return err
		}
		if s.config.mode == "random" {
			s.upCTR, err = keyCTR(s.united, iv)
			if err != nil {
				return err
			}
		}
		s.pendingRandom = true
		return s.writeWire(prefix)
	}
	kem, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public := append(append([]byte(nil), kem.EncapsulationKey().Bytes()...), xkey.PublicKey().Bytes()...)
	length, err := nfsAEAD.seal(encLength(len(public)+16), nil)
	if err != nil {
		return err
	}
	encrypted, err := nfsAEAD.seal(public, nil)
	if err != nil {
		return err
	}
	prefix = append(prefix, length...)
	prefix = append(prefix, encrypted...)
	hello, lengths, gaps, err := s.padding(nfsAEAD, prefix)
	if err != nil {
		return err
	}
	if err = s.sendPadding(hello, lengths, gaps); err != nil {
		return err
	}
	reply, err := readN(s.wire, 1136)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = 255
	}
	peerPublic, err := nfsAEAD.Open(nil, nonce, reply, nil)
	if err != nil {
		return providerError(501)
	}
	kemSecret, err := kem.Decapsulate(peerPublic[:1088])
	if err != nil {
		return providerError(501)
	}
	xpub, err := ecdh.X25519().NewPublicKey(peerPublic[1088:1120])
	if err != nil {
		return providerError(501)
	}
	xsecret, err := xkey.ECDH(xpub)
	if err != nil {
		return providerError(501)
	}
	pfs := append(append([]byte(nil), kemSecret...), xsecret...)
	s.united = append(append([]byte(nil), pfs...), nfs...)
	s.upCipher, err = newRecordAEAD(public, s.united)
	if err != nil {
		return err
	}
	s.downCipher, err = newRecordAEAD(peerPublic, s.united)
	if err != nil {
		return err
	}
	encryptedTicket, err := readN(s.wire, 32)
	if err != nil {
		return err
	}
	ticket, err := s.downCipher.open(encryptedTicket, nil)
	if err != nil {
		return err
	}
	seconds := int(binary.BigEndian.Uint16(ticket[:2]))
	if s.config.resume && seconds > 0 {
		putTicket(s.cacheID, savedTicket{pfs: pfs, ticket: append([]byte(nil), ticket...), expires: time.Now().Add(time.Duration(seconds) * time.Second)})
	}
	encryptedLength, err := readN(s.wire, 18)
	if err != nil {
		return err
	}
	plainLength, err := s.downCipher.open(encryptedLength, nil)
	if err != nil {
		return err
	}
	count := int(binary.BigEndian.Uint16(plainLength))
	if count < 16 {
		return providerError(502)
	}
	padding, err := readN(s.wire, count)
	if err != nil {
		return err
	}
	if _, err = s.downCipher.open(padding, nil); err != nil {
		return err
	}
	if s.config.mode == "random" {
		s.upCTR, err = keyCTR(s.united, iv)
		if err != nil {
			return err
		}
		s.downCTR, err = keyCTR(s.united, ticket)
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *encryptionSession) upload() error {
	buffer := make([]byte, 8192)
	for {
		n, err := s.up.Read(buffer)
		if n > 0 {
			header := []byte{23, 3, 3, byte((n + 16) >> 8), byte(n + 16)}
			payload, e := s.upCipher.seal(buffer[:n], header)
			if e != nil {
				return e
			}
			if s.upCTR != nil {
				s.upCTR.XORKeyStream(header, header)
			}
			if e = s.writeWire(append(header, payload...)); e != nil {
				return e
			}
			s.up.mu.Lock()
			s.encoded += uint64(n)
			s.up.mu.Unlock()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.up.mu.Lock()
				s.uploadDone = true
				s.up.mu.Unlock()
				return nil
			}
			return err
		}
	}
}
func (s *encryptionSession) download() error {
	if s.pendingRandom {
		random, err := readN(s.wire, 16)
		if err != nil {
			return err
		}
		s.downCipher, err = newRecordAEAD(random, s.united)
		if err != nil {
			return err
		}
		if s.config.mode == "random" {
			s.downCTR, err = keyCTR(s.united, random)
			if err != nil {
				return err
			}
		}
	}
	for {
		header, err := readN(s.wire, 5)
		if err != nil {
			return err
		}
		if s.downCTR != nil {
			s.downCTR.XORKeyStream(header, header)
		}
		count := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 23 || header[1] != 3 || header[2] != 3 || count < 17 || count > 16640 {
			return providerError(502)
		}
		payload, err := readN(s.wire, count)
		if err != nil {
			return err
		}
		plain, err := s.downCipher.open(payload, header)
		if err != nil {
			return err
		}
		if _, err = s.down.Write(plain); err != nil {
			return err
		}
	}
}
func (s *encryptionSession) run(timeout int) {
	s.deadline = time.Now().Add(time.Duration(timeout) * time.Millisecond)
	_ = s.wire.SetDeadline(s.deadline)
	if err := s.handshake(); err != nil {
		s.fail(err)
		return
	}
	_ = s.wire.SetDeadline(time.Time{})
	s.mu.Lock()
	s.state = 1
	s.mu.Unlock()
	go func() {
		if err := s.upload(); err != nil {
			s.fail(err)
		}
	}()
	if err := s.download(); err != nil {
		if errors.Is(err, io.EOF) {
			s.down.close(nil)
			s.mu.Lock()
			if s.state >= 0 {
				s.state = 2
			}
			s.mu.Unlock()
		} else {
			s.fail(err)
		}
	}
}
