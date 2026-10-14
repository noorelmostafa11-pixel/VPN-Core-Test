package core

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

type encryptionServerKey struct {
	x      *ecdh.PrivateKey
	kem    *mlkem.DecapsulationKey768
	public []byte
	hash   [32]byte
}
type encryptionServerTicket struct {
	pfs     [64]byte
	expires time.Time
}
type vlessEncryptionServer struct {
	keys                   []encryptionServerKey
	mode                   string
	secondsFrom, secondsTo int
	padding                [][3]int
	mu                     sync.Mutex
	tickets                map[[16]byte]encryptionServerTicket
	replay                 map[[32]byte]time.Time
	nextReclaim            time.Time
}

func appendEncryptionPadding(rules *[][3]int, text string) error {
	fields := strings.Split(text, "-")
	if len(fields) != 3 || len(*rules) >= 16 {
		return providerError(500)
	}
	var p [3]int
	for i, value := range fields {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 {
			return providerError(500)
		}
		p[i] = n
	}
	if p[0] > 100 || len(*rules) == 0 && (p[0] != 100 || p[1] < 35 || p[2] < 35) {
		return providerError(500)
	}
	total := 0
	for index, prior := range append(append([][3]int(nil), (*rules)...), p) {
		if index%2 == 0 {
			total += max(prior[1], prior[2])
		}
	}
	if total > 65553 {
		return providerError(500)
	}
	*rules = append(*rules, p)
	return nil
}

func compileVLESSDecryption(text string) (*vlessEncryptionServer, error) {
	bad := errors.New("VLESS_SERVER_DECRYPTION_INVALID")
	if len(text) > 20480 {
		return nil, bad
	}
	parts := strings.Split(text, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" || !contains([]string{"native", "xorpub", "random"}, parts[1]) {
		return nil, bad
	}
	s := &vlessEncryptionServer{mode: parts[1], tickets: map[[16]byte]encryptionServerTicket{}, replay: map[[32]byte]time.Time{}}
	seconds := strings.Split(strings.TrimSuffix(parts[2], "s"), "-")
	if len(seconds) > 2 {
		return nil, bad
	}
	var err error
	s.secondsFrom, err = number(seconds[0], 0, 65535)
	if err != nil {
		return nil, bad
	}
	if len(seconds) == 2 {
		s.secondsTo, err = number(seconds[1], s.secondsFrom, 65535)
		if err != nil {
			return nil, bad
		}
	}
	seen := map[[32]byte]bool{}
	for _, part := range parts[3:] {
		if len(part) < 20 {
			if len(s.keys) != 0 || appendEncryptionPadding(&s.padding, part) != nil {
				return nil, bad
			}
			continue
		}
		if len(s.keys) >= 8 || len(part) > 128 {
			return nil, bad
		}
		key, err := decodeKey(part)
		if err != nil {
			return nil, bad
		}
		k := encryptionServerKey{}
		switch len(key) {
		case 32:
			if bytesEqual(key, make([]byte, 32)) {
				return nil, bad
			}
			k.x, err = ecdh.X25519().NewPrivateKey(key)
			if err == nil {
				k.public = k.x.PublicKey().Bytes()
			}
		case 64:
			k.kem, err = mlkem.NewDecapsulationKey768(key)
			if err == nil {
				k.public = k.kem.EncapsulationKey().Bytes()
			}
		default:
			return nil, bad
		}
		if err != nil {
			return nil, bad
		}
		k.hash = blake3.Sum256(k.public)
		if seen[k.hash] {
			return nil, bad
		}
		seen[k.hash] = true
		s.keys = append(s.keys, k)
	}
	if len(s.keys) == 0 {
		return nil, bad
	}
	return s, nil
}

func (s *vlessEncryptionServer) reclaim(now time.Time) {
	if now.Before(s.nextReclaim) {
		return
	}
	s.nextReclaim = now.Add(time.Second)
	for id, ticket := range s.tickets {
		if !ticket.expires.After(now) {
			delete(s.tickets, id)
		}
	}
	for id, expires := range s.replay {
		if !expires.After(now) {
			delete(s.replay, id)
		}
	}
}

func (s *vlessEncryptionServer) issueTicket(pfs []byte, now time.Time) ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	seconds := s.secondsFrom
	if s.secondsTo > 0 {
		seconds = (intRange{s.secondsFrom, s.secondsTo}).choose()
	} else {
		seconds = seconds * (intRange{50, 100}).choose() / 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reclaim(now)
	if len(s.tickets) >= 1024 {
		seconds = 0
	}
	binary.BigEndian.PutUint16(id[:2], uint16(seconds))
	if seconds > 0 {
		if _, collision := s.tickets[id]; collision {
			return id, errors.New("VLESS_SERVER_TICKET_COLLISION")
		}
		ticket := encryptionServerTicket{expires: now.Add(time.Duration(seconds) * time.Second)}
		copy(ticket.pfs[:], pfs)
		s.tickets[id] = ticket
	}
	return id, nil
}

func (s *vlessEncryptionServer) resumeTicket(id, nfs []byte, now time.Time) ([]byte, error) {
	if len(id) != 16 || len(nfs) != 32 {
		return nil, errors.New("VLESS_SERVER_TICKET_INVALID")
	}
	var ticketID [16]byte
	copy(ticketID[:], id)
	hash := sha256.Sum256(join(id, nfs))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reclaim(now)
	ticket, ok := s.tickets[ticketID]
	if !ok || !ticket.expires.After(now) {
		delete(s.tickets, ticketID)
		return nil, errors.New("VLESS_SERVER_TICKET_INVALID")
	}
	if _, ok = s.replay[hash]; ok {
		return nil, errors.New("VLESS_SERVER_TICKET_REPLAY")
	}
	if len(s.replay) >= 8192 {
		return nil, errors.New("VLESS_SERVER_TICKET_LIMIT")
	}
	s.replay[hash] = ticket.expires
	return append([]byte(nil), ticket.pfs[:]...), nil
}

func (s *vlessEncryptionServer) fixedExchange(raw net.Conn) (iv, nfs []byte, err error) {
	iv, err = readN(raw, 16)
	if err != nil {
		return
	}
	var prior cipher.Stream
	for index, k := range s.keys {
		n := 32
		if k.kem != nil {
			n = 1088
		}
		var public []byte
		public, err = readN(raw, n)
		if err != nil {
			return
		}
		if prior != nil {
			prior.XORKeyStream(public[:32], public[:32])
		}
		if s.mode != "native" {
			var mask cipher.Stream
			mask, err = keyCTR(k.public, iv)
			if err != nil {
				return
			}
			mask.XORKeyStream(public, public)
		}
		if k.x != nil {
			if public[31] > 127 {
				err = errors.New("VLESS_SERVER_KEY_NONCANONICAL")
				return
			}
			var pk *ecdh.PublicKey
			pk, err = ecdh.X25519().NewPublicKey(public)
			if err == nil {
				nfs, err = k.x.ECDH(pk)
			}
		} else {
			nfs, err = k.kem.Decapsulate(public)
		}
		if err != nil {
			return
		}
		if index+1 < len(s.keys) {
			var tag []byte
			tag, err = readN(raw, 32)
			if err != nil {
				return
			}
			prior, err = keyCTR(nfs, iv)
			if err != nil {
				return
			}
			prior.XORKeyStream(tag, tag)
			if !bytesEqual(tag, s.keys[index+1].hash[:]) {
				err = errors.New("VLESS_SERVER_KEY_COMMITMENT")
				return
			}
		}
	}
	return
}

func encryptedHandshakeRecord(raw net.Conn, a *recordAEAD, minLen int) ([]byte, error) {
	header, err := readN(raw, 18)
	if err != nil {
		return nil, err
	}
	length, err := a.open(header, nil)
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length))
	if n < minLen {
		return nil, providerError(502)
	}
	wire, err := readN(raw, n)
	if err != nil {
		return nil, err
	}
	return a.open(wire, nil)
}

func (s *vlessEncryptionServer) handshake(ctx context.Context, raw net.Conn, deadline time.Time) (*vlessEncryptionConn, error) {
	iv, nfs, err := s.fixedExchange(raw)
	if err != nil {
		return nil, err
	}
	lengthWire, err := readN(raw, 18)
	if err != nil {
		return nil, err
	}
	useAES := true
	auth, err := encryptionAEAD(iv, nfs, useAES)
	if err != nil {
		return nil, err
	}
	length, err := auth.open(lengthWire, nil)
	if err != nil {
		useAES = false
		auth, err = encryptionAEAD(iv, nfs, useAES)
		if err == nil {
			length, err = auth.open(lengthWire, nil)
		}
	}
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length))
	c := &vlessEncryptionConn{Conn: raw, useAES: useAES, randomMode: s.mode == "random"}
	if n == 32 {
		wire, err := readN(raw, 32)
		if err != nil {
			return nil, err
		}
		id, err := auth.open(wire, nil)
		if err != nil {
			return nil, err
		}
		pfs, err := s.resumeTicket(id, nfs, time.Now())
		if err != nil {
			return nil, err
		}
		c.united = join(pfs, nfs)
		random := make([]byte, 16)
		if _, err = rand.Read(random); err != nil {
			return nil, err
		}
		c.readCipher, err = encryptionAEAD(wire, c.united, useAES)
		if err == nil {
			c.writeCipher, err = encryptionAEAD(random, c.united, useAES)
		}
		if err == nil && c.randomMode {
			c.inCTR, err = keyCTR(c.united, iv)
			if err == nil {
				c.outCTR, err = keyCTR(c.united, random)
			}
		}
		if err == nil {
			err = writeAll(raw, random)
		}
		return c, err
	}
	if n < 1232 {
		return nil, providerError(502)
	}
	wire, err := readN(raw, n)
	if err != nil {
		return nil, err
	}
	public, err := auth.open(wire, nil)
	if err != nil {
		return nil, err
	}
	kem, err := mlkem.NewEncapsulationKey768(public[:1184])
	if err != nil {
		return nil, err
	}
	kemSecret, kemCipher := kem.Encapsulate()
	xpub, err := ecdh.X25519().NewPublicKey(public[1184:1216])
	if err != nil {
		return nil, err
	}
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	xsecret, err := xkey.ECDH(xpub)
	if err != nil {
		return nil, err
	}
	pfs, replyPublic := join(kemSecret, xsecret), join(kemCipher, xkey.PublicKey().Bytes())
	c.united = join(pfs, nfs)
	c.readCipher, err = encryptionAEAD(public[:1216], c.united, useAES)
	if err == nil {
		c.writeCipher, err = encryptionAEAD(replyPublic, c.united, useAES)
	}
	if err != nil {
		return nil, err
	}
	id, err := s.issueTicket(pfs, time.Now())
	if err != nil {
		return nil, err
	}
	// Remove a new ticket if the client never authenticates its padding.
	committed := false
	defer func() {
		if !committed {
			s.mu.Lock()
			delete(s.tickets, id)
			s.mu.Unlock()
		}
	}()
	maxNonce := [12]byte{}
	for i := range maxNonce {
		maxNonce[i] = 255
	}
	reply := auth.Seal(nil, maxNonce[:], replyPublic, nil)
	ticketWire, err := c.writeCipher.seal(id[:], nil)
	if err != nil {
		return nil, err
	}
	helper := encryptionSession{config: encryptionConfig{padding: s.padding}, wire: raw, paddingContext: ctx, deadline: deadline}
	hello, lengths, gaps, err := helper.padding(c.writeCipher, join(reply, ticketWire))
	if err != nil {
		return nil, err
	}
	// Existing connection deadline bounds I/O and cancellation. Padding gaps use
	// deadline-aware waits in the shared sender, without maintenance workers.
	if err = helper.sendPadding(hello, lengths, gaps); err != nil {
		return nil, err
	}
	if _, err = encryptedHandshakeRecord(raw, auth, 16); err != nil {
		return nil, err
	}
	if c.randomMode {
		c.inCTR, err = keyCTR(c.united, iv)
		if err == nil {
			c.outCTR, err = keyCTR(c.united, id[:])
		}
	}
	if err != nil {
		return nil, err
	}
	committed = true
	return c, nil
}
