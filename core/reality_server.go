package core

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type RealityServerConfig struct {
	PrivateKey    string   `json:"private_key"`
	ServerNames   []string `json:"server_names"`
	ShortIDs      []string `json:"short_ids"`
	Target        string   `json:"target"`
	MaxTimeDiffMS int      `json:"max_time_diff_ms,omitempty"`
}

type realityServerState struct {
	private  *ecdh.PrivateKey
	signer   ed25519.PrivateKey
	names    map[string]bool
	shortIDs map[[8]byte]bool
	dnsNames []string
	target   string
	timeDiff time.Duration
	mu       sync.Mutex
	replay   map[[32]byte]time.Time
}

func compileRealityServer(c RealityServerConfig) (*realityServerState, error) {
	if len(c.PrivateKey) < 1 || len(c.PrivateKey) > 128 {
		return nil, errors.New("REALITY_SERVER_PRIVATE_KEY_INVALID")
	}
	key, err := decodeKey(c.PrivateKey)
	if err != nil || len(key) != 32 || bytesEqual(key, make([]byte, 32)) {
		return nil, errors.New("REALITY_SERVER_PRIVATE_KEY_INVALID")
	}
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, errors.New("REALITY_SERVER_PRIVATE_KEY_INVALID")
	}
	if len(c.ServerNames) < 1 || len(c.ServerNames) > 32 || len(c.ShortIDs) < 1 || len(c.ShortIDs) > 128 {
		return nil, errors.New("REALITY_SERVER_IDENTITIES_INVALID")
	}
	if _, _, err = splitProtocolTarget(c.Target); err != nil || len(c.Target) > 512 {
		return nil, errors.New("REALITY_SERVER_TARGET_INVALID")
	}
	if c.MaxTimeDiffMS == 0 {
		c.MaxTimeDiffMS = 30000
	}
	if c.MaxTimeDiffMS < 1 || c.MaxTimeDiffMS > 300000 {
		return nil, errors.New("REALITY_SERVER_TIME_WINDOW_INVALID")
	}
	s := &realityServerState{private: private, names: map[string]bool{}, shortIDs: map[[8]byte]bool{}, target: c.Target, timeDiff: time.Duration(c.MaxTimeDiffMS) * time.Millisecond, replay: map[[32]byte]time.Time{}}
	for _, name := range c.ServerNames {
		name = strings.ToLower(name)
		if len(name) > 253 || strings.ContainsAny(name, "\x00 \t\r\n/:*") || s.names[name] {
			return nil, errors.New("REALITY_SERVER_NAME_INVALID")
		}
		s.names[name] = true
		if name != "" {
			s.dnsNames = append(s.dnsNames, name)
		}
	}
	for _, text := range c.ShortIDs {
		value, err := hex.DecodeString(text)
		if err != nil || len(value) > 8 {
			return nil, errors.New("REALITY_SERVER_SHORT_ID_INVALID")
		}
		var id [8]byte
		copy(id[:], value)
		if s.shortIDs[id] {
			return nil, errors.New("REALITY_SERVER_SHORT_ID_INVALID")
		}
		s.shortIDs[id] = true
	}
	_, s.signer, err = ed25519.GenerateKey(rand.Reader)
	return s, err
}

// Preserve complete wire records for either the authenticated native TLS
// handshake or configured fallback. ClientHello assembly is independently
// bounded, including fragmented records and extra bytes in the last record.
func readRealityHello(r io.Reader) (hello, prefix []byte, err error) {
	for records := 0; records < 16; records++ {
		var header [5]byte
		n, readErr := io.ReadFull(r, header[:])
		prefix = append(prefix, header[:n]...)
		if readErr != nil {
			return nil, prefix, readErr
		}
		length := getWord(header[:], 3)
		if header[0] != 22 || header[1] != 3 || header[2] > 3 || length < 1 || length > 16384 || len(prefix)+length > 131072 {
			return nil, prefix, errors.New("REALITY_SERVER_HELLO_INVALID")
		}
		body := make([]byte, length)
		n, readErr = io.ReadFull(r, body)
		prefix = append(prefix, body[:n]...)
		hello = append(hello, body[:n]...)
		if readErr != nil {
			return nil, prefix, readErr
		}
		if hello[0] != 1 {
			return nil, prefix, errors.New("REALITY_SERVER_HELLO_INVALID")
		}
		if len(hello) >= 4 {
			length = 4 + (int(hello[1]) << 16) + (int(hello[2]) << 8) + int(hello[3])
			if length < 71 || length > 65535 {
				return nil, prefix, errors.New("REALITY_SERVER_HELLO_INVALID")
			}
			if len(hello) >= length {
				return hello[:length], prefix, nil
			}
		}
	}
	return nil, prefix, errors.New("REALITY_SERVER_HELLO_LIMIT")
}

func realityHelloFields(hello []byte) (string, [][]byte, error) {
	bad := errors.New("REALITY_SERVER_HELLO_INVALID")
	if len(hello) < 75 || hello[0] != 1 || hello[38] != 32 {
		return "", nil, bad
	}
	pos := 71
	length := getWord(hello, pos)
	pos += 2
	if length < 2 || length%2 != 0 || length > len(hello)-pos {
		return "", nil, bad
	}
	pos += length
	if pos >= len(hello) || hello[pos] != 1 || pos+2 > len(hello) || hello[pos+1] != 0 {
		return "", nil, bad
	}
	pos += 2
	if pos+2 > len(hello) {
		return "", nil, bad
	}
	length = getWord(hello, pos)
	pos += 2
	if length != len(hello)-pos {
		return "", nil, bad
	}
	name, tls13 := "", false
	seen := map[int]bool{}
	var classic, hybrid []byte
	for pos < len(hello) {
		if pos+4 > len(hello) {
			return "", nil, bad
		}
		kind, size := getWord(hello, pos), getWord(hello, pos+2)
		pos += 4
		if size > len(hello)-pos || seen[kind] || len(seen) >= 128 {
			return "", nil, bad
		}
		seen[kind] = true
		body := hello[pos : pos+size]
		pos += size
		switch kind {
		case 0:
			if len(body) < 5 || getWord(body, 0) != len(body)-2 || body[2] != 0 || getWord(body, 3) != len(body)-5 {
				return "", nil, bad
			}
			name = strings.ToLower(string(body[5:]))
		case 43:
			if len(body) < 3 || int(body[0]) != len(body)-1 || body[0]%2 != 0 {
				return "", nil, bad
			}
			for p := 1; p < len(body); p += 2 {
				if getWord(body, p) == 0x0304 {
					tls13 = true
				}
			}
		case 51:
			if len(body) < 2 || getWord(body, 0) != len(body)-2 {
				return "", nil, bad
			}
			for p := 2; p < len(body); {
				if p+4 > len(body) {
					return "", nil, bad
				}
				group, n := getWord(body, p), getWord(body, p+2)
				p += 4
				if n > len(body)-p {
					return "", nil, bad
				}
				if group == 29 {
					if n != 32 || classic != nil {
						return "", nil, bad
					}
					classic = body[p : p+n]
				} else if group == 4588 {
					if n != 1216 || hybrid != nil {
						return "", nil, bad
					}
					hybrid = body[p+n-32 : p+n]
				}
				p += n
			}
		}
	}
	if !tls13 || classic == nil && hybrid == nil {
		return "", nil, bad
	}
	var keys [][]byte
	if classic != nil {
		keys = append(keys, classic)
	}
	if hybrid != nil {
		keys = append(keys, hybrid)
	}
	return name, keys, nil
}

func (s *realityServerState) authenticate(hello []byte, now time.Time) ([]byte, error) {
	name, shares, err := realityHelloFields(hello)
	if err != nil || !s.names[name] {
		return nil, errors.New("REALITY_SERVER_AUTHENTICATION")
	}
	aad := append([]byte(nil), hello...)
	clear(aad[39:71])
	for _, share := range shares {
		public, err := ecdh.X25519().NewPublicKey(share)
		if err != nil {
			continue
		}
		shared, err := s.private.ECDH(public)
		if err != nil {
			continue
		}
		auth, err := hkdf.Key(sha256.New, shared, hello[6:26], "REALITY", 32)
		if err != nil {
			continue
		}
		block, _ := aes.NewCipher(auth)
		gcm, _ := cipher.NewGCM(block)
		plain, err := gcm.Open(nil, hello[26:38], hello[39:71], aad)
		if err != nil || len(plain) != 16 || plain[3] != 0 {
			continue
		}
		stamp := time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)
		var id [8]byte
		copy(id[:], plain[8:])
		if now.Sub(stamp).Abs() > s.timeDiff || !s.shortIDs[id] {
			continue
		}
		key := sha256.Sum256(hello)
		s.mu.Lock()
		if expires, ok := s.replay[key]; ok && expires.After(now) {
			s.mu.Unlock()
			return nil, errors.New("REALITY_SERVER_REPLAY")
		}
		if len(s.replay) >= 8192 {
			for k, expires := range s.replay {
				if !expires.After(now) {
					delete(s.replay, k)
				}
			}
			if len(s.replay) >= 8192 {
				s.mu.Unlock()
				return nil, errors.New("REALITY_SERVER_REPLAY_LIMIT")
			}
		}
		s.replay[key] = now.Add(2*s.timeDiff + time.Second)
		s.mu.Unlock()
		return auth, nil
	}
	return nil, errors.New("REALITY_SERVER_AUTHENTICATION")
}

func (s *realityServerState) certificate(auth []byte) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "REALITY"}, DNSNames: s.dnsNames, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	public := s.signer.Public().(ed25519.PublicKey)
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, s.signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	var signed struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err = asn1.Unmarshal(der, &signed); err != nil {
		return tls.Certificate{}, err
	}
	mac := hmac.New(sha512.New, auth)
	mac.Write(public)
	signed.Signature = asn1.BitString{Bytes: mac.Sum(nil), BitLength: 512}
	der, err = asn1.Marshal(signed)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: s.signer, Leaf: leaf}, err
}

func (e *Engine) acceptReality(raw net.Conn, s serverSpec) (net.Conn, error) {
	hello, prefix, err := readRealityHello(raw)
	var auth []byte
	if err == nil {
		auth, err = s.reality.authenticate(hello, time.Now())
	}
	buffered := &bufferedConn{Conn: raw, r: io.MultiReader(bytes.NewReader(prefix), raw)}
	if err != nil {
		e.rejected.Add(1)
		if e.ctx.Err() == nil {
			e.realityFallback(buffered, s.reality.target)
		}
		return nil, err
	}
	certificate, err := s.reality.certificate(auth)
	if err != nil {
		return nil, err
	}
	config := s.tls.Clone()
	config.Certificates = []tls.Certificate{certificate}
	config.NextProtos = []string{"h2", "http/1.1"}
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		// REALITY fixes CertificateVerify to Ed25519 independently of the
		// browser signature advertisement. Go 1.27 exposes the parsed list
		// here while retaining the original ClientHello transcript bytes.
		// Apply this compatibility rule only after REALITY authentication.
		for _, scheme := range info.SignatureSchemes {
			if scheme == tls.Ed25519 {
				return nil, nil
			}
		}
		if len(info.SignatureSchemes) == 0 {
			return nil, errors.New("REALITY_SERVER_SIGNATURE_INVALID")
		}
		info.SignatureSchemes[0] = tls.Ed25519
		return nil, nil
	}
	wire := net.Conn(buffered)
	if s.vlessFlow != "" {
		wire = &recordBoundedConn{Conn: buffered}
	}
	secure := tls.Server(wire, config)
	if err = secure.HandshakeContext(e.ctx); err != nil {
		return nil, err
	}
	if s.vlessFlow != "" {
		return &directConn{Conn: secure, raw: raw}, nil
	}
	return secure, nil
}

func (e *Engine) realityFallback(raw net.Conn, target string) {
	ctx, cancel := context.WithTimeout(e.ctx, e.config.ConnectTimeout)
	defer cancel()
	remote, err := outboundDial(ctx, "tcp", target, e.config.ConnectTimeout)
	if err != nil {
		return
	}
	if !e.track(remote) {
		return
	}
	defer e.untrack(remote)
	defer remote.Close()
	e.relay(raw, remote)
}
