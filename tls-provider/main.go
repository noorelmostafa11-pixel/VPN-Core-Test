// Project-owned memory transport and C ABI around the pinned uTLS TLS library.
// This package implements no VPN engine, routing, SOCKS, or proxy protocol.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

const bufferLimit = 1048576

type settings struct {
	Security        string   `json:"security"`
	Fingerprint     string   `json:"fingerprint"`
	ServerName      string   `json:"server_name"`
	ALPN            []string `json:"alpn"`
	CAFile          string   `json:"ca_file"`
	CAPEM           string   `json:"ca_pem"`
	OnlyCustomRoots bool     `json:"only_custom_roots"`
	PublicKey       string   `json:"public_key"`
	ShortID         string   `json:"short_id"`
	PQVerify        string   `json:"pq_verify"`
	LegacyXTLS      string   `json:"legacy_xtls"`
	Vision          bool     `json:"vision"`
	ECH             string   `json:"ech"`
	Pins            []string `json:"pins"`
	Names           []string `json:"names"`
	TimeoutMS       int      `json:"timeout_ms"`
}

type memoryConn struct {
	mu                          sync.Mutex
	changed                     *sync.Cond
	incoming, outgoing          []byte
	dead                        bool
	waiting                     bool
	readDeadline, writeDeadline time.Time
}

func newMemoryConn() *memoryConn { c := &memoryConn{}; c.changed = sync.NewCond(&c.mu); return c }
func (c *memoryConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.incoming) == 0 && !c.dead {
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.waiting = true
		c.changed.Broadcast()
		c.changed.Wait()
	}
	c.waiting = false
	if len(c.incoming) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.incoming)
	copy(c.incoming, c.incoming[n:])
	c.incoming = c.incoming[:len(c.incoming)-n]
	c.changed.Broadcast()
	return n, nil
}
func (c *memoryConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.outgoing)+len(b) > bufferLimit && !c.dead {
		c.changed.Wait()
	}
	if c.dead {
		return 0, net.ErrClosed
	}
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	c.outgoing = append(c.outgoing, b...)
	c.changed.Broadcast()
	return len(b), nil
}
func (c *memoryConn) Close() error {
	c.mu.Lock()
	c.dead = true
	c.changed.Broadcast()
	c.mu.Unlock()
	return nil
}

type address string

func (a address) Network() string        { return "memory" }
func (a address) String() string         { return string(a) }
func (*memoryConn) LocalAddr() net.Addr  { return address("project-client") }
func (*memoryConn) RemoteAddr() net.Addr { return address("project-peer") }
func (c *memoryConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *memoryConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.changed.Broadcast()
	c.mu.Unlock()
	if !t.IsZero() {
		time.AfterFunc(time.Until(t), func() { c.mu.Lock(); c.changed.Broadcast(); c.mu.Unlock() })
	}
	return nil
}
func (c *memoryConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.changed.Broadcast()
	c.mu.Unlock()
	return nil
}

type session struct {
	conn   *memoryConn
	tls    *utls.UConn
	stream interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		CloseWrite() error
	}
	mu            sync.Mutex
	plain         []byte
	state         int // 0 handshake, 1 ready, 2 authenticated close, -1 failed
	code          int
	version       uint16
	alpn, profile string
	cancel        context.CancelFunc
}

var sessions sync.Map
var nextID atomic.Uint64

func find(id C.uint64_t) *session {
	v, ok := sessions.Load(uint64(id))
	if !ok {
		return nil
	}
	return v.(*session)
}
func (s *session) fail(code int) {
	s.mu.Lock()
	s.state = -1
	s.code = code
	s.mu.Unlock()
	_ = s.conn.Close()
}

func profile(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "360":
		return utls.Hello360_11_0, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "unsafe", "native":
		return utls.HelloGolang, nil
	case "randomized", "randomizednoalpn":
		id := utls.HelloRandomizedALPN
		if strings.EqualFold(strings.TrimSpace(name), "randomizednoalpn") {
			id = utls.HelloRandomizedNoALPN
		}
		// These presets must remain usable with TLS 1.3-only endpoints,
		// including REALITY, while still offering permitted TLS 1.2.
		weights := utls.DefaultWeights
		weights.TLSVersMax_Set_VersionTLS13 = 1
		weights.FirstKeyShare_Set_CurveP256 = 0
		id.Weights = &weights
		return id, nil
	case "random":
		ids := []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloIOS_Auto, utls.HelloEdge_Auto, utls.HelloQQ_Auto}
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return utls.ClientHelloID{}, err
		}
		return ids[int(b[0])%len(ids)], nil
	default:
		return utls.ClientHelloID{}, errors.New("unknown TLS profile")
	}
}

func decodeKey(text string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := encoding.DecodeString(text); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("key encoding")
}
func verifyConfigured(c settings, roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return providerError(314)
		}
		certs := make([]*x509.Certificate, 0, len(raw))
		for _, b := range raw {
			cert, err := x509.ParseCertificate(b)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		trusted := roots
		if len(c.Pins) > 0 {
			trusted = x509.NewCertPool()
			matched := false
			for _, cert := range certs {
				hash := sha256.Sum256(cert.Raw)
				for _, p := range c.Pins {
					pin, err := hex.DecodeString(p)
					if err != nil || len(pin) != 32 {
						return providerError(301)
					}
					if hmac.Equal(hash[:], pin) {
						trusted.AddCert(cert)
						matched = true
					}
				}
			}
			if !matched {
				return providerError(315)
			}
		}
		names := c.Names
		if len(names) == 0 {
			names = []string{c.ServerName}
		}
		var verifyErr error
		for _, name := range names {
			_, err := certs[0].Verify(x509.VerifyOptions{DNSName: name, Roots: trusted, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err == nil {
				return nil
			}
			if verifyErr == nil {
				verifyErr = err
			}
		}
		return providerError(tlsErrorCode(verifyErr, 314))
	}
}

func prepareReality(u *utls.UConn, cfg *utls.Config, c settings) error {
	public, err := decodeKey(c.PublicKey)
	if err != nil || len(public) != 32 {
		return errors.New("REALITY public key")
	}
	short, err := hex.DecodeString(c.ShortID)
	if err != nil || len(short) > 8 {
		return errors.New("REALITY short id")
	}
	var pq *mldsa.PublicKey
	if c.PQVerify != "" {
		encoded, err := decodeKey(c.PQVerify)
		if err != nil {
			return err
		}
		pq, err = mldsa.NewPublicKey(mldsa.MLDSA65(), encoded)
		if err != nil {
			return err
		}
	}
	if err = u.BuildHandshakeState(); err != nil {
		return err
	}
	hello := u.HandshakeState.Hello
	shares := u.HandshakeState.State13.KeyShareKeys
	if hello == nil || len(hello.Random) != 32 || len(hello.Raw) < 71 || shares == nil {
		return errors.New("REALITY hello state")
	}
	private := shares.Ecdhe
	if private == nil || private.Curve() != ecdh.X25519() {
		private = shares.MlkemEcdhe
	}
	if private == nil || private.Curve() != ecdh.X25519() {
		return errors.New("REALITY X25519 key share required")
	}
	key, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return err
	}
	shared, err := private.ECDH(key)
	if err != nil {
		return err
	}
	auth, err := hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		return err
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:71], hello.SessionId)
	payload := make([]byte, 16)
	// Protocol compatibility version, independent of the core release number.
	payload[0], payload[1], payload[2] = 26, 9, 22
	binary.BigEndian.PutUint32(payload[4:8], uint32(time.Now().Unix()))
	copy(payload[8:], short)
	block, err := aes.NewCipher(auth)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	encrypted := aead.Seal(nil, hello.Random[20:], payload, hello.Raw)
	copy(hello.SessionId, encrypted)
	copy(hello.Raw[39:71], encrypted)
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return providerError(308)
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return providerError(308)
		}
		mac := hmac.New(sha512.New, auth)
		_, _ = mac.Write(pub)
		if !hmac.Equal(mac.Sum(nil), cert.Signature) {
			return providerError(308)
		}
		if pq != nil {
			if len(cert.Extensions) == 0 || u.HandshakeState.ServerHello == nil {
				return providerError(308)
			}
			_, _ = mac.Write(u.HandshakeState.Hello.Raw)
			_, _ = mac.Write(u.HandshakeState.ServerHello.Raw)
			if mldsa.Verify(pq, mac.Sum(nil), cert.Extensions[0].Value, nil) != nil {
				return providerError(308)
			}
		}
		if len(c.Pins) > 0 {
			sum := sha256.Sum256(cert.Raw)
			matched := false
			for _, pin := range c.Pins {
				b, err := hex.DecodeString(pin)
				if err != nil || len(b) != 32 {
					return providerError(301)
				}
				matched = matched || hmac.Equal(sum[:], b)
			}
			if !matched {
				return providerError(308)
			}
		}
		if len(c.Names) > 0 {
			matched := false
			for _, name := range c.Names {
				matched = matched || cert.VerifyHostname(name) == nil
			}
			if !matched {
				return providerError(308)
			}
		}
		return nil
	}
	return nil
}

// A profile may set older protocol bounds while constructing ClientHello.
// Keep its extension ordering, but never permit a downgrade below policy.
func enforceTLSVersions(u *utls.UConn, cfg *utls.Config, minimum uint16) error {
	cfg.MinVersion = minimum
	if cfg.MaxVersion != 0 && cfg.MaxVersion < minimum {
		return errors.New("profile has no permitted TLS version")
	}
	for _, ext := range u.Extensions {
		if versions, ok := ext.(*utls.SupportedVersionsExtension); ok {
			filtered := make([]uint16, 0, len(versions.Versions))
			for _, v := range versions.Versions {
				if v >= minimum || v&0x0f0f == 0x0a0a {
					filtered = append(filtered, v)
				}
			}
			versions.Versions = filtered
		}
	}
	// Randomized templates independently choose the hybrid group and share.
	// Every offered non-GREASE share must also be in supported_groups.
	var curves *utls.SupportedCurvesExtension
	for _, ext := range u.Extensions {
		if c, ok := ext.(*utls.SupportedCurvesExtension); ok {
			curves = c
		}
	}
	if curves != nil {
		for _, ext := range u.Extensions {
			if keys, ok := ext.(*utls.KeyShareExtension); ok {
				for _, key := range keys.KeyShares {
					if uint16(key.Group)&0x0f0f == 0x0a0a {
						continue
					}
					found := false
					for _, curve := range curves.Curves {
						found = found || curve == key.Group
					}
					if !found {
						curves.Curves = append(curves.Curves, key.Group)
					}
				}
			}
		}
	}
	return u.BuildHandshakeState()
}

func permittedCipher(id uint16) bool {
	switch id {
	case utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

type providerError int

func (e providerError) Error() string { return "provider operation failed" }
func tlsRoots(c settings) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || c.OnlyCustomRoots {
		roots = x509.NewCertPool()
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, providerError(301)
		}
	}
	if c.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, providerError(301)
	}
	return roots, nil
}
func configuredTLS(ctx context.Context, conn net.Conn, c settings) (*utls.UConn, string, error) {
	roots, err := tlsRoots(c)
	if err != nil {
		return nil, "", err
	}
	cfg := &utls.Config{ServerName: c.ServerName, RootCAs: roots, MinVersion: utls.VersionTLS12, NextProtos: c.ALPN}
	if len(c.Pins) > 0 || len(c.Names) > 0 {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verifyConfigured(c, roots)
	}
	id, err := profile(c.Fingerprint)
	if err != nil {
		return nil, "", providerError(302)
	}
	if c.ECH != "" {
		config, err := resolveECH(ctx, c.ECH, c.ServerName, roots)
		if err != nil {
			return nil, "", err
		}
		cfg.MinVersion = utls.VersionTLS13
		cfg.EncryptedClientHelloConfigList = config
	}
	if c.Security == "reality" {
		cfg.MinVersion = utls.VersionTLS13
		cfg.SessionTicketsDisabled = true
	}
	u := utls.UClient(conn, cfg, id)
	// ALPN controls the actual carrier, including the ECH inner connection.
	if err = u.BuildHandshakeState(); err != nil {
		return nil, "", providerError(302)
	}
	if len(c.ALPN) > 0 {
		for _, ext := range u.Extensions {
			if a, ok := ext.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = c.ALPN
			}
		}
		if err = u.BuildHandshakeState(); err != nil {
			return nil, "", providerError(302)
		}
	}
	minimum := uint16(utls.VersionTLS12)
	if c.Security == "reality" || c.ECH != "" || c.Vision || c.LegacyXTLS != "" {
		minimum = utls.VersionTLS13
	}
	if err = enforceTLSVersions(u, cfg, minimum); err != nil {
		return nil, "", providerError(302)
	}
	if c.Security == "reality" {
		if err = prepareReality(u, cfg, c); err != nil {
			return nil, "", providerError(308)
		}
	}
	if err = u.HandshakeContext(ctx); err != nil {
		return nil, "", providerError(tlsErrorCode(err, 303))
	}
	state := u.ConnectionState()
	if state.Version < minimum || !permittedCipher(state.CipherSuite) {
		return nil, "", providerError(310)
	}
	return u, id.Str(), nil
}

func (s *session) run(c settings) {
	ctx, cancel := context.WithTimeout(providerContext(), time.Duration(c.TimeoutMS)*time.Millisecond)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	defer cancel()
	u, selected, err := configuredTLS(ctx, s.conn, c)
	if err != nil {
		code := 303
		var pe providerError
		if errors.As(err, &pe) {
			code = int(pe)
		}
		s.fail(code)
		return
	}
	state := u.ConnectionState()
	s.mu.Lock()
	s.tls = u
	s.stream = u
	if c.LegacyXTLS != "" {
		s.stream = &legacyXTLS{Conn: u, tls: u, raw: s.conn, direct: c.LegacyXTLS != "xtls-rprx-origin"}
	}
	s.profile = selected
	s.state = 1
	s.version = state.Version
	s.alpn = state.NegotiatedProtocol
	s.mu.Unlock()
	// Handshake deadline ends here. Relay controls its own idle deadline.
	_ = s.conn.SetDeadline(time.Time{})
	buffer := make([]byte, 16384)
	for {
		n, err := s.stream.Read(buffer)
		if n > 0 {
			s.mu.Lock()
			if len(s.plain)+n > bufferLimit {
				s.mu.Unlock()
				s.fail(307)
				return
			}
			s.plain = append(s.plain, buffer[:n]...)
			s.mu.Unlock()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.mu.Lock()
				s.state = 2
				s.mu.Unlock()
			} else {
				s.fail(tlsErrorCode(err, 304))
			}
			return
		}
	}
}

//export vpn_tls_new
func vpn_tls_new(data *C.char, length C.int) C.uint64_t {
	if length <= 0 || length > 131072 {
		return 0
	}
	var c settings
	if json.Unmarshal(C.GoBytes(unsafe.Pointer(data), length), &c) != nil {
		return 0
	}
	if c.TimeoutMS < 1000 || c.TimeoutMS > 120000 {
		return 0
	}
	s := &session{conn: newMemoryConn()}
	id := nextID.Add(1)
	sessions.Store(id, s)
	go s.run(c)
	return C.uint64_t(id)
}

//export vpn_tls_feed
func vpn_tls_feed(id C.uint64_t, data *C.char, length C.int) C.int {
	s := find(id)
	if s == nil || length < 0 || length > 65536 {
		return -1
	}
	bytes := C.GoBytes(unsafe.Pointer(data), length)
	c := s.conn
	c.mu.Lock()
	if c.dead || len(c.incoming)+len(bytes) > bufferLimit {
		c.mu.Unlock()
		return -1
	}
	c.waiting = false
	c.incoming = append(c.incoming, bytes...)
	c.changed.Broadcast()
	c.mu.Unlock()
	// Let a complete TLS record reach Read or the next memory read boundary.
	// Partial TLS input returns promptly; C++ retains socket/event ownership.
	until := time.Now().Add(5 * time.Millisecond)
	for time.Now().Before(until) {
		c.mu.Lock()
		done := c.waiting && len(c.incoming) == 0
		c.mu.Unlock()
		s.mu.Lock()
		end := s.state < 0
		s.mu.Unlock()
		if done || end {
			break
		}
		time.Sleep(100 * time.Microsecond)
	}
	return length
}

//export vpn_tls_write
func vpn_tls_write(id C.uint64_t, data *C.char, length C.int) C.int {
	s := find(id)
	if s == nil || length < 0 || length > 65536 {
		return -1
	}
	s.mu.Lock()
	u, state := s.stream, s.state
	s.mu.Unlock()
	if u == nil || state != 1 {
		return -1
	}
	n, err := u.Write(C.GoBytes(unsafe.Pointer(data), length))
	if err != nil {
		s.fail(tlsErrorCode(err, 305))
		return -1
	}
	return C.int(n)
}

//export vpn_tls_read
func vpn_tls_read(id C.uint64_t, kind C.int, buffer *C.char, capacity C.int) C.int {
	s := find(id)
	if s == nil || capacity < 0 || capacity > bufferLimit {
		return -1
	}
	destination := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity))
	if kind == 0 {
		c := s.conn
		c.mu.Lock()
		n := copy(destination, c.outgoing)
		copy(c.outgoing, c.outgoing[n:])
		c.outgoing = c.outgoing[:len(c.outgoing)-n]
		c.changed.Broadcast()
		c.mu.Unlock()
		return C.int(n)
	}
	s.mu.Lock()
	n := copy(destination, s.plain)
	copy(s.plain, s.plain[n:])
	s.plain = s.plain[:len(s.plain)-n]
	s.mu.Unlock()
	return C.int(n)
}

//export vpn_tls_state
func vpn_tls_state(id C.uint64_t) C.int {
	s := find(id)
	if s == nil {
		return -1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state < 0 {
		return C.int(-s.code)
	}
	return C.int(s.state)
}

//export vpn_tls_ready_input
func vpn_tls_ready_input(id C.uint64_t) C.int {
	s := find(id)
	if s == nil {
		return 0
	}
	c := s.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.waiting && len(c.incoming) == 0 {
		return 1
	}
	return 0
}

//export vpn_tls_info
func vpn_tls_info(id C.uint64_t, buffer *C.char, capacity C.int) C.int {
	s := find(id)
	if s == nil || capacity < 0 || capacity > 8192 {
		return -1
	}
	s.mu.Lock()
	b, _ := json.Marshal(map[string]any{"version": s.version, "alpn": s.alpn, "profile": s.profile})
	s.mu.Unlock()
	if len(b) > int(capacity) {
		return -1
	}
	return C.int(copy(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity)), b))
}

//export vpn_tls_shutdown
func vpn_tls_shutdown(id C.uint64_t) C.int {
	s := find(id)
	if s == nil {
		return -1
	}
	s.mu.Lock()
	u := s.stream
	s.mu.Unlock()
	if u == nil {
		return -1
	}
	if u.CloseWrite() != nil {
		return -1
	}
	return 0
}

//export vpn_tls_free
func vpn_tls_free(id C.uint64_t) {
	s := find(id)
	if s == nil {
		return
	}
	sessions.Delete(uint64(id))
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = s.conn.Close()
}

func main() {}
