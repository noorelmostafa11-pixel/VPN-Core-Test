package core

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

	"errors"

	"net"
	"os"
	"strings"

	"time"

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
	ShadowTLS       string   `json:"-"`
}

type address string

func (a address) Network() string { return "memory" }
func (a address) String() string  { return string(a) }

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
		if err != nil {
			return nil, errors.New("TLS_CA_READ_FAILED")
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("TLS_CA_FORMAT_INVALID")
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
	if c.Security == "reality" || c.ECH != "" || c.Vision || c.LegacyXTLS != "" || c.ShadowTLS != "" {
		minimum = utls.VersionTLS13
	}
	if err = enforceTLSVersions(u, cfg, minimum); err != nil {
		return nil, "", providerError(302)
	}
	if c.ShadowTLS != "" {
		hello := u.HandshakeState.Hello
		if hello == nil {
			return nil, "", errors.New("SHADOWTLS_CLIENT_HELLO_INVALID")
		}
		if err = shadowSignHello(hello.Raw, c.ShadowTLS); err != nil {
			return nil, "", err
		}
		hello.SessionId = append([]byte(nil), hello.Raw[39:71]...)
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
