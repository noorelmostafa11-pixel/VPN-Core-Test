package nativego

// Go-native TLS/REALITY implementation is ported directly from the pinned
// tls-provider/main.go security implementation in this repository. There is
// no CGO, no C++ handshake, and no plaintext fallback. REALITY's authenticated
// certificate predicate is intentionally not replaced by ordinary TLS trust.

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
 "strings"
 "time"

 utls "github.com/refraction-networking/utls"
)

type nativeRealitySettings struct {
 PublicKey string
 ShortID string
 PQVerify string
 Pins []string
 Names []string
}
type nativeTLSError int
func (nativeTLSError)Error()string{return "nativego: TLS or REALITY authentication rejected"}

func nativeTLSProfile(name string) (utls.ClientHelloID, error) {
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

func nativeDecodeKey(text string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := encoding.DecodeString(text); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("key encoding")
}
func nativePrepareReality(u *utls.UConn, cfg *utls.Config, c nativeRealitySettings) error {
	public, err := nativeDecodeKey(c.PublicKey)
	if err != nil || len(public) != 32 {
		return errors.New("REALITY public key")
	}
	short, err := hex.DecodeString(c.ShortID)
	if err != nil || len(short) > 8 {
		return errors.New("REALITY short id")
	}
	var pq *mldsa.PublicKey
	if c.PQVerify != "" {
		encoded, err := nativeDecodeKey(c.PQVerify)
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
			return nativeTLSError(308)
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nativeTLSError(308)
		}
		mac := hmac.New(sha512.New, auth)
		_, _ = mac.Write(pub)
		if !hmac.Equal(mac.Sum(nil), cert.Signature) {
			return nativeTLSError(308)
		}
		if pq != nil {
			if len(cert.Extensions) == 0 || u.HandshakeState.ServerHello == nil {
				return nativeTLSError(308)
			}
			_, _ = mac.Write(u.HandshakeState.Hello.Raw)
			_, _ = mac.Write(u.HandshakeState.ServerHello.Raw)
			if mldsa.Verify(pq, mac.Sum(nil), cert.Extensions[0].Value, nil) != nil {
				return nativeTLSError(308)
			}
		}
		if len(c.Pins) > 0 {
			sum := sha256.Sum256(cert.Raw)
			matched := false
			for _, pin := range c.Pins {
				b, err := hex.DecodeString(pin)
				if err != nil || len(b) != 32 {
					return nativeTLSError(301)
				}
				matched = matched || hmac.Equal(sum[:], b)
			}
			if !matched {
				return nativeTLSError(308)
			}
		}
		if len(c.Names) > 0 {
			matched := false
			for _, name := range c.Names {
				matched = matched || cert.VerifyHostname(name) == nil
			}
			if !matched {
				return nativeTLSError(308)
			}
		}
		return nil
	}
	return nil
}

func nativeEnforceTLSVersions(u *utls.UConn, cfg *utls.Config, minimum uint16) error {
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

func nativePermittedCipher(id uint16) bool {
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


func nativeHandshake(ctx context.Context, conn net.Conn, n Node)(net.Conn,error){
 id,err:=nativeTLSProfile(n.Fingerprint)
 if err!=nil{return nil,err}
 cfg:=&utls.Config{ServerName:n.ServerName,MinVersion:utls.VersionTLS12,NextProtos:n.ALPN}
 minimum:=uint16(utls.VersionTLS12)
 if n.Security=="reality"{
  minimum=utls.VersionTLS13
  cfg.MinVersion=minimum
  cfg.SessionTicketsDisabled=true
 }
 u:=utls.UClient(conn,cfg,id)
 if err=u.BuildHandshakeState();err!=nil{return nil,err}
 if len(n.ALPN)>0 {
  for _,ext:=range u.Extensions {
   if a,ok:=ext.(*utls.ALPNExtension);ok{a.AlpnProtocols=n.ALPN}
  }
  if err=u.BuildHandshakeState();err!=nil{return nil,err}
 }
 if err=nativeEnforceTLSVersions(u,cfg,minimum);err!=nil{return nil,err}
 if n.Security=="reality" {
  opts:=nativeRealitySettings{PublicKey:n.PublicKey,ShortID:n.ShortID,PQVerify:n.PQVerify,Pins:n.Pins,Names:n.Names}
  if err=nativePrepareReality(u,cfg,opts);err!=nil{return nil,err}
 }
 if err=u.HandshakeContext(ctx);err!=nil{return nil,err}
 state:=u.ConnectionState()
 if state.Version<minimum||!nativePermittedCipher(state.CipherSuite){return nil,errors.New("nativego: unauthorized TLS version or cipher")}
 return u,nil
}
