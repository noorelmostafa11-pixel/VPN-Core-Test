// ShadowTLS wire design: ihciah/shadow-tls v0.2.25, MIT; see third_party.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

func parseShadowTLSURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "shadowtls", "raw", "none"
	u, err := url.Parse(uri)
	if err != nil || u.User == nil || (u.Path != "" && u.Path != "/") {
		return c, errors.New("SHADOWTLS_CONFIGURATION")
	}
	c.Password = u.User.Username()
	if p, ok := u.User.Password(); ok {
		c.Password += ":" + p
	}
	c.Server, c.Port = u.Hostname(), 443
	if u.Port() != "" {
		c.Port, err = number(u.Port(), 1, 65535)
		if err != nil {
			return c, err
		}
	}
	c.Options = map[string]string{}
	for k, v := range u.Query() {
		if len(v) != 1 {
			return c, errors.New("SHADOWTLS_CONFIGURATION")
		}
		c.Options[strings.ToLower(k)] = v[0]
	}
	c.Cipher = c.Options["method"]
	c.ServerName = option(c.Options, c.Server, "sni", "peer")
	c.Fingerprint = option(c.Options, "chrome", "fp", "fingerprint")
	if a := c.Options["alpn"]; a != "" {
		c.ALPN = strings.Split(a, ",")
	}
	c.InsecureRequested = truth(option(c.Options, "", "insecure", "allowinsecure"))
	return c, c.Validate()
}
func shadowVersion(c Config) int {
	if c.Options["version"] == "2" {
		return 2
	}
	return 3
}
func shadowFromSS(c Config) (Config, error) {
	if c.Transport != "raw" || c.Security != "none" || c.PluginMux || c.Header != "none" || len(c.Extra) != 0 || len(c.FinalMask) != 0 {
		return c, errors.New("SHADOWTLS_CONFIGURATION")
	}
	opts := map[string]string{"method": c.Cipher, "ss-password": c.Password}
	for k, v := range c.PluginOptions {
		switch k {
		case "password":
		case "host":
			opts["sni"] = v
		default:
			if !contains([]string{"version", "sni", "fp", "fingerprint", "uot", "alpn", "pinsha256", "pcs", "vcn"}, k) {
				return c, errors.New("SHADOWTLS_OPTION_UNSUPPORTED")
			}
			opts[k] = v
		}
	}
	for _, k := range []string{"pinsha256", "pcs", "vcn", "insecure", "allowinsecure"} {
		if v := c.Options[k]; v != "" {
			opts[k] = v
		}
	}
	c.Protocol, c.Password, c.Plugin, c.Options = "shadowtls", c.PluginOptions["password"], "", opts
	if a := opts["alpn"]; a != "" {
		c.ALPN = strings.Split(a, ",")
	}
	return c, nil
}
func shadowSSConfig(c Config) Config {
	c.Protocol, c.Transport, c.Security = "ss", "raw", "none"
	c.Password = c.Options["ss-password"]
	c.Plugin = ""
	c.PluginOptions = nil
	c.Options = map[string]string{}
	c.ECH = ""
	return c
}
func validateShadowTLS(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || len(c.Password) == 0 || len(c.Password) > 4096 || c.Transport != "raw" || c.Security != "none" || !hostValid(c.ServerName) {
		return errors.New("SHADOWTLS_CONFIGURATION")
	}
	if len(c.Options["ss-password"]) > 4096 || (c.Options["ss-password"] == "" && !contains([]string{"none", "plain"}, c.Cipher)) {
		return errors.New("SHADOWTLS_SS_PASSWORD_INVALID")
	}
	for k := range c.Options {
		if !contains([]string{"version", "method", "ss-password", "sni", "peer", "fp", "fingerprint", "alpn", "uot", "insecure", "allowinsecure", "pinsha256", "pcs", "vcn"}, k) {
			return errors.New("SHADOWTLS_OPTION_UNSUPPORTED")
		}
	}
	if v := option(c.Options, "3", "version"); v != "2" && v != "3" {
		return errors.New("SHADOWTLS_VERSION_UNSUPPORTED")
	}
	if shadowVersion(c) == 3 && contains([]string{"native", "unsafe"}, c.Fingerprint) {
		return errors.New("SHADOWTLS_FINGERPRINT_UNSUPPORTED")
	}
	if v := c.Options["uot"]; v != "" && v != "2" {
		return errors.New("SHADOWTLS_UOT_UNSUPPORTED")
	}
	if len(c.ALPN) > 8 {
		return errors.New("SHADOWTLS_CONFIGURATION")
	}
	for _, p := range c.ALPN {
		if len(p) == 0 || len(p) > 255 {
			return errors.New("SHADOWTLS_CONFIGURATION")
		}
	}
	if err := shadowSSConfig(c).Validate(); err != nil {
		return err
	}
	secure := c
	secure.Security = "tls"
	_, err := secure.tlsSettings()
	return err
}
func shadowMAC(password string, init ...[]byte) hash.Hash {
	m := hmac.New(sha1.New, []byte(password))
	for _, b := range init {
		m.Write(b)
	}
	return m
}
func shadowTag(m hash.Hash, body []byte, separator bool) []byte {
	m.Write(body)
	tag := m.Sum(nil)[:4]
	if separator {
		m.Write(tag)
	}
	return tag
}
func shadowRecord(kind byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0], out[1], out[2] = kind, 3, 3
	copy(out[3:5], word(len(body)))
	copy(out[5:], body)
	return out
}
func readShadowRecord(r io.Reader) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := getWord(h[:], 3)
	if h[1] != 3 || h[2] > 3 || n > 18436 {
		return nil, errors.New("SHADOWTLS_RECORD_INVALID")
	}
	b := make([]byte, 5+n)
	copy(b, h[:])
	_, err := io.ReadFull(r, b[5:])
	return b, err
}
func shadowRandom(frame []byte) []byte {
	if len(frame) < 43 || frame[0] != 22 || frame[5] != 2 {
		return nil
	}
	return append([]byte(nil), frame[11:43]...)
}
func shadowSignHello(hello []byte, password string) error {
	if len(hello) < 71 || hello[0] != 1 || hello[38] != 32 {
		return errors.New("SHADOWTLS_CLIENT_HELLO_INVALID")
	}
	copy(hello[39:67], randomBytes(28))
	clear(hello[67:71])
	m := shadowMAC(password)
	m.Write(hello)
	copy(hello[67:71], m.Sum(nil)[:4])
	return nil
}
func shadowVerifyHello(frame []byte, password string) bool {
	if len(frame) < 76 || frame[0] != 22 || frame[5] != 1 || frame[43] != 32 {
		return false
	}
	body := append([]byte(nil), frame[5:]...)
	tag := append([]byte(nil), body[67:71]...)
	clear(body[67:71])
	m := shadowMAC(password)
	m.Write(body)
	return hmac.Equal(tag, m.Sum(nil)[:4])
}

type shadowHandshakeConn struct {
	net.Conn
	version      int
	password     string
	challenge    hash.Hash
	serverRandom []byte
	serverMAC    hash.Hash
	xor          [32]byte
	authorized   bool
	pending      []byte
}

func (c *shadowHandshakeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		frame, err := readShadowRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		if c.version == 2 {
			c.challenge.Write(frame)
		} else {
			if sr := shadowRandom(frame); sr != nil {
				c.serverRandom = sr
				c.serverMAC = shadowMAC(c.password, sr)
				c.xor = sha256.Sum256(append([]byte(c.password), sr...))
			}
			if frame[0] == 23 && c.serverMAC != nil && len(frame) > 9 {
				tag := shadowTag(c.serverMAC, frame[9:], false)
				if hmac.Equal(tag, frame[5:9]) {
					c.authorized = true
					body := append([]byte(nil), frame[9:]...)
					for i := range body {
						body[i] ^= c.xor[i%32]
					}
					frame = shadowRecord(23, body)
				}
			}
		}
		c.pending = frame
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

type shadowConn struct {
	net.Conn
	version                      int
	readMAC, writeMAC, ignoreMAC hash.Hash
	initial, pending             []byte
	tls                          *utls.UConn
	challenge                    []byte
	readMu, writeMu              sync.Mutex
	closed                       bool // writeMu
}

func (c *shadowConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		if len(c.initial) > 0 {
			c.pending = c.initial
			c.initial = nil
			break
		}
		frame, err := readShadowRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		if frame[0] == 21 {
			return 0, io.EOF
		}
		if frame[0] != 23 {
			return 0, c.integrityFailure()
		}
		if c.version == 2 {
			if c.tls != nil {
				if c.tls.ProjectShadowTLSResidual(frame) {
					continue
				}
				c.tls = nil
			}
			c.pending = frame[5:]
			continue
		}
		if len(frame) < 9 {
			return 0, c.integrityFailure()
		}
		if c.ignoreMAC != nil {
			tag := shadowTag(c.ignoreMAC, frame[9:], false)
			if hmac.Equal(tag, frame[5:9]) {
				continue
			}
			c.ignoreMAC = nil
		}
		tag := shadowTag(c.readMAC, frame[9:], true)
		if !hmac.Equal(tag, frame[5:9]) {
			return 0, c.integrityFailure()
		}
		c.pending = frame[9:]
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *shadowConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(b) > 0 {
		n := len(b)
		if n > 16384 {
			n = 16384
		}
		body := b[:n]
		if c.version == 3 {
			tag := shadowTag(c.writeMAC, body, true)
			body = append(append([]byte(nil), tag...), body...)
		} else if c.challenge != nil {
			body = append(append([]byte(nil), c.challenge...), body...)
			c.challenge = nil
		}
		if err := writeAll(c.Conn, shadowRecord(23, body)); err != nil {
			c.closed = true
			c.Conn.Close()
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func (c *shadowConn) integrityFailure() error {
	c.writeMu.Lock()
	if !c.closed {
		c.Conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		writeAll(c.Conn, shadowRecord(21, []byte{2, 20}))
		c.closed = true
	}
	c.writeMu.Unlock()
	c.Conn.Close()
	return errors.New("SHADOWTLS_INTEGRITY_FAILED")
}
func (c *shadowConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

func openShadowTLS(ctx context.Context, c Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	raw, err := outboundDial(ctx, "tcp", net.JoinHostPort(c.Server, itoa(c.Port)), c.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	raw.SetDeadline(time.Now().Add(c.ConnectTimeout))
	h := &shadowHandshakeConn{Conn: raw, version: shadowVersion(c), password: c.Password, challenge: shadowMAC(c.Password)}
	secure := c
	secure.Security = "tls"
	settings, err := secure.tlsSettings()
	if err != nil {
		return nil, err
	}
	if h.version == 3 {
		settings.ShadowTLS = c.Password
	}
	u, _, err := configuredTLS(ctx, h, settings)
	if err != nil {
		return nil, err
	}
	result := &shadowConn{Conn: raw, version: h.version}
	if len(h.pending) != 0 {
		return nil, errors.New("SHADOWTLS_HANDSHAKE_REMAINDER")
	}
	if h.version == 3 {
		if u.ConnectionState().Version != utls.VersionTLS13 || !h.authorized || len(h.serverRandom) != 32 {
			// No user payload enters a connection that did not authenticate the server.
			u.Write([]byte("GET / HTTP/1.1\r\nHost: " + c.ServerName + "\r\nConnection: close\r\n\r\n"))
			return nil, errors.New("SHADOWTLS_AUTHENTICATION_FAILED")
		}
		result.writeMAC = shadowMAC(c.Password, h.serverRandom, []byte("C"))
		result.readMAC = shadowMAC(c.Password, h.serverRandom, []byte("S"))
		result.ignoreMAC = h.serverMAC
	} else {
		result.challenge = append([]byte(nil), h.challenge.Sum(nil)[:8]...)
		result.tls = u
	}
	raw.SetDeadline(time.Time{})
	success = true
	return result, nil
}
func dialShadowTLS(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	a, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	ss := newProtocol(shadowSSConfig(c), false)
	header, err := ss.open(a)
	if err != nil {
		return nil, err
	}
	conn, err := openShadowTLS(ctx, c)
	if err != nil {
		return nil, err
	}
	conn.SetWriteDeadline(time.Now().Add(c.ConnectTimeout))
	err = writeAll(conn, header)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &protocolConn{Conn: conn, p: ss}, nil
}
func dialShadowTLSPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if c.Options["uot"] != "2" {
		return nil, errors.New("SHADOWTLS_TCP_ONLY")
	}
	a, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	conn, err := dialShadowTLS(ctx, c, uotV2Host, 443)
	if err != nil {
		return nil, err
	}
	conn.SetWriteDeadline(time.Now().Add(c.ConnectTimeout))
	err = writeAll(conn, append([]byte{1}, a...))
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &uotPackets{Conn: conn, address: a, connect: true}, nil
}
