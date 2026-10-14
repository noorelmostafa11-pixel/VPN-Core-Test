// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
package core

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config keeps the original URI and options intact. Credentials are never logged.
type Config struct {
	Protocol, Server, Security, Transport, Cipher, Password, PasswordHash       string
	Flow, Encryption, Fingerprint, Path, Host, Service, Authority, Mode, Header string
	ServerName, PublicKey, ShortID, ECH, CAFile, CAPEM, ReadyFile               string
	PluginCAFile                                                                string
	Plugin, PluginMode, EarlyHeader                                             string
	UUID                                                                        [16]byte
	Port, ListenPort, AlterID, EarlyData, MaxConnections                        int
	ConnectTimeout, IdleTimeout, UDPTimeout                                     time.Duration
	ALPN                                                                        []string
	Options, PluginOptions                                                      map[string]string
	Extra, FinalMask                                                            json.RawMessage
	OriginalURI                                                                 string
	Username                                                                    string
	Routing                                                                     *RouterConfig
	Compatibility                                                               []string
	PluginMux, OnlyCustomRoots, InsecureRequested, InvalidPathED                bool
	Sniffing, NativeDNS, PreferIPv4, PreferTCP                                  bool
}

func defaults() Config {
	return Config{Path: "/", Header: "none", Encryption: "none", EarlyHeader: "Sec-WebSocket-Protocol", ListenPort: 1080, MaxConnections: 128, ConnectTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, Sniffing: true, NativeDNS: true, PreferIPv4: true}
}
func option(m map[string]string, fallback string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return fallback
}
func truth(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
func decode(s string) string {
	hexDigit := func(b byte) int {
		switch {
		case b >= '0' && b <= '9':
			return int(b - '0')
		case b >= 'a' && b <= 'f':
			return int(b-'a') + 10
		case b >= 'A' && b <= 'F':
			return int(b-'A') + 10
		}
		return -1
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			a, b := hexDigit(s[i+1]), hexDigit(s[i+2])
			if a >= 0 && b >= 0 {
				out.WriteByte(byte(a*16 + b))
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}
func decode64(s string) ([]byte, error) {
	s = decode(s)
	var out []byte
	var bits uint32
	var n uint
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, ch := range s {
		if ch == '=' {
			break
		}
		if ch == '-' {
			ch = '+'
		}
		if ch == '_' {
			ch = '/'
		}
		p := strings.IndexRune(alphabet, ch)
		if p < 0 {
			continue
		}
		bits = (bits << 6) | uint32(p)
		n += 6
		if n >= 8 {
			n -= 8
			out = append(out, byte(bits>>n))
		}
	}
	return out, nil
}
func query(s string) (map[string]string, map[string]string) {
	q, raw := map[string]string{}, map[string]string{}
	for _, p := range strings.Split(s, "&") {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(decode(k))
		if _, ok := q[k]; !ok {
			q[k] = decode(v)
			raw[k] = v
		}
	}
	return q, raw
}
func number(s string, lo, hi int) (int, error) {
	n, e := strconv.Atoi(s)
	if e != nil || n < lo || n > hi {
		return 0, fmt.Errorf("PARSE_INVALID: integer outside %d..%d", lo, hi)
	}
	return n, nil
}
func transport(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tcp", "raw":
		return "raw"
	case "mkcp", "kcp":
		return "kcp"
	case "http", "h2", "http2":
		return "http"
	case "ws", "websocket":
		return "websocket"
	case "gun", "grpc":
		return "grpc"
	case "splithttp", "xhttp":
		return "xhttp"
	case "http-upgrade", "httpupgrade":
		return "httpupgrade"
	}
	return strings.TrimSpace(s)
}
func security(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "off", "none":
		return "none"
	case "1", "true", "on", "tls":
		return "tls"
	case "reality":
		return "reality"
	case "xtls":
		return "xtls"
	}
	return strings.TrimSpace(s)
}
func hostValid(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if c <= 32 || c >= 127 || strings.ContainsRune("/\\?#@", c) {
			return false
		}
	}
	return true
}
func uuidBytes(s string) ([16]byte, error) {
	var id [16]byte
	if len(s) > 0 && len(s) <= 30 {
		h := sha1.Sum(append(make([]byte, 16), s...))
		copy(id[:], h[:16])
		id[6] = (id[6] & 15) | 0x50
		id[8] = (id[8] & 63) | 0x80
		return id, nil
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if e != nil || len(b) != 16 {
		return id, errors.New("PARSE_INVALID: invalid UUID")
	}
	copy(id[:], b)
	return id, nil
}
func rawJSON(s, raw string) json.RawMessage {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if json.Valid([]byte(s)) {
		return []byte(s)
	}
	v := decode(strings.ReplaceAll(raw, "+", " "))
	if strings.Contains(raw, "+") && json.Valid([]byte(v)) && strings.HasPrefix(strings.TrimSpace(v), "{") {
		return []byte(v)
	}
	b, _ := json.Marshal(s)
	return b
}
func tagged(s string) string {
	i := strings.IndexByte(s, '#')
	if i < 1 || i+1 == len(s) {
		return ""
	}
	base := strings.ToLower(strings.TrimSpace(s[:i]))
	switch base {
	case "ws", "websocket":
		return "websocket"
	case "grpc", "gun":
		return "grpc"
	}
	return ""
}

func ParseURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	fail := func(e error) (Config, error) { return c, e }
	if len(uri) > 65536 {
		return fail(errors.New("PARSE_INVALID: URI too large"))
	}
	proto, body, ok := strings.Cut(uri, "://")
	c.Protocol = strings.ToLower(proto)
	if ok && (c.Protocol == "hysteria" || c.Protocol == "hysteria1") {
		return parseHysteria1URI(uri)
	}
	if ok && c.Protocol == "shadowtls" {
		return parseShadowTLSURI(uri)
	}
	if ok && c.Protocol == "tuic" {
		return parseTUICURI(uri)
	}
	if ok && c.Protocol == "anytls" {
		return parseAnyTLSURI(uri)
	}
	if ok && (c.Protocol == "wireguard" || c.Protocol == "wg") {
		return parseWireGuardURI(uri)
	}
	if ok && c.Protocol == "ssh" {
		return parseSSHURI(uri)
	}
	if ok && (c.Protocol == "hysteria2" || c.Protocol == "hy2") {
		return parseHysteriaURI(uri)
	}
	if ok && contains([]string{"http", "https", "socks", "socks4", "socks4a", "socks5", "socks5h", "direct", "block"}, c.Protocol) {
		return parseProxyURI(uri)
	}
	if !ok || !contains([]string{"vless", "vmess", "trojan", "ss"}, c.Protocol) {
		return fail(errors.New("PARSE_INVALID: unknown scheme"))
	}
	body = strings.SplitN(body, "#", 2)[0]
	q, raw := map[string]string{}, map[string]string{}
	legacy := c.Protocol == "vmess" && !strings.Contains(body, "@")
	if legacy {
		b, e := decode64(body)
		if e != nil {
			return fail(e)
		}
		var m map[string]json.RawMessage
		if e = json.Unmarshal(b, &m); e != nil || m == nil {
			return fail(errors.New("PARSE_INVALID: VMess JSON object"))
		}
		for k, v := range m {
			var s string
			if json.Unmarshal(v, &s) != nil {
				if string(v) != "null" {
					s = string(v)
				}
			}
			q[strings.ToLower(k)] = s
		}
		if v, ok := m["alpn"]; ok && len(v) > 0 && v[0] == '[' {
			var a []string
			if json.Unmarshal(v, &a) == nil {
				q["alpn"] = strings.Join(a, ",")
			}
		}
		c.Server = option(q, "", "add", "address")
		c.Port, e = number(option(q, "", "port"), 1, 65535)
		if e != nil {
			return fail(e)
		}
		c.UUID, e = uuidBytes(option(q, "", "id"))
		if e != nil {
			return fail(e)
		}
		c.Transport = transport(option(q, "tcp", "net", "network"))
		c.Security = security(option(q, "", "tls"))
		if c.Security == "none" && contains([]string{"tls", "reality"}, strings.ToLower(q["security"])) {
			c.Security = security(q["security"])
		}
		c.Cipher = option(q, "auto", "scy", "cipher")
		if _, ok := q["scy"]; !ok {
			if _, ok := q["cipher"]; !ok && !contains([]string{"", "none", "tls", "reality"}, q["security"]) {
				c.Cipher = q["security"]
			}
		}
	} else {
		if b, s, ok := strings.Cut(body, "?"); ok {
			body = b
			q, raw = query(s)
		}
		at := strings.LastIndexByte(body, '@')
		auth, hp := "", ""
		if c.Protocol == "ss" && at < 0 {
			b, e := decode64(body)
			if e != nil {
				return fail(e)
			}
			body = string(b)
			at = strings.LastIndexByte(body, '@')
		}
		if at < 1 {
			return fail(errors.New("PARSE_INVALID: missing credential"))
		}
		auth, hp = body[:at], strings.SplitN(body[at+1:], "/", 2)[0]
		h, p, e := net.SplitHostPort(hp)
		if e != nil {
			return fail(errors.New("PARSE_INVALID: endpoint requires host and port"))
		}
		c.Server = h
		c.Port, e = number(p, 1, 65535)
		if e != nil {
			return fail(e)
		}
		if c.Protocol == "ss" {
			auth = decode(auth)
			if !strings.Contains(auth, ":") {
				b, e := decode64(auth)
				if e != nil {
					return fail(e)
				}
				auth = string(b)
			}
			c.Cipher, c.Password, ok = strings.Cut(auth, ":")
			c.Cipher = strings.TrimSpace(c.Cipher)
			if !ok || c.Password == "" {
				return fail(errors.New("PARSE_INVALID: Shadowsocks credential"))
			}
		} else {
			auth = decode(strings.SplitN(auth, ":", 2)[0])
			if auth == "" {
				return fail(errors.New("PARSE_INVALID: empty credential"))
			}
			if c.Protocol == "trojan" {
				c.Password = auth
				h := sha256.Sum224([]byte(auth))
				c.PasswordHash = hex.EncodeToString(h[:])
			} else {
				c.UUID, e = uuidBytes(strings.TrimSpace(auth))
				if e != nil {
					return fail(e)
				}
			}
		}
		defaultSec := "none"
		if c.Protocol == "trojan" {
			defaultSec = "tls"
		}
		c.Security = security(option(q, defaultSec, "security", "tls"))
		c.Options = map[string]string{}
		for k, v := range q {
			c.Options[k] = v
		}
		if c.Protocol == "vless" && c.Security == "reality" {
			explicit := false
			for _, k := range []string{"pbk", "password", "publickey", "public-key"} {
				if _, ok := q[k]; ok {
					explicit = true
				}
			}
			aliased := false
			if !explicit {
				for k, v := range c.Options {
					key := strings.TrimLeft(k, ";")
					if key != k && contains([]string{"pbk", "password", "publickey", "public-key"}, key) && v != "" {
						aliased = true
					}
				}
			}
			if aliased {
				for k, v := range c.Options {
					key := strings.TrimLeft(k, ";")
					if key != k {
						if _, ok := q[key]; !ok {
							q[key] = v
							raw[key] = raw[k]
						}
					}
				}
				c.Compatibility = append(c.Compatibility, "REALITY_SEMICOLON_FIELD_ALIASES")
			}
		}

		c.Transport = transport(option(q, "tcp", "type", "network", "net"))
		if truth(q["ws"]) && option(q, "", "type", "network", "net") == "" {
			c.Transport = "websocket"
		}
		for _, keys := range [][]string{{"type", "network", "net"}, {"security", "tls"}} {
			v := option(raw, "", keys...)
			if strings.Contains(v, "+") {
				s := decode(strings.ReplaceAll(v, "+", " "))
				if keys[0] == "type" {
					t := transport(s)
					if contains([]string{"raw", "websocket", "http", "grpc", "xhttp", "httpupgrade", "kcp", "quic"}, t) {
						c.Transport = t
					}
				} else {
					t := security(s)
					if contains([]string{"none", "tls", "reality", "xtls"}, t) {
						c.Security = t
					}
				}
			}
		}
		if c.Protocol == "vmess" {
			c.Cipher = option(q, "auto", "encryption")
		}
	}
	if !hostValid(c.Server) {
		return fail(errors.New("PARSE_INVALID: invalid hostname"))
	}
	if c.Options == nil {
		c.Options = map[string]string{}
		for k, v := range q {
			c.Options[k] = v
		}
	}
	c.Flow = option(q, "", "flow")
	if c.Flow == "none" {
		c.Flow = ""
	}
	c.Encryption = option(q, "none", "encryption")
	if c.Encryption == "" {
		c.Encryption = "none"
	}
	c.Fingerprint = option(q, "", "fp", "fingerprint", "client-fingerprint")
	c.Path = option(q, "/", "path", "wspath")
	c.Host = option(q, "", "host", "authority")
	c.Authority = option(q, c.Host, "authority")
	c.Mode = q["mode"]
	c.Header = option(q, "none", "headertype", "header-type")
	if legacy {
		c.Header = option(q, "none", "type", "headertype")
	}
	if c.Protocol == "vless" && (strings.HasPrefix(strings.ToLower(c.Encryption), "none=") || strings.HasPrefix(strings.ToLower(c.Encryption), "none@") || strings.HasPrefix(strings.ToLower(c.Encryption), "none¬e=")) {
		c.Encryption = "none"
		c.Compatibility = append(c.Compatibility, "VLESS_NONE_SUFFIX")
	}

	if c.Protocol == "vless" && c.Security == "reality" && strings.HasPrefix(strings.ToLower(c.Transport), "tcp#") {
		c.Transport = "raw"
		c.Compatibility = append(c.Compatibility, "REALITY_TCP_FRAGMENT_SUFFIX")
	}
	if t := tagged(c.Transport); t != "" {
		c.Transport = t
		c.Compatibility = append(c.Compatibility, "TRANSPORT_ENCODED_TAG_SUFFIX")
	}
	if c.Protocol == "vless" && c.Flow == "xtls-rprx-vision-udp443-udp443" {
		c.Flow = "xtls-rprx-vision-udp443"
		c.Compatibility = append(c.Compatibility, "VISION_DUPLICATE_UDP443_SUFFIX")
	}
	if legacy && c.Transport == "quic" {
		if option(q, "", "quicsecurity", "quic-security") == "" {
			c.Options["quicsecurity"] = q["host"]
		}
		if option(q, "", "quickey", "quic-key", "key") == "" {
			c.Options["quickey"] = q["path"]
		}
	}
	c.Service = option(q, strings.TrimLeft(c.Path, "/"), "servicename", "service-name", "grpc-service-name", "service_name")
	c.ServerName = option(q, c.Server, "sni", "servername", "server-name", "peer")
	if c.ServerName == "" {
		c.ServerName = c.Server
	}
	c.PublicKey = option(q, "", "pbk", "password", "publickey", "public-key")
	c.ShortID = option(q, "", "sid", "shortid", "short-id")
	c.ECH = option(q, "", "ech", "echconfiglist", "ech-config-list")
	c.InsecureRequested = truth(option(q, "", "allowinsecure", "allow_insecure", "allow-insecure", "insecure", "skip-cert-verify", "skip_cert_verify"))
	for _, v := range strings.Split(q["alpn"], ",") {
		v = strings.TrimSpace(v)
		if len(v) > 255 {
			return fail(errors.New("PARSE_INVALID: ALPN length"))
		}
		if v != "" {
			c.ALPN = append(c.ALPN, v)
		}
	}
	if c.Transport == "xhttp" && c.Security != "reality" && len(c.ALPN) == 1 {
		s := c.ALPN[0]
		var a []string
		for s != "" {
			found := false
			for _, p := range []string{"http/1.1", "h2", "h3"} {
				if strings.HasPrefix(s, p) {
					a = append(a, p)
					s = s[len(p):]
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		if s == "" && len(a) > 1 {
			c.ALPN = a
			c.Compatibility = append(c.Compatibility, "ALPN_CONCATENATED_PROTOCOLS")
		}
	}
	c.Extra = rawJSON(q["extra"], raw["extra"])
	c.FinalMask = rawJSON(option(q, "", "fm", "finalmask"), option(raw, "", "fm", "finalmask"))
	if c.Transport == "xhttp" && len(c.Extra) > 0 && c.Extra[0] == '"' {
		var s string
		json.Unmarshal(c.Extra, &s)
		if extra, strategy := compatibleExtra(s); strategy != "" {
			c.Extra = extra
			c.Compatibility = append(c.Compatibility, strategy)
		}
	}
	if c.Protocol == "vmess" {
		s := option(q, "0", "aid", "alterid")
		if s == "" {
			s = "0"
		}
		var e error
		c.AlterID, e = number(s, 0, 65535)
		if e != nil {
			return fail(e)
		}
	}
	if e := c.parsePlugin(); e != nil {
		return fail(e)
	}
	if c.Transport == "http" && len(c.Extra) > 0 && c.Extra[0] != '{' {
		c.Compatibility = append(c.Compatibility, "LEGACY_HTTP_INACTIVE_EXTRA")
	}
	if c.Transport == "websocket" {
		s := option(q, "", "ed", "max_early_data", "maxearlydata", "max-early-data")
		p, v, ok := strings.Cut(c.Path, "?")
		if ok {
			pq, _ := query(v)
			if s == "" && pq["ed"] != "" {
				s = pq["ed"]
				if _, e := strconv.Atoi(s); e != nil {
					s = ""
					c.InvalidPathED = true
				}
			}
			if _, ok := pq["ed"]; ok {
				var parts []string
				for _, item := range strings.Split(v, "&") {
					k, _, _ := strings.Cut(item, "=")
					if strings.ToLower(decode(k)) != "ed" {
						parts = append(parts, item)
					}
				}
				c.Path = p
				if len(parts) > 0 {
					c.Path += "?" + strings.Join(parts, "&")
				}
			}
		}
		if s != "" {
			var e error
			c.EarlyData, e = number(s, 0, 16384)
			if e != nil {
				return fail(e)
			}
		}
		c.EarlyHeader = option(q, c.EarlyHeader, "eh", "earlydataheadername", "early_data_header_name", "early-data-header-name")
	}
	return c, nil
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func (c *Config) parsePlugin() error {
	if c.Protocol != "ss" {
		return nil
	}
	s := c.Options["plugin"]
	if s == "" || contains([]string{"none", "0", "false", "off"}, strings.ToLower(s)) {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(s), "v2ray-plugin%3b") {
		s = decode(s)
	}
	name, rest, _ := strings.Cut(s, ";")
	c.Plugin = strings.ToLower(strings.TrimSpace(name))
	if contains([]string{"none", "0", "false", "off"}, c.Plugin) {
		c.Plugin = ""
		return nil
	}
	q := map[string]string{}
	var b strings.Builder
	escaped := false
	add := func() error {
		k, v, _ := strings.Cut(b.String(), "=")
		k = strings.ToLower(strings.TrimSpace(k))
		b.Reset()
		if k == "" {
			return nil
		}
		if _, ok := q[k]; ok {
			return errors.New("PARSE_INVALID: duplicate plugin option")
		}
		q[k] = v
		return nil
	}
	for _, ch := range rest {
		if escaped {
			b.WriteRune(ch)
			escaped = false
		} else if ch == '\\' {
			escaped = true
		} else if ch == ';' {
			if e := add(); e != nil {
				return e
			}
		} else {
			b.WriteRune(ch)
		}
	}
	if escaped {
		return errors.New("PARSE_INVALID: plugin escape")
	}
	if e := add(); e != nil {
		return e
	}
	c.PluginOptions = q
	switch c.Plugin {
	case "shadow-tls", "shadowtls":
		c.Plugin = "shadowtls"
		c.ServerName = option(q, c.Server, "host", "sni")
		c.Fingerprint = option(q, "chrome", "fp", "fingerprint")
	case "simple-obfs", "obfs-local":
		c.PluginMode = option(q, "http", "obfs")
		c.Transport = "obfs-" + c.PluginMode
		c.Host = option(q, c.Server, "obfs-host")
		c.Path = option(q, "/", "obfs-uri")
	case "v2ray-plugin":
		c.PluginMode = option(q, "websocket", "mode")
		c.Transport = c.PluginMode
		c.Path = option(q, "/", "path")
		c.Host = option(q, "cloudfront.com", "host")
		if _, ok := q["tls"]; ok || c.PluginMode == "quic" {
			c.Security = "tls"
			c.ServerName = c.Host
			if q["cert"] != "" {
				c.PluginCAFile = q["cert"]
				c.OnlyCustomRoots = true
			} else if q["certraw"] != "" {
				c.CAPEM = "-----BEGIN CERTIFICATE-----\n" + q["certraw"] + "\n-----END CERTIFICATE-----\n"
				c.OnlyCustomRoots = true
			}
		}
		n, e := number(option(q, "1", "mux"), 0, 1024)
		if e != nil {
			return e
		}
		c.PluginMux = n > 0 && c.PluginMode == "websocket"
		c.InsecureRequested = c.InsecureRequested || truth(q["skip-cert-verify"])
	}
	return nil
}

// ReadConfig reads the original node.ini format with bounded input.
func ReadConfig(path string) (Config, error) {
	f, e := os.Open(path)
	if e != nil {
		return Config{}, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1048577))
	if e != nil {
		return Config{}, e
	}
	if len(b) > 1048576 {
		return Config{}, errors.New("PARSE_INVALID: config too large")
	}
	b = bytes.TrimPrefix(b, []byte{239, 187, 191})
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte{'{'}) {
		routing, err := ReadRouterConfig(bytes.NewReader(b))
		if err != nil {
			return Config{}, err
		}
		c := defaults()
		c.Protocol, c.Transport, c.Security = "direct", "raw", "none"
		c.ListenPort, c.Routing = routing.ListenPort, &routing
		if routing.MaxConnections != 0 {
			c.MaxConnections = routing.MaxConnections
		}
		return c, nil
	}
	if len(b) > 131072 {
		return Config{}, errors.New("PARSE_INVALID: config too large")
	}
	q := map[string]string{}
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, 4096), 131073)
	for scan.Scan() {
		s := strings.TrimSpace(scan.Text())
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return Config{}, errors.New("PARSE_INVALID: key=value required")
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, ok := q[k]; ok {
			return Config{}, errors.New("PARSE_INVALID: duplicate config key")
		}
		q[k] = strings.TrimSpace(v)
	}
	if e := scan.Err(); e != nil {
		return Config{}, e
	}
	c, e := ParseURI(q["node_uri"])
	if e != nil {
		return c, e
	}
	for k, v := range q {
		lo, hi := 0, 0
		var target *int
		var duration *time.Duration
		switch k {
		case "node_uri":
			continue
		case "listen_port":
			target = &c.ListenPort
			hi = 65535
		case "max_connections":
			target = &c.MaxConnections
			lo, hi = 1, 512
		case "connect_timeout_ms":
			duration = &c.ConnectTimeout
			lo, hi = 1000, 120000
		case "idle_timeout_ms":
			duration = &c.IdleTimeout
			lo, hi = 1000, 600000
		case "udp_response_timeout_ms":
			duration = &c.UDPTimeout
			hi = 600000
		case "ready_file":
			c.ReadyFile = v
			continue
		case "sniffing", "native_dns", "prefer_ipv4", "prefer_tcp":
			if v != "true" && v != "false" {
				return c, fmt.Errorf("PARSE_INVALID: %s requires true or false", k)
			}
			switch k {
			case "sniffing":
				c.Sniffing = truth(v)
			case "native_dns":
				c.NativeDNS = truth(v)
			case "prefer_ipv4":
				c.PreferIPv4 = truth(v)
			case "prefer_tcp":
				c.PreferTCP = truth(v)
			}
			continue
		case "tls_ca_file", "test_ca_file":
			c.CAFile = v
			continue
		default:
			return c, fmt.Errorf("PARSE_INVALID: unknown config setting %s", k)
		}
		n, e := number(v, lo, hi)
		if e != nil {
			return c, e
		}
		if target != nil {
			*target = n
		} else {
			*duration = time.Duration(n) * time.Millisecond
		}
	}
	return c, nil
}
