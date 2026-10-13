package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

func (c Config) tlsSettings() (settings, error) {
	s := settings{Security: c.Security, Fingerprint: c.Fingerprint, ServerName: c.ServerName, ALPN: append([]string{}, c.ALPN...), CAFile: c.CAFile, CAPEM: c.CAPEM, OnlyCustomRoots: c.OnlyCustomRoots, PublicKey: c.PublicKey, ShortID: c.ShortID, PQVerify: option(c.Options, "", "pqv", "mldsa65verify", "mldsa65-verify"), Vision: strings.HasPrefix(c.Flow, "xtls-rprx-vision"), ECH: c.ECH, TimeoutMS: int(c.ConnectTimeout.Milliseconds())}
	if c.OnlyCustomRoots {
		s.CAFile = c.PluginCAFile
	}
	if c.Security == "xtls" {
		s.Security = "tls"
		s.LegacyXTLS = strings.TrimSuffix(c.Flow, "-udp443")
	}
	if s.Fingerprint == "" && c.Security == "tls" {
		s.Fingerprint = "native"
	}
	if (c.Transport == "websocket" || c.Transport == "httpupgrade") && contains(s.ALPN, "http/1.1") {
		s.ALPN = []string{"http/1.1"}
	}
	if len(s.ALPN) == 0 {
		switch c.Transport {
		case "websocket", "httpupgrade":
			s.ALPN = []string{"http/1.1"}
		case "grpc", "http":
			s.ALPN = []string{"h2"}
		case "xhttp":
			s.ALPN = []string{"h2", "http/1.1"}
		}
	}
	list := func(keys ...string) ([]string, error) {
		v := option(c.Options, "", keys...)
		if v == "" {
			return nil, nil
		}
		var a []string
		if v[0] == '[' {
			if e := json.Unmarshal([]byte(v), &a); e != nil {
				return nil, e
			}
		} else {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					a = append(a, p)
				}
			}
		}
		if len(a) > 32 {
			return nil, errors.New("TLS_LIST_LIMIT")
		}
		return a, nil
	}
	var e error
	s.Pins, e = list("pcs", "pinnedpeercertsha256", "pinned-peer-cert-sha256", "pinsha256")
	if e != nil {
		return s, e
	}
	for i, p := range s.Pins {
		if b, e := hex.DecodeString(p); e == nil && len(b) == 32 {
			s.Pins[i] = strings.ToLower(p)
			continue
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "sha256/"), "sha256-")
		b, e := decode64(p)
		if e != nil || len(b) != 32 {
			return s, errors.New("TLS_PIN_INVALID")
		}
		s.Pins[i] = hex.EncodeToString(b)
	}
	s.Names, e = list("vcn", "verifypeercertbyname", "verify-peer-cert-by-name")
	if e != nil {
		return s, e
	}
	for _, n := range s.Names {
		if !hostValid(n) {
			return s, errors.New("TLS_NAME_INVALID")
		}
	}
	return s, nil
}
func rangeValue(raw json.RawMessage, max int) (wireRange, error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "\"\"" {
		return wireRange{}, nil
	}
	var r intRange
	if e := json.Unmarshal(raw, &r); e != nil || r.Hi > max {
		return wireRange{}, errors.New("FINALMASK_RANGE")
	}
	return wireRange{r.Lo, r.Hi}, nil
}
func (c Config) masks() ([]wireMask, error) {
	if len(c.FinalMask) == 0 || string(c.FinalMask) == "null" {
		return nil, nil
	}
	var fm map[string]json.RawMessage
	if e := json.Unmarshal(c.FinalMask, &fm); e != nil {
		return nil, errors.New("FINALMASK_STRUCTURE_INVALID")
	}
	if string(fm["type"]) == "\"fragment\"" {
		fm = map[string]json.RawMessage{"tcp": append(append([]byte{'['}, c.FinalMask...), ']')}
	}
	if raw, ok := fm["outbounds"]; ok {
		var a []struct {
			Protocol string
			Settings struct{ Fragment map[string]json.RawMessage }
		}
		if json.Unmarshal(raw, &a) != nil || len(a) != 1 || a[0].Protocol != "freedom" {
			return nil, errors.New("FINALMASK_OUTBOUND")
		}
		m := a[0].Settings.Fragment
		if v, ok := m["interval"]; ok {
			m["delay"] = v
			delete(m, "interval")
		}
		b, _ := json.Marshal(map[string]any{"type": "fragment", "settings": m})
		fm = map[string]json.RawMessage{"tcp": append(append([]byte{'['}, b...), ']')}
	}
	for k := range fm {
		if k != "tcp" && k != "udp" {
			return nil, errors.New("FINALMASK_STRUCTURE_INVALID")
		}
	}
	var items []struct {
		Type     string
		Settings map[string]json.RawMessage
	}
	if len(fm["tcp"]) > 0 && json.Unmarshal(fm["tcp"], &items) != nil {
		return nil, errors.New("FINALMASK_TCP_LIST")
	}
	if len(items) > 8 {
		return nil, errors.New("FINALMASK_LIMIT")
	}
	var out []wireMask
	for _, item := range items {
		if item.Type != "fragment" {
			return nil, errors.New("FEATURE_UNIMPLEMENTED: FINALMASK_TCP_TYPE")
		}
		s := item.Settings
		if s == nil {
			return nil, errors.New("FINALMASK_SETTINGS")
		}
		for k := range s {
			if !contains([]string{"packets", "length", "lengths", "delay", "delays", "maxSplit"}, k) {
				return nil, errors.New("FEATURE_UNIMPLEMENTED: FINALMASK_OPTION")
			}
		}
		var m wireMask
		var packets string
		json.Unmarshal(s["packets"], &packets)
		if packets == "tlshello" {
			m.TLSHello = true
		} else {
			r, e := rangeValue(s["packets"], 1000000)
			if e != nil {
				return nil, e
			}
			if len(s["packets"]) > 0 && r.Lo == 0 {
				return nil, errors.New("FINALMASK_PACKETS")
			}
			m.Packets = r
		}
		ranges := func(plural, singular string, max int) ([]wireRange, error) {
			var a []json.RawMessage
			if len(s[plural]) > 0 {
				if json.Unmarshal(s[plural], &a) != nil {
					return nil, errors.New("FINALMASK_LIST")
				}
			}
			if len(a) == 0 {
				a = []json.RawMessage{s[singular]}
			}
			if len(a) > 64 {
				return nil, errors.New("FINALMASK_LIST_LIMIT")
			}
			var out []wireRange
			for _, v := range a {
				r, e := rangeValue(v, max)
				if e != nil {
					return nil, e
				}
				out = append(out, r)
			}
			return out, nil
		}
		var e error
		m.Lengths, e = ranges("lengths", "length", 1048576)
		if e != nil {
			return nil, e
		}
		if m.Lengths[len(m.Lengths)-1].Lo == 0 {
			return nil, errors.New("FINALMASK_LENGTH")
		}
		m.Delays, e = ranges("delays", "delay", 1000)
		if e != nil {
			return nil, e
		}
		m.MaxSplit, e = rangeValue(s["maxSplit"], 65536)
		if e != nil {
			return nil, e
		}
		out = append(out, m)
	}
	return out, nil
}
func (c Config) xSettings() (xSettings, error) {
	t, e := c.tlsSettings()
	if e != nil {
		return xSettings{}, e
	}
	m, e := c.masks()
	if e != nil {
		return xSettings{}, e
	}
	x := xSettings{Transport: c.Transport, Server: c.Server, Port: c.Port, Host: c.Host, Path: c.Path, Mode: c.Mode, Extra: c.Extra, TLS: t, Masks: m, LegacyHTTP: c.Transport == "http"}
	if x.LegacyHTTP && len(x.Extra) > 0 && x.Extra[0] != '{' {
		x.Extra = nil
	}
	x.KCP.Header = c.Header
	x.KCP.HeaderDomain = option(c.Options, "", "headerdomain", "header-domain")
	if s, ok := c.Options["seed"]; ok {
		x.KCP.Seed = &s
	}
	for _, p := range []struct {
		k      string
		target *int
	}{{"mtu", &x.KCP.MTU}, {"tti", &x.KCP.TTI}} {
		if v, ok := c.Options[p.k]; ok {
			n, e := number(v, 1, 65535)
			if e != nil {
				return x, e
			}
			*p.target = n
		}
	}
	x.QUIC = legacyQUICOptions{Header: c.Header, HeaderDomain: x.KCP.HeaderDomain, Cipher: option(c.Options, "none", "quicsecurity", "quic-security"), Key: option(c.Options, "", "quickey", "quic-key", "key")}
	if c.Plugin == "v2ray-plugin" {
		x.QUIC.Cipher = "none"
	}
	return x, nil
}

// Validate refuses invalid or unsupported options before opening a socket.
func (c Config) Validate() error {
	if c.MaxConnections < 1 || c.MaxConnections > 512 || c.ConnectTimeout <= 0 || c.IdleTimeout <= 0 {
		return errors.New("ENGINE_LIMIT_INVALID")
	}
	if c.Routing != nil {
		if _, err := compileRoutes(*c.Routing); err != nil {
			return err
		}
	}
	if c.Protocol == "hysteria2" {
		return validateHysteria(c)
	}
	if c.Protocol == "ssh" {
		return validateSSH(c)
	}
	if c.Protocol == "wireguard" {
		return validateWireGuard(c)
	}
	if c.Protocol == "anytls" {
		return validateAnyTLS(c)
	}
	if isProxyProtocol(c.Protocol) {
		return validateProxyConfig(c)
	}
	if !contains([]string{"vless", "vmess", "trojan", "ss"}, c.Protocol) || !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 {
		return errors.New("PARSE_INVALID: protocol or endpoint")
	}
	if !contains([]string{"raw", "websocket", "grpc", "xhttp", "httpupgrade", "http", "kcp", "quic", "obfs-http", "obfs-tls"}, c.Transport) {
		return errors.New("TRANSPORT_NAME_INVALID")
	}
	if !contains([]string{"none", "tls", "reality", "xtls"}, c.Security) {
		return errors.New("PARSE_INVALID: security")
	}
	flows := []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443", "xtls-rprx-direct", "xtls-rprx-direct-udp443", "xtls-rprx-origin", "xtls-rprx-origin-udp443", "xtls-rprx-splice", "xtls-rprx-splice-udp443"}
	if !contains(flows, c.Flow) {
		return errors.New("FLOW_NAME_INVALID")
	}
	vision := strings.HasPrefix(c.Flow, "xtls-rprx-vision")
	if vision && (c.Protocol != "vless" || c.Security == "none" || c.Transport != "raw" && c.Transport != "xhttp") {
		return errors.New("VISION_CONFIGURATION")
	}
	if c.Security == "xtls" {
		if !contains([]string{"vless", "trojan"}, c.Protocol) || c.Transport != "raw" || c.Flow == "" || vision {
			return errors.New("XTLS_CONFIGURATION")
		}
	} else if c.Flow != "" && !vision {
		return errors.New("XTLS_FLOW_SECURITY")
	}
	if c.Security != "none" {
		if _, e := profile(c.Fingerprint); e != nil {
			return errors.New("TLS_FINGERPRINT_INVALID")
		}
	}
	if c.Security == "reality" {
		b, e := decode64(c.PublicKey)
		if e != nil || len(b) != 32 {
			return errors.New("REALITY_PUBLIC_KEY_INVALID")
		}
		b, e = hex.DecodeString(c.ShortID)
		if e != nil || len(b) > 8 {
			return errors.New("REALITY_SHORT_ID_INVALID")
		}
	}
	if c.ECH != "" && c.Security != "tls" {
		return errors.New("ECH_CONFIGURATION")
	}
	if c.Protocol == "vmess" && !contains([]string{"", "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"}, c.Cipher) {
		return errors.New("VMESS_CIPHER_INVALID")
	}
	if c.Protocol == "ss" {
		if !contains(ssMethods, c.Cipher) {
			return errors.New("SS_CIPHER_INVALID")
		}
		if _, e := ssKeys(c); e != nil {
			return e
		}
	}
	if c.Protocol == "vless" && c.Encryption != "none" {
		if !strings.HasPrefix(c.Encryption, "mlkem768x25519plus.") {
			return errors.New("VLESS_ENCRYPTION_INVALID")
		}
		if _, e := parseEncryption(c.Encryption); e != nil {
			return errors.New("VLESS_ENCRYPTION_CONFIGURATION")
		}
	}
	if c.Plugin != "" && !((c.Plugin == "v2ray-plugin" && contains([]string{"websocket", "quic"}, c.PluginMode)) || (contains([]string{"simple-obfs", "obfs-local"}, c.Plugin) && contains([]string{"http", "tls"}, c.PluginMode))) {
		return errors.New("FEATURE_UNIMPLEMENTED: SS_PLUGIN")
	}
	if c.Transport == "xhttp" && len(c.ALPN) > 0 && c.Security != "reality" && !contains(c.ALPN, "h2") && !contains(c.ALPN, "h3") && !contains(c.ALPN, "http/1.1") {
		return errors.New("XHTTP_ALPN_INVALID")
	}
	if c.Transport == "raw" && !contains([]string{"", "none", "http"}, strings.ToLower(c.Header)) {
		return errors.New("RAW_HEADER_INVALID")
	}
	if c.Host != "" && contains([]string{"websocket", "httpupgrade", "xhttp", "http", "obfs-http"}, c.Transport) && strings.ContainsAny(c.Host, " \t\r\n\x00") {
		return errors.New("HTTP_HOST_INVALID")
	}
	if strings.ContainsAny(c.Path, "\r\n") || strings.ContainsAny(c.Service, "\r\n") {
		return errors.New("HTTP_PATH_INVALID")
	}
	if c.Transport == "websocket" && c.EarlyData > 0 {
		if !httpToken(c.EarlyHeader) || contains([]string{"host", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version", "sec-websocket-accept", "sec-websocket-extensions", "content-length", "transfer-encoding"}, strings.ToLower(c.EarlyHeader)) {
			return errors.New("WEBSOCKET_EARLY_HEADER")
		}
	}
	if _, e := c.tlsSettings(); e != nil {
		return e
	}
	if _, e := c.masks(); e != nil {
		return e
	}
	if contains([]string{"xhttp", "http", "kcp", "quic"}, c.Transport) {
		x, e := c.xSettings()
		if e != nil {
			return e
		}
		switch c.Transport {
		case "kcp":
			_, e = x.KCP.validate()
		case "quic":
			e = x.QUIC.validate()
		default:
			_, e = x.options()
		}
		if e != nil {
			return errors.New("XHTTP_CONFIGURATION")
		}
	}
	return nil
}
func (c Config) Inspect() map[string]any {
	if c.ALPN == nil {
		c.ALPN = []string{}
	}
	m := map[string]any{"schema": "vpn-core-inspect-v3", "protocol": c.Protocol, "transport": c.Transport, "security": c.Security, "flow": c.Flow, "cipher": c.Cipher, "fingerprint": c.Fingerprint, "plugin": c.Plugin, "plugin_mux": c.PluginMux, "websocket_early_data": c.EarlyData, "websocket_path_ed_invalid": c.InvalidPathED, "alter_id": c.AlterID, "alpn": c.ALPN, "mode": c.Mode, "header_type": c.Header, "certificate_verification": true, "legacy_insecure_requested": c.InsecureRequested, "uri_parsed": true, "config_valid": true, "network_test_performed": false, "connectable_by_this_build": true, "missing_features": []string{}, "source_uri_preserved": true}
	if c.Routing != nil {
		m["routing_enabled"], m["outbound_count"], m["route_count"], m["group_count"] = true, len(c.Routing.Outbounds), len(c.Routing.Rules), len(c.Routing.Groups)
		m["source_uri_preserved"] = false
		m["protocol"], m["transport"] = "routing", "policy"
	}
	if c.Protocol == "vless" {
		summary := c.Encryption
		if strings.HasPrefix(summary, "mlkem") {
			parts := strings.Split(summary, ".")
			if len(parts) >= 3 {
				summary = strings.Join(parts[:3], ".")
			}
		}
		m["cipher"] = summary
	}
	if c.Protocol == "vmess" {
		auth := "aead"
		if c.AlterID > 0 {
			auth = "legacy-md5-cfb"
		}
		m["vmess_authentication"] = auth
	}
	if len(c.Compatibility) > 0 {
		m["uri_compatibility"] = c.Compatibility
	}
	if e := c.Validate(); e != nil {
		m["connectable_by_this_build"] = false
		m["config_valid"] = false
		m["reason_code"] = e.Error()
	}
	return m
}
