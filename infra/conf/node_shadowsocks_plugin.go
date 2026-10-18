package conf

import (
	"errors"
	"net/url"
	"strings"
)

// nodeShadowsocksPlugin translates only the basic WebSocket subset of a
// v2ray-plugin SIP003 share-link into the *existing* in-process WS transport.
// No plugin executable is installed, spawned, downloaded or inferred. Options
// requiring an external plugin or a different wire format remain unsupported.
// The conversion is opt-in: all no-plugin Shadowsocks links are untouched.
func nodeShadowsocksPlugin(fields *nodeFields, scheme string) error {
	if scheme != "ss" {
		return nil
	}
	raw, present := fields.values["plugin"]
	if !present {
		return nil
	}
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n") {
		return errors.New("node URI: invalid Shadowsocks plugin")
	}
	parts := strings.Split(raw, ";")
	if parts[0] != "v2ray-plugin" {
		return errors.New("node URI: unsupported Shadowsocks plugin")
	}

	// Never overwrite explicit stream or TLS settings provided beside SIP003.
	// A plugin hint is not permission to silently reinterpret existing nodes.
	for _, key := range []string{
		"type", "network", "net", "security", "tls", "host", "authority",
		"path", "wspath", "sni", "servername", "peer", "fp", "fingerprint",
		"client-fingerprint", "alpn", "allowinsecure", "allow_insecure",
		"allow-insecure", "insecure", "skip-cert-verify", "ech", "echconfiglist",
		"ech-config-list", "pcs", "pinsha256", "pinnedpeercertsha256",
		"vcn", "verifypeercertbyname", "pbk", "publickey", "public-key",
		"sid", "shortid", "short-id", "spx", "spiderx", "pqv", "mldsa65verify",
	} {
		if _, exists := fields.values[key]; exists {
			return errors.New("node URI: conflicting Shadowsocks plugin and stream settings")
		}
	}

	options := make(map[string]string, 4)
	for _, part := range parts[1:] {
		if part == "" {
			return errors.New("node URI: empty Shadowsocks plugin option")
		}
		key, value, hasValue := strings.Cut(part, "=")
		key = strings.ToLower(key)
		switch key {
		case "tls":
			if hasValue {
				return errors.New("node URI: invalid Shadowsocks plugin TLS option")
			}
		case "mode", "host", "path", "mux":
			if !hasValue || value == "" {
				return errors.New("node URI: invalid Shadowsocks plugin option")
			}
		default:
			return errors.New("node URI: unsupported Shadowsocks plugin option")
		}
		if _, exists := options[key]; exists {
			return errors.New("node URI: duplicate Shadowsocks plugin option")
		}
		options[key] = value
	}
	if mode := options["mode"]; mode != "" && mode != "websocket" {
		return errors.New("node URI: unsupported Shadowsocks plugin mode")
	}
	// The plugin defaults to mux=1, which wraps the Shadowsocks stream in
	// V2Ray mux framing. Raw WS is compatible only with an explicitly mux=0
	// plugin endpoint; never silently map the default to a different wire.
	if options["mux"] != "0" {
		return errors.New("node URI: v2ray-plugin requires explicit mux=0; multiplexed plugin framing is unsupported")
	}
	if options["host"] == "" {
		options["host"] = "cloudfront.com" // v2ray-plugin's original default
	}
	if host := options["host"]; host != "" {
		// A plugin host is a single authority, not an HTTP header or a URL.
		if _, err := nodeEndpoint(host, "443"); err != nil {
			return errors.New("node URI: invalid Shadowsocks plugin host")
		}
	}
	if path := options["path"]; path != "" {
		// The supported subset is a simple WS pathname. Reject URI queries,
		// fragments, controls and ambiguous URLs (including WS early-data).
		parsed, err := url.ParseRequestURI(path)
		if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
			parsed == nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || strings.ContainsAny(path, "\x00\r\n\t?#") ||
			strings.ContainsAny(parsed.Path, "\x00\r\n\t") {
			return errors.New("node URI: invalid Shadowsocks plugin path")
		}
	}

	delete(fields.values, "plugin")
	fields.values["type"] = "ws"
	if host := options["host"]; host != "" {
		fields.values["host"] = host
	}
	if path := options["path"]; path != "" {
		fields.values["path"] = path
	}
	if _, tlsEnabled := options["tls"]; tlsEnabled {
		fields.values["security"] = "tls"
		if host := options["host"]; host != "" {
			fields.values["sni"] = host
		}
	}
	return nil
}
