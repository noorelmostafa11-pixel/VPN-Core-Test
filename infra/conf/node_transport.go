package conf

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

func nodeStream(fields *nodeFields, scheme string) (*StreamConfig, error) {
	network := strings.ToLower(fields.take("type", "network", "net"))
	if network == "" {
		network = "tcp"
	}
	p := TransportProtocol(network)
	stream := &StreamConfig{Network: &p}
	security := strings.ToLower(fields.take("security", "tls"))
	if security == "" && (scheme == "trojan" || scheme == "https") {
		security = "tls"
	}
	switch security {
	case "", "none", "false", "0":
		stream.Security = "none"
	case "tls", "true", "1":
		stream.Security = "tls"
	case "reality":
		stream.Security = "reality"
	default:
		return nil, errors.New("node URI: unsupported transport security")
	}
	sni := fields.take("sni", "servername", "peer")
	fingerprint := fields.take("fp", "fingerprint", "client-fingerprint")
	alpn := fields.take("alpn")
	insecure := fields.take("allowinsecure", "allow_insecure", "allow-insecure", "insecure", "skip-cert-verify")
	ech := fields.take("ech", "echconfiglist", "ech-config-list")
	key := fields.take("pbk", "publickey", "public-key")
	shortID := fields.take("sid", "shortid", "short-id")
	spider := fields.take("spx", "spiderx")
	pqv := fields.take("pqv", "mldsa65verify")
	if stream.Security == "tls" {
		if key != "" || shortID != "" || spider != "" || pqv != "" {
			return nil, errors.New("node URI: REALITY parameters on TLS node")
		}
		switch strings.ToLower(insecure) {
		case "", "0", "false", "1", "true":
		default:
			return nil, errors.New("node URI: invalid certificate policy")
		}
		cfg := &TLSConfig{ServerName: sni, Fingerprint: fingerprint, ECHConfigList: ech, AllowInsecure: insecure == "1" || strings.EqualFold(insecure, "true")}
		if alpn != "" {
			list := StringList{}
			for _, value := range strings.Split(alpn, ",") {
				value = strings.TrimSpace(value)
				if value == "" || len(value) > 255 {
					return nil, errors.New("node URI: invalid ALPN")
				}
				list = append(list, value)
			}
			cfg.ALPN = &list
		}
		stream.TLSSettings = cfg
	} else if stream.Security == "reality" {
		if insecure != "" || ech != "" || alpn != "" {
			return nil, errors.New("node URI: unsupported REALITY security parameters")
		}
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		if spider != "" {
			parsed, err := url.Parse(spider)
			if err != nil || !strings.HasPrefix(spider, "/") || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
				return nil, errors.New("node URI: invalid REALITY spider path")
			}
		}
		stream.REALITYSettings = &REALITYConfig{ServerName: sni, Fingerprint: fingerprint, PublicKey: key, ShortId: shortID, SpiderX: spider, Mldsa65Verify: pqv}
	} else if sni != "" || fingerprint != "" || alpn != "" || insecure != "" || ech != "" || key != "" || shortID != "" || spider != "" || pqv != "" {
		return nil, errors.New("node URI: security parameters on an unencrypted transport")
	}
	host := fields.take("host", "authority")
	if strings.ContainsAny(host, "\r\n\x00 \t") || (strings.Contains(host, ",") && network != "http" && network != "h2" && network != "http2" && network != "h2c") {
		return nil, errors.New("node URI: invalid transport authority")
	}
	path := fields.take("path", "wspath")
	service := fields.take("servicename", "service-name", "grpc-service-name", "service_name")
	mode := fields.take("mode")
	header := strings.ToLower(fields.take("headertype", "header-type"))
	extra := fields.take("extra")
	if header != "" && header != "none" && network != "quic" {
		return nil, errors.New("node URI: transport header import is not implemented")
	}
	switch network {
	case "quic":
		if stream.Security == "tls" && fingerprint != "" && fingerprint != "unsafe" && !strings.EqualFold(fingerprint, "hellogolang") {
			return nil, errors.New("node URI: QUIC browser TLS fingerprints are not implemented")
		}
		cipher := strings.ToLower(fields.take("quicsecurity", "quic-security", "quic_security"))
		key := fields.take("quickey", "quic-key", "quic_key", "key")
		if host != "" {
			if cipher != "" && cipher != strings.ToLower(host) {
				return nil, errors.New("node URI: conflicting QUIC packet cipher")
			}
			cipher = strings.ToLower(host)
		}
		if path != "" {
			if key != "" && key != path {
				return nil, errors.New("node URI: conflicting QUIC key")
			}
			key = path
		}
		domain := fields.take("headerdomain", "header-domain", "header_domain")
		encoded, _ := json.Marshal(map[string]string{"type": header, "domain": domain})
		stream.QUICSettings = &QUICConfig{Security: cipher, Key: key, Header: encoded}
	case "tcp", "raw", "kcp", "mkcp":
		if host != "" || path != "" || mode != "" || service != "" || extra != "" {
			return nil, errors.New("node URI: unsupported raw/KCP transport parameters")
		}
	case "ws", "websocket":
		stream.WSSettings = &WebSocketConfig{Host: host, Path: path}
	case "httpupgrade":
		stream.HTTPUPGRADESettings = &HttpUpgradeConfig{Host: host, Path: path}
	case "grpc":
		if service == "" {
			service = strings.TrimLeft(path, "/")
		}
		if mode != "" && mode != "gun" && mode != "multi" {
			return nil, errors.New("node URI: invalid gRPC mode")
		}
		stream.GRPCSettings = &GRPCConfig{Authority: host, ServiceName: service, MultiMode: mode == "multi"}
	case "http", "h2", "http2", "h2c":
		stream.HTTPSettings = &HTTPConfig{Path: path}
		if host != "" {
			list := StringList(strings.Split(host, ","))
			stream.HTTPSettings.Host = &list
		}
	case "xhttp", "splithttp":
		stream.XHTTPSettings = &SplitHTTPConfig{Host: host, Path: path, Mode: mode}
		if extra != "" {
			var object map[string]json.RawMessage
			if json.Unmarshal([]byte(extra), &object) != nil || object == nil {
				return nil, errors.New("node URI: invalid XHTTP extra object")
			}
			// A share link is connection data, not permission to load local
			// certificate/key files or replace arbitrary nested stream settings.
			for key, value := range object {
				switch strings.ToLower(key) {
				case "headers", "xpaddingbytes", "xpaddingobfsmode", "xpaddingkey", "xpaddingheader", "xpaddingplacement", "xpaddingmethod", "uplinkhttpmethod", "sessionidplacement", "sessionidkey", "sessionidtable", "sessionidlength", "seqplacement", "seqkey", "uplinkdataplacement", "uplinkdatakey", "uplinkchunksize", "nogrpcheader", "nosseheader", "scmaxeachpostbytes", "scminpostsintervalms", "scmaxbufferedposts", "scstreamupserversecs", "servermaxheaderbytes":
				case "xmux":
					var settings map[string]json.RawMessage
					if json.Unmarshal(value, &settings) != nil || settings == nil {
						return nil, errors.New("node URI: invalid XHTTP mux parameters")
					}
					for name := range settings {
						switch strings.ToLower(name) {
						case "maxconcurrency", "maxconnections", "cmaxreusetimes", "hmaxrequesttimes", "hmaxreusablesecs", "hkeepaliveperiod":
						default:
							return nil, errors.New("node URI: unsupported XHTTP mux parameter")
						}
					}
				default:
					return nil, errors.New("node URI: unsupported XHTTP extra parameter")
				}
			}
			stream.XHTTPSettings.Extra = json.RawMessage(extra)
		}
	default:
		return nil, errors.New("node URI: transport import is not implemented")
	}
	if network != "xhttp" && network != "splithttp" && extra != "" {
		return nil, errors.New("node URI: XHTTP extra on another transport")
	}
	if network != "grpc" && service != "" {
		return nil, errors.New("node URI: gRPC service on another transport")
	}
	if network != "grpc" && network != "xhttp" && network != "splithttp" && mode != "" {
		return nil, errors.New("node URI: mode on an incompatible transport")
	}
	return stream, nil
}
