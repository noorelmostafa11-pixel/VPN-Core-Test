package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// nodeXHTTPDownloadSettings validates the deliberately narrow, connection-only
// representation of an XHTTP download stream. The normal StreamConfig builder
// still owns transport, TLS and REALITY behavior; no local file or socket
// configuration can be injected through an untrusted node link.
func nodeXHTTPDownloadSettings(raw json.RawMessage) error {
	if len(raw) > 8192 {
		return errors.New("node URI: oversized XHTTP download settings")
	}
	var download struct {
		Address         string          `json:"address"`
		Port            uint16          `json:"port"`
		Network         string          `json:"network"`
		Security        string          `json:"security"`
		XHTTPSettings   json.RawMessage `json:"xhttpSettings"`
		TLSSettings     json.RawMessage `json:"tlsSettings"`
		REALITYSettings json.RawMessage `json:"realitySettings"`
	}
	if err := nodeXHTTPDecodeObject(raw, &download); err != nil {
		return errors.New("node URI: invalid XHTTP download settings")
	}
	if _, err := nodeEndpoint(download.Address, strconv.Itoa(int(download.Port))); err != nil {
		return errors.New("node URI: invalid XHTTP download endpoint")
	}
	if download.Network != "xhttp" && download.Network != "splithttp" {
		return errors.New("node URI: XHTTP download requires XHTTP network")
	}
	if err := nodeXHTTPDownloadTransport(download.XHTTPSettings); err != nil {
		return err
	}

	switch download.Security {
	case "none":
		if len(download.TLSSettings) != 0 || len(download.REALITYSettings) != 0 {
			return errors.New("node URI: XHTTP download security settings conflict")
		}
	case "tls":
		if len(download.REALITYSettings) != 0 {
			return errors.New("node URI: XHTTP download security settings conflict")
		}
		if len(download.TLSSettings) != 0 {
			var tlsSettings struct {
				ServerName           string      `json:"serverName"`
				Fingerprint          string      `json:"fingerprint"`
				ALPN                 *StringList `json:"alpn"`
				PinnedPeerCertSha256 string      `json:"pinnedPeerCertSha256"`
				VerifyPeerCertByName string      `json:"verifyPeerCertByName"`
				ECHConfigList        string      `json:"echConfigList"`
			}
			if err := nodeXHTTPDecodeObject(download.TLSSettings, &tlsSettings); err != nil {
				return errors.New("node URI: unsupported XHTTP download TLS settings")
			}
			if tlsSettings.ALPN != nil {
				for _, protocol := range *tlsSettings.ALPN {
					if protocol == "" || len(protocol) > 255 || strings.ContainsAny(protocol, "\x00\r\n") {
						return errors.New("node URI: invalid XHTTP download ALPN")
					}
				}
			}
		}
	case "reality":
		if len(download.TLSSettings) != 0 || len(download.REALITYSettings) == 0 {
			return errors.New("node URI: XHTTP download security settings conflict")
		}
		var realitySettings struct {
			ServerName    string `json:"serverName"`
			Fingerprint   string `json:"fingerprint"`
			PublicKey     string `json:"publicKey"`
			ShortID       string `json:"shortId"`
			SpiderX       string `json:"spiderX"`
			Mldsa65Verify string `json:"mldsa65Verify"`
		}
		if err := nodeXHTTPDecodeObject(download.REALITYSettings, &realitySettings); err != nil {
			return errors.New("node URI: unsupported XHTTP download REALITY settings")
		}
	default:
		// An absent security field must not silently become a cleartext download.
		return errors.New("node URI: XHTTP download requires explicit security")
	}
	return nil
}

func nodeXHTTPDownloadTransport(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var transport struct {
		Host                 string     `json:"host"`
		Headers              map[string]string `json:"headers"`
		Path                 string     `json:"path"`
		Mode                 string     `json:"mode"`
		UplinkHTTPMethod     string     `json:"uplinkHTTPMethod"`
		SessionIDPlacement   string     `json:"sessionIDPlacement"`
		SessionIDKey         string     `json:"sessionIDKey"`
		SeqPlacement         string     `json:"seqPlacement"`
		SeqKey               string     `json:"seqKey"`
		UplinkDataPlacement  string     `json:"uplinkDataPlacement"`
		UplinkDataKey        string     `json:"uplinkDataKey"`
		UplinkChunkSize      Int32Range `json:"uplinkChunkSize"`
		XPaddingBytes        Int32Range `json:"xPaddingBytes"`
		XPaddingObfsMode     bool       `json:"xPaddingObfsMode"`
		XPaddingKey          string     `json:"xPaddingKey"`
		XPaddingHeader       string     `json:"xPaddingHeader"`
		XPaddingPlacement    string     `json:"xPaddingPlacement"`
		XPaddingMethod       string     `json:"xPaddingMethod"`
		NoGRPCHeader         bool       `json:"noGRPCHeader"`
		NoSSEHeader          bool       `json:"noSSEHeader"`
		Xmux                 XmuxConfig `json:"xmux"`
	}
	if err := nodeXHTTPDecodeObject(raw, &transport); err != nil {
		return errors.New("node URI: unsupported XHTTP download transport settings")
	}
	if strings.ContainsAny(transport.Host, "\r\n\x00 \t") || strings.ContainsAny(transport.Path, "\r\n\x00") || (transport.Path != "" && !strings.HasPrefix(transport.Path, "/")) {
		return errors.New("node URI: invalid XHTTP download host or path")
	}
	switch transport.Mode {
	case "", "auto", "packet-up", "stream-up", "stream-one":
	default:
		return errors.New("node URI: unsupported XHTTP download mode")
	}
	if transport.UplinkHTTPMethod != "" && transport.UplinkHTTPMethod != "POST" &&
		transport.UplinkHTTPMethod != "GET" {
		return errors.New("node URI: unsupported XHTTP download uplink method")
	}
	for _, placement := range []string{transport.SessionIDPlacement, transport.SeqPlacement} {
		switch placement {
		case "", "path", "cookie", "header", "query":
		default:
			return errors.New("node URI: unsupported XHTTP download metadata placement")
		}
	}
	switch transport.UplinkDataPlacement {
	case "", "auto", "body", "cookie", "header":
	default:
		return errors.New("node URI: unsupported XHTTP download data placement")
	}
	for _, item := range []struct{ placement, key string }{
		{transport.SessionIDPlacement, transport.SessionIDKey},
		{transport.SeqPlacement, transport.SeqKey},
		{transport.UplinkDataPlacement, transport.UplinkDataKey},
	} {
		if len(item.key) > 64 {
			return errors.New("node URI: oversized XHTTP download metadata key")
		}
		if item.key == "" {
			continue
		}
		switch item.placement {
		case "header":
			if !nodeHTTPHeaderToken(item.key) || nodeHTTPTransportReservedHeader(item.key) {
				return errors.New("node URI: invalid XHTTP download header key")
			}
		case "cookie", "query":
			for _, character := range item.key {
				if !(character >= 'a' && character <= 'z' ||
					character >= 'A' && character <= 'Z' ||
					character >= '0' && character <= '9' ||
					character == '-' || character == '_') {
					return errors.New("node URI: invalid XHTTP download query/cookie key")
				}
			}
		default:
			return errors.New("node URI: XHTTP download key without compatible placement")
		}
	}
	if transport.UplinkChunkSize != (Int32Range{}) &&
		(transport.UplinkChunkSize.From < 1024 ||
			transport.UplinkChunkSize.To < transport.UplinkChunkSize.From ||
			transport.UplinkChunkSize.To > 262144) {
		return errors.New("node URI: invalid XHTTP download chunk-size range")
	}
	// HTTP headers on the independent XHTTP download leg use the same
	// reserved-name and input-safety policy as the original WS/HTTPUpgrade
	// node import. Host remains the dedicated authority field.
	if len(transport.Headers) > 32 {
		return errors.New("node URI: too many XHTTP download headers")
	}
	for key, value := range transport.Headers {
		if !nodeHTTPHeaderToken(key) || nodeHTTPTransportReservedHeader(key) ||
			len(value) > 2048 || !nodeHTTPHeaderValue(value) {
			return errors.New("node URI: unsafe XHTTP download header")
		}
	}
	if transport.XPaddingBytes.From < 0 || transport.XPaddingBytes.To > 8192 ||
		len(transport.XPaddingKey) > 64 || len(transport.XPaddingHeader) > 128 {
		return errors.New("node URI: unsafe XHTTP download padding")
	}
	if transport.XPaddingHeader != "" && !nodeHTTPHeaderToken(transport.XPaddingHeader) {
		return errors.New("node URI: invalid XHTTP download padding header")
	}
	for _, rng := range []Int32Range{
		transport.Xmux.MaxConcurrency, transport.Xmux.MaxConnections,
		transport.Xmux.CMaxReuseTimes, transport.Xmux.HMaxRequestTimes,
		transport.Xmux.HMaxReusableSecs,
	} {
		if rng.From < 0 || rng.To > 4096 {
			return errors.New("node URI: unsafe XHTTP download XMux limits")
		}
	}
	if transport.Xmux.HKeepAlivePeriod < 0 || transport.Xmux.HKeepAlivePeriod > 3600 {
		return errors.New("node URI: unsafe XHTTP download keep-alive")
	}
	// Preserve original Full-JSON semantics and validation for the accepted
	// fields. This does not instantiate a dialer or touch local files.
	config := &SplitHTTPConfig{
		Host: transport.Host, Path: transport.Path, Mode: transport.Mode,
		UplinkHTTPMethod: transport.UplinkHTTPMethod,
		SessionIDPlacement: transport.SessionIDPlacement,
		SessionIDKey: transport.SessionIDKey,
		SeqPlacement: transport.SeqPlacement,
		SeqKey: transport.SeqKey,
		UplinkDataPlacement: transport.UplinkDataPlacement,
		UplinkDataKey: transport.UplinkDataKey,
		UplinkChunkSize: transport.UplinkChunkSize,
		Headers: transport.Headers,
		XPaddingBytes: transport.XPaddingBytes,
		XPaddingObfsMode: transport.XPaddingObfsMode,
		XPaddingKey: transport.XPaddingKey,
		XPaddingHeader: transport.XPaddingHeader,
		XPaddingPlacement: transport.XPaddingPlacement,
		XPaddingMethod: transport.XPaddingMethod,
		NoGRPCHeader: transport.NoGRPCHeader,
		NoSSEHeader: transport.NoSSEHeader,
		Xmux: transport.Xmux,
	}
	if _, err := config.Build(); err != nil {
		return errors.New("node URI: invalid XHTTP download transport settings")
	}
	return nil
}

// Reject unknown fields and duplicate names, including mixed-case aliases.
// This helper is used only for the new downloadSettings opt-in, leaving the
// existing XHTTP extra path untouched for profiles without downloadSettings.
func nodeXHTTPDecodeObject(raw json.RawMessage, dst any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return errors.New("not a JSON object")
	}
	if !nodeJSONObject(json.NewDecoder(bytes.NewReader(raw)), 0) {
		return errors.New("ambiguous JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid JSON object")
	}
	var rest any
	if decoder.Decode(&rest) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
