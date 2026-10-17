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
		Host string `json:"host"`
		Path string `json:"path"`
		Mode string `json:"mode"`
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
