package conf

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// This is a connection-data adapter for the original Hysteria2 transport. It
// supplies existing settings, never replaces the protocol/TLS implementation.
func nodeHysteria2Stream(fields *nodeFields, stream *StreamConfig) error {
	if stream.Security != "tls" || stream.TLSSettings == nil {
		return errors.New("node: Hysteria2 requires TLS")
	}
	tls := stream.TLSSettings
	// The transport uses its own QUIC handshake; a TCP uTLS selector must not
	// be silently relabeled as ChromeParrot or a standard-library handshake.
	if tls.Fingerprint != "" {
		return errors.New("node: Hysteria2 TLS fingerprint selection is unsupported")
	}
	if tls.ALPN != nil {
		if len(*tls.ALPN) != 1 || (*tls.ALPN)[0] != "h3" {
			return errors.New("node: Hysteria2 requires HTTP3 ALPN")
		}
	} else {
		alpn := StringList{"h3"}
		tls.ALPN = &alpn
	}
	if pin := fields.take("pinsha256", "pcs"); pin != "" {
		decoded, err := hex.DecodeString(strings.ReplaceAll(pin, ":", ""))
		if err != nil || len(decoded) != 32 {
			return errors.New("node: invalid Hysteria2 certificate fingerprint")
		}
		tls.PinnedPeerCertSha256 = hex.EncodeToString(decoded)
	}
	obfs := strings.ToLower(fields.take("obfs"))
	password := fields.take("obfs-password", "obfs_password")
	switch obfs {
	case "":
		if password != "" {
			return errors.New("node: obfuscation password without a Hysteria2 obfuscator")
		}
	case "salamander":
		if len(password) < 4 || len(password) > 4096 {
			return errors.New("node: invalid Hysteria2 obfuscation password")
		}
		encoded, _ := json.Marshal(&Salamander{Password: password})
		raw := json.RawMessage(encoded)
		stream.FinalMask = &FinalMask{Udp: []Mask{{Type: "salamander", Settings: &raw}}}
	default:
		return errors.New("node: Hysteria2 obfuscator import is unsupported")
	}
	stream.HysteriaSettings = &HysteriaConfig{Version: 2}
	return nil
}
