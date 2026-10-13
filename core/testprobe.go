//go:build testprobe

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/net/http2/hpack"
	"lukechampine.com/blake3"
	"strings"
)

// TestProbe exposes synthetic fixture data only in developer test builds.
func TestProbe(kind, line string) (string, error) {
	unhex := func(s string) []byte {
		if s == "-" {
			return nil
		}
		b, _ := hex.DecodeString(s)
		return b
	}
	switch kind {
	case "protocol":
		h := sha256.Sum224(unhex(line))
		return hex.EncodeToString(h[:]), nil
	case "uri":
		var request struct{ URI string }
		if e := json.Unmarshal([]byte(line), &request); e != nil {
			return "", e
		}
		c, e := ParseURI(request.URI)
		if e != nil {
			return "", e
		}
		if e = c.Validate(); e != nil {
			code := e.Error()
			if strings.HasPrefix(code, "FINALMASK_") {
				code = "CONFIG_VALIDATION_INVALID"
			}
			b, _ := json.Marshal(map[string]string{"reason_code": code, "error": e.Error()})
			return string(b), nil
		}
		m := c.Inspect()
		m["original_options"] = c.Options
		m["resolved_extra"] = c.Extra
		m["resolved_public_key"] = c.PublicKey
		m["resolved_short_id"] = c.ShortID
		m["resolved_server_name"] = c.ServerName
		m["resolved_path"] = c.Path
		x, _ := c.xSettings()
		m["provider_extra"] = x.Extra
		b, e := json.Marshal(m)
		return string(b), e
	case "crypto":
		p := strings.Fields(line)
		if len(p) < 2 {
			return "", errors.New("probe fields")
		}
		switch p[0] {
		case "blake3":
			h := blake3.Sum256(unhex(p[1]))
			return hex.EncodeToString(h[:]), nil
		case "blake3-derive":
			b := make([]byte, 32)
			blake3.DeriveKey(b, string(unhex(p[1])), unhex(p[2]))
			return hex.EncodeToString(b), nil
		case "huffman":
			return hpack.HuffmanDecodeToString(unhex(p[1]))
		case "hpack":
			fields, e := hpack.NewDecoder(4096, nil).DecodeFull(unhex(p[1]))
			if e != nil {
				return "", e
			}
			m := map[string]string{}
			for _, f := range fields {
				m[f.Name] = f.Value
			}
			b, e := json.Marshal(m)
			return string(b), e
		default:
			if len(p) != 5 {
				return "", errors.New("AEAD fields")
			}
			a, e := cipherAEAD(p[0], unhex(p[1]))
			if e != nil {
				return "", e
			}
			nonce := unhex(p[2])
			if len(nonce) != a.NonceSize() {
				return "", errors.New("nonce")
			}
			b := a.Seal(nil, nonce, unhex(p[3]), unhex(p[4]))
			return hex.EncodeToString(b), nil
		}
	}
	return "", errors.New("probe kind")
}
