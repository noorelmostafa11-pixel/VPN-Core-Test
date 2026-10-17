package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	protocolName   = "quic"
	internalDomain = "quic.internal.example.com"
)

// Key derivation and nonce-prefixed packet encryption match pre-removal Xray
// ab3c00e9 and pinned main b066df12. This is not HTTP/3 or XHTTP framing.
func (c *Config) auth() (cipher.AEAD, error) {
	security := protocol.SecurityType_NONE
	if c.Security != nil {
		security = c.Security.Type
	}
	key := sha256.Sum256([]byte(c.Key + "xray-quic-salt"))
	switch security {
	case protocol.SecurityType_NONE:
		return nil, nil
	case protocol.SecurityType_AES128_GCM:
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case protocol.SecurityType_CHACHA20_POLY1305:
		return chacha20poly1305.New(key[:])
	default:
		return nil, errors.New("legacy QUIC: unsupported packet cipher")
	}
}

func (c *Config) Validate() error {
	if c == nil || len(c.Key) > 1024 {
		return errors.New("legacy QUIC: missing or oversized settings")
	}
	if _, err := c.auth(); err != nil {
		return err
	}
	_, err := c.packetHeader()
	return err
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} { return new(Config) }))
}
