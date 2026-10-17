package conf

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet/quic"
	"google.golang.org/protobuf/proto"
)

type QUICConfig struct {
	Security string          `json:"security"`
	Key      string          `json:"key"`
	Header   json.RawMessage `json:"header"`
}

func (c *QUICConfig) Build() (proto.Message, error) {
	config := &quic.Config{Key: c.Key, Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE}}
	switch strings.ToLower(c.Security) {
	case "", "none":
	case "aes-128-gcm":
		config.Security.Type = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		config.Security.Type = protocol.SecurityType_CHACHA20_POLY1305
	default:
		return nil, errors.New("legacy QUIC: unsupported packet cipher")
	}
	if len(c.Header) > 0 && string(c.Header) != "null" {
		var header struct {
			Type   string `json:"type"`
			Domain string `json:"domain"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(c.Header)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&header); err != nil {
			return nil, errors.New("legacy QUIC: invalid header settings")
		}
		var tail any
		if decoder.Decode(&tail) != io.EOF {
			return nil, errors.New("legacy QUIC: trailing header settings")
		}
		config.HeaderType, config.HeaderDomain = header.Type, header.Domain
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
