package serial

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/infra/conf"
)

// DecodeURIConfig imports one node, not an arbitrary subscription or a list
// silently interpreted as retry candidates. A node selects its own codec.
func DecodeURIConfig(reader io.Reader) (*conf.Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, conf.MaxNodeURIBytes+1))
	if err != nil || len(data) > conf.MaxNodeURIBytes {
		return nil, errors.New("node URI: unreadable or oversized profile")
	}
	outbound, err := conf.ParseNodeURI(string(data))
	if err != nil {
		return nil, err
	}
	return &conf.Config{OutboundConfigs: []conf.OutboundDetourConfig{*outbound}}, nil
}
