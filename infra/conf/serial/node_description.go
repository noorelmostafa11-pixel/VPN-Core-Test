package serial

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/infra/conf"
)

func DecodeNodeConfig(reader io.Reader) (*conf.Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, conf.MaxNodeURIBytes+1))
	if err != nil || len(data) > conf.MaxNodeURIBytes {
		return nil, errors.New("node: unreadable or oversized description")
	}
	outbound, err := conf.ParseNodeJSON(data)
	if err != nil {
		return nil, err
	}
	return &conf.Config{OutboundConfigs: []conf.OutboundDetourConfig{*outbound}}, nil
}
