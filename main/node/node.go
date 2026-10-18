package node

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func init() {
	for _, format := range []struct {
		name       string
		extensions []string
		decode     func(io.Reader) (*conf.Config, error)
	}{
		{"node", []string{"node"}, serial.DecodeNodeConfig},
		{"subscription", []string{"sub", "subscription"}, serial.DecodeSubscriptionConfig},
		{"sub", nil, serial.DecodeSubscriptionConfig},
		{"subjson", []string{"subjson", "node-list"}, serial.DecodeNodeListJSONConfig},
		{"node-list", nil, serial.DecodeNodeListJSONConfig},
	} {
		common.Must(core.RegisterConfigLoader(&core.ConfigFormat{
			Name: format.name, Extension: format.extensions,
			Loader: func(input interface{}) (*core.Config, error) {
				reader, ok := input.(io.Reader)
				if !ok {
					return nil, errors.New("node: expected a reader")
				}
				config, err := format.decode(reader)
				if err != nil {
					return nil, err
				}
				return config.Build()
			},
		}))
	}
}
