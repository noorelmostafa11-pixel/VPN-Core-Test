package node

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func init() {
	common.Must(core.RegisterConfigLoader(&core.ConfigFormat{
		Name: "Node", Extension: []string{"node"},
		Loader: func(input interface{}) (*core.Config, error) {
			reader, ok := input.(io.Reader)
			if !ok {
				return nil, errors.New("node: expected a reader")
			}
			config, err := serial.DecodeNodeConfig(reader)
			if err != nil {
				return nil, err
			}
			return config.Build()
		},
	}))
}
