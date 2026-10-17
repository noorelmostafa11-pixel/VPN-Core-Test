package uri

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func init() {
	common.Must(core.RegisterConfigLoader(&core.ConfigFormat{
		Name: "URI", Extension: []string{"uri"},
		Loader: func(input interface{}) (*core.Config, error) {
			reader, ok := input.(io.Reader)
			if !ok {
				return nil, errors.New("node URI: expected a reader")
			}
			config, err := serial.DecodeURIConfig(reader)
			if err != nil {
				return nil, err
			}
			return config.Build()
		},
	}))
}
