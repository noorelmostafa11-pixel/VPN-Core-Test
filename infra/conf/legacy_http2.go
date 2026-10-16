package conf

import (
	"sort"

	httpheader "github.com/xtls/xray-core/transport/internet/headers/http"
	legacyhttp "github.com/xtls/xray-core/transport/internet/http"
	"google.golang.org/protobuf/proto"
)

type HTTPConfig struct {
	Host               *StringList            `json:"host"`
	Path               string                 `json:"path"`
	Method             string                 `json:"method"`
	Headers            map[string]*StringList `json:"headers"`
	ReadIdleTimeout    int32                  `json:"read_idle_timeout"`
	HealthCheckTimeout int32                  `json:"health_check_timeout"`
}

func (c *HTTPConfig) Build() (proto.Message, error) {
	config := &legacyhttp.Config{Path: c.Path, Method: c.Method, IdleTimeout: c.ReadIdleTimeout, HealthCheckTimeout: c.HealthCheckTimeout}
	if c.Host != nil {
		config.Host = append([]string(nil), (*c.Host)...)
	}
	names := make([]string, 0, len(c.Headers))
	for name := range c.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var values []string
		if c.Headers[name] != nil {
			values = append([]string(nil), (*c.Headers[name])...)
		}
		config.Header = append(config.Header, &httpheader.Header{Name: name, Value: values})
	}
	return config, config.Validate()
}
