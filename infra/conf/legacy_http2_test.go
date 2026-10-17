package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	legacyhttp "github.com/xtls/xray-core/transport/internet/http"
	"google.golang.org/protobuf/proto"
)

func TestForkLegacyHTTP2Selectors(t *testing.T) {
	for _, network := range []string{"http", "h2", "http2", "h2c"} {
		t.Run(network, func(t *testing.T) {
			var settings conf.StreamConfig
			if err := json.Unmarshal([]byte(`{"network":"`+network+`","security":"none","httpSettings":{"host":["tunnel.example"],"path":"/legacy"}}`), &settings); err != nil {
				t.Fatal(err)
			}
			stream, err := settings.Build()
			if err != nil {
				t.Fatal(err)
			}
			if stream.ProtocolName != "http" {
				t.Fatal("legacy HTTP/2 substituted with another transport", stream.ProtocolName)
			}
		})
	}
}

func TestForkLegacyHTTP2Configuration(t *testing.T) {
	for _, raw := range []string{
		`{"network":"h2","security":"tls","httpSettings":{"host":"tunnel.example","path":"legacy","method":"PATCH","headers":{"X-Test":["one","two"]},"read_idle_timeout":10,"health_check_timeout":3}}`,
		`{"network":"http2","security":"none"}`,
		`{"network":"h2c","httpSettings":{"path":"/a%20b?key=value"}}`,
	} {
		var c conf.StreamConfig
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		stream, err := c.Build()
		if err != nil {
			t.Fatal(err)
		}
		memory, err := internet.ToMemoryStreamConfig(stream)
		if err != nil {
			t.Fatal(err)
		}
		settings := memory.ProtocolSettings.(*legacyhttp.Config)
		if err := settings.Validate(); err != nil {
			t.Fatal(err)
		}
		wire, err := proto.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		var decoded legacyhttp.Config
		if err := proto.Unmarshal(wire, &decoded); err != nil || !proto.Equal(settings, &decoded) {
			t.Fatal("protobuf round trip failed", err)
		}
		if settings.Method == "PATCH" && (settings.Path != "legacy" || len(settings.Host) != 1 || len(settings.Header) != 1 || len(settings.Header[0].Value) != 2 || settings.IdleTimeout != 10 || settings.HealthCheckTimeout != 3) {
			t.Fatal("HTTP settings lost")
		}
	}
	for _, raw := range []string{
		`{"network":"h2c","security":"tls"}`,
		`{"network":"http","security":"reality"}`,
		`{"network":"h3"}`,
		`{"network":"quic-unknown"}`,
		`{"network":"http","httpSettings":{"method":"HEAD"}}`,
		`{"network":"http","httpSettings":{"method":"bad\r\n"}}`,
		`{"network":"http","httpSettings":{"path":"/%zz"}}`,
		`{"network":"http","httpSettings":{"path":"/x#fragment"}}`,
		`{"network":"http","httpSettings":{"host":"bad\r\nhost"}}`,
		`{"network":"http","httpSettings":{"headers":{"Host":"wrong"}}}`,
		`{"network":"http","httpSettings":{"headers":{"Content-Length":"1"}}}`,
		`{"network":"http","httpSettings":{"headers":{"X-Test":"bad\r\nvalue"}}}`,
		`{"network":"http","httpSettings":{"headers":{"X-Test":"1","x-test":"2"}}}`,
		`{"network":"http","httpSettings":{"read_idle_timeout":-1}}`,
		`{"network":"http","httpSettings":{"health_check_timeout":5}}`,
	} {
		var c conf.StreamConfig
		err := json.Unmarshal([]byte(raw), &c)
		if err == nil {
			_, err = c.Build()
		}
		if err == nil {
			t.Fatal("invalid legacy HTTP/2 configuration accepted", raw)
		}
	}
	for _, name := range []string{"tcp", "xhttp", "grpc", "websocket"} {
		p := conf.TransportProtocol(name)
		stream, err := (&conf.StreamConfig{Network: &p}).Build()
		if err != nil || stream.ProtocolName == "http" {
			t.Fatal("existing transport redirected to legacy HTTP/2", name, err)
		}
	}
}

func TestForkHTTP2MethodSelectorIsolation(t *testing.T) {
	for _, raw := range []string{
		`{"method":"tcp","network":"h2","httpSettings":{"host":true}}`,
		`{"method":"xhttp","network":"h2","httpSettings":"ignored"}`,
	} {
		var c conf.StreamConfig
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		stream, err := c.Build()
		if err != nil || stream.ProtocolName == "http" || c.HTTPSettings != nil {
			t.Fatal("method override entered the HTTP2 path", err)
		}
	}
	var c conf.StreamConfig
	if err := json.Unmarshal([]byte(`{"method":"h2c","network":"tcp","httpSettings":{"path":"/explicit"}}`), &c); err != nil {
		t.Fatal(err)
	}
	stream, err := c.Build()
	if err != nil || stream.ProtocolName != "http" || c.HTTPSettings == nil || c.HTTPSettings.Path != "/explicit" {
		t.Fatal("explicit HTTP2 method lost its settings", err)
	}
}
