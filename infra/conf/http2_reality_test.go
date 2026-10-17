package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestForkHTTP2RealitySelection(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, network := range []string{"http", "h2", "http2", "H2"} {
		for _, selector := range []string{"network", "method"} {
			var config conf.StreamConfig
			data, _ := json.Marshal(map[string]any{selector: network, "security": "reality", "realitySettings": map[string]any{"serverName": "reality.example", "fingerprint": "chrome", "publicKey": key, "shortId": "ab"}, "httpSettings": map[string]any{"path": "/extra"}})
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatalf("%s=%s: %v", selector, network, err)
			}
			memory, err := internet.ToMemoryStreamConfig(built)
			if err != nil || memory.ProtocolName != "http" || reality.ConfigFromStreamSettings(memory) == nil {
				t.Fatal("HTTP2/REALITY changed to another transport or security", err)
			}
		}
	}
	for _, network := range []string{"http", "h2", "http2"} {
		node, err := conf.ParseNodeURI("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?type=" + network + "&security=reality&sni=reality.example&pbk=" + key + "&sid=ab&path=%2Fextra")
		if err != nil || node.StreamSetting.REALITYSettings.Fingerprint != "chrome" {
			t.Fatal("node did not select HTTP2/REALITY automatically", network, err)
		}
	}
}

func TestForkHTTP2RealityKeepsSecurityGuards(t *testing.T) {
	for _, raw := range []string{
		`{"network":"http","security":"reality"}`,
		`{"network":"h2c","security":"reality","realitySettings":{}}`,
		`{"network":"http","security":"unknown"}`,
		`{"network":"ws","security":"reality","realitySettings":{}}`,
	} {
		var config conf.StreamConfig
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); err == nil {
			t.Fatal("invalid or unsupported combination accepted", raw)
		}
	}
}
