package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/quic"
	"google.golang.org/protobuf/proto"
)

func TestForkLegacyQUICSelection(t *testing.T) {
	for _, selector := range []string{"network", "method"} {
		var config conf.StreamConfig
		if err := json.Unmarshal([]byte(`{"`+selector+`":"quic","security":"tls","quicSettings":{"security":"aes-128-gcm","key":"synthetic","header":{"type":"srtp"}}}`), &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil || built.ProtocolName != "quic" {
			t.Fatal("standalone QUIC unavailable or substituted", err)
		}
	}
}

func TestForkLegacyQUICNodeMatrix(t *testing.T) {
	for _, cipher := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		for _, header := range []string{"none", "srtp", "utp", "dtls", "wechat", "wechat-video", "wireguard", "dns"} {
			input := fmt.Sprintf("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?type=quic&quicsecurity=%s&quickey=synthetic&headerType=%s", cipher, header)
			node, err := conf.ParseNodeURI(input)
			if err != nil {
				t.Fatal(err)
			}
			built, err := node.StreamSetting.Build()
			if err != nil {
				t.Fatal(err)
			}
			memory, err := internet.ToMemoryStreamConfig(built)
			if err != nil {
				t.Fatal(err)
			}
			selected := memory.ProtocolSettings.(*quic.Config)
			if memory.ProtocolName != "quic" || selected.Key != "synthetic" || selected.HeaderType != header {
				t.Fatal("node metadata not preserved")
			}
			wire, err := proto.Marshal(selected)
			if err != nil {
				t.Fatal(err)
			}
			var decoded quic.Config
			if err := proto.Unmarshal(wire, &decoded); err != nil || !proto.Equal(selected, &decoded) {
				t.Fatal("protobuf roundtrip changed metadata", err)
			}
			body := fmt.Sprintf(`{"add":"127.0.0.1","port":443,"id":"00000000-0000-4000-8000-000000000001","net":"quic","host":%q,"path":"synthetic","type":%q,"scy":"auto"}`, cipher, header)
			node, err = conf.ParseNodeURI("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(body)))
			if err != nil || node.StreamSetting.QUICSettings.Security != cipher || node.StreamSetting.QUICSettings.Key != "synthetic" {
				t.Fatal("legacy VMess envelope lost QUIC metadata", err)
			}
		}
	}
}

func TestForkLegacyQUICRejectsUnknownSettings(t *testing.T) {
	for _, raw := range []string{
		`{"network":"quic","security":"reality","realitySettings":{}}`,
		`{"network":"quic","security":"unknown"}`,
		`{"network":"quic","quicSettings":{"security":"auto"}}`,
		`{"network":"quic","quicSettings":{"header":{"type":"http"}}}`,
		`{"network":"quic","quicSettings":{"header":{"type":"none","unknown":1}}}`,
		`{"network":"quic","quicSettings":{"header":{"type":"dns","domain":"a..b"}}}`,
	} {
		var config conf.StreamConfig
		err := json.Unmarshal([]byte(raw), &config)
		if err == nil {
			_, err = config.Build()
		}
		if err == nil {
			t.Fatal("invalid QUIC settings accepted", raw)
		}
	}
	for _, suffix := range []string{"&quicsecurity=typo", "&security=tls&fp=chrome", "&host=none&quicsecurity=aes-128-gcm", "&quickey=one&path=two", "&headerType=dns&headerdomain=a..b", "&headerType=http"} {
		if _, err := conf.ParseNodeURI("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?type=quic" + suffix); err == nil {
			t.Fatal("invalid or conflicting node metadata accepted", suffix)
		}
	}
	for _, raw := range []string{`{"method":"tcp","network":"quic","quicSettings":true}`, `{"method":"http","network":"quic","quicSettings":"ignored"}`} {
		var config conf.StreamConfig
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil || built.ProtocolName == "quic" || config.QUICSettings != nil {
			t.Fatal("method override entered QUIC", err)
		}
	}
}

func TestForkLegacyQUICIgnoredSettings(t *testing.T) {
	for _, network := range []string{"tcp", "xhttp", "grpc", "ws", "http"} {
		for _, settings := range []string{`true`, `"ignored"`, `{"security":"unknown","key":17}`} {
			var config conf.StreamConfig
			if err := json.Unmarshal([]byte(`{"network":"`+network+`","quicSettings":`+settings+`}`), &config); err != nil {
				t.Fatal("original ignored field rejected", err)
			}
			built, err := config.Build()
			if err != nil || built.ProtocolName == "quic" {
				t.Fatal("original path redirected to QUIC", err)
			}
		}
	}
}
