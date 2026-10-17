package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestAddedVMessJSONHeadersAliasString(t *testing.T) {
	for _, network := range []string{"ws", "httpupgrade"} {
		body, err := json.Marshal(map[string]any{"v": "2", "add": "127.0.0.1", "port": "443", "id": "11111111-1111-4111-8111-111111111111", "aid": 0, "scy": "auto", "net": network, "type": "none", "headers": `{"X-Route":"synthetic"}`})
		if err != nil {
			t.Fatal(err)
		}
		out, err := conf.ParseNodeURI("vmess://" + base64.RawStdEncoding.EncodeToString(body))
		if err != nil {
			t.Fatal(err)
		}
		if network == "ws" && out.StreamSetting.WSSettings.Headers["X-Route"] != "synthetic" {
			t.Fatal("WS header missing")
		}
		if network == "httpupgrade" && out.StreamSetting.HTTPUPGRADESettings.Headers["X-Route"] != "synthetic" {
			t.Fatal("HTTPUpgrade header missing")
		}
		if _, err := out.Build(); err != nil {
			t.Fatal(err)
		}
	}
}
