package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestAddedVMessJSONHeadersAliasRejectsUnsafe(t *testing.T) {
	for _, item := range []struct{ network, headers string }{
		{"ws", `{"Host":"override.invalid"}`},
		{"ws", `{"X-Test":"one","x-test":"two"}`},
		{"httpupgrade", `{"Connection":"close"}`},
		{"tcp", `{"X-Test":"synthetic"}`},
	} {
		body, err := json.Marshal(map[string]any{"v": "2", "add": "127.0.0.1", "port": "443", "id": "11111111-1111-4111-8111-111111111111", "aid": 0, "scy": "auto", "net": item.network, "type": "none", "headers": item.headers})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conf.ParseNodeURI("vmess://" + base64.RawStdEncoding.EncodeToString(body)); err == nil {
			t.Fatal("unsafe VMess JSON headers alias accepted on", item.network)
		}
	}
}
