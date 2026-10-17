package conf_test

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

func TestAddedHeadersAliasVersionedJSONParity(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	const headers = `{"X-Route":"synthetic"}`
	pass := "synthetic"
	profiles := []struct {
		scheme, uri string
		creds conf.NodeCredentials
	}{
		{"vless", "vless://"+id+"@127.0.0.1:443", conf.NodeCredentials{ID:id}},
		{"vmess", "vmess://"+id+"@127.0.0.1:443", conf.NodeCredentials{ID:id}},
		{"trojan", "trojan://synthetic@127.0.0.1:443", conf.NodeCredentials{Password:&pass}},
		{"ss", "ss://aes-128-gcm:synthetic@127.0.0.1:443", conf.NodeCredentials{Method:"aes-128-gcm",Password:&pass}},
	}
	for _, profile := range profiles {
		for _, network := range []string{"ws","httpupgrade"} {
			body,err:=json.Marshal(conf.NodeDescription{Version:1,Protocol:profile.scheme,Address:"127.0.0.1",Port:443,Credentials:profile.creds,Parameters:map[string]string{"type":network,"headers":headers}})
			if err!=nil {t.Fatal(err)}
			got,err:=conf.ParseNodeJSON(body)
			if err!=nil {t.Fatal(err)}
			want,err:=conf.ParseNodeURI(profile.uri+"?type="+network+"&headers="+url.QueryEscape(headers))
			if err!=nil {t.Fatal(err)}
			actual,err:=got.StreamSetting.Build()
			if err!=nil {t.Fatal(err)}
			expected,err:=want.StreamSetting.Build()
			if err!=nil {t.Fatal(err)}
			if !proto.Equal(actual,expected) {t.Fatal("JSON/URI transport mismatch",profile.scheme,network)}
		}
	}
}
