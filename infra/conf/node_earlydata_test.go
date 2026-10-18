package conf_test

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestNodeEarlyDataFourProtocolWireSelection(t *testing.T) {
	bases := []string{
		"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"vmess://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	}
	for _, base := range bases {
		for _, protocol := range []string{"ws", "httpupgrade"} {
			got, err := conf.ParseNodeURI(base + "?type=" + protocol + "&path=" + url.QueryEscape("/edge?x=1") + "&ed=256")
			if err != nil {
				t.Fatal(err)
			}
			want, err := conf.ParseNodeURI(base + "?type=" + protocol + "&path=" + url.QueryEscape("/edge?ed=256&x=1"))
			if err != nil {
				t.Fatal(err)
			}
			a, err := got.StreamSetting.Build()
			if err != nil {
				t.Fatal(err)
			}
			b, err := want.StreamSetting.Build()
			if err != nil {
				t.Fatal(err)
			}
			if !addedConfigEqual(a, b) {
				t.Fatal("early-data URI differs from full path wire config")
			}
			if _, err := got.Build(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestNodeEarlyDataRejectsConflictsAndIncompatibleCarriers(t *testing.T) {
	base := "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type="
	for name, input := range map[string]string{
		"negative": "ws&ed=-1", "too-big": "ws&ed=999999", "empty": "ws&ed=",
		"mixed-alias":     "ws&ed=10&earlyData=100",
		"pre-existing":    "ws&ed=128&path=" + url.QueryEscape("/a?ed=32"),
		"invalid-path":    "ws&ed=5&path=" + url.QueryEscape("http://bad.invalid/a"),
		"invalid-query":   "ws&ed=5&path=" + url.QueryEscape("/a?token=%zz"),
		"ambiguous-query": "ws&ed=5&path=" + url.QueryEscape("/a?token=one;two"),
		"wrong-http2":     "h2&ed=256", "wrong-grpc": "grpc&ed=256", "wrong-tcp": "tcp&ed=256",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := conf.ParseNodeURI(base + input); err == nil {
				t.Fatal("invalid early-data selector accepted")
			}
		})
	}
}

func TestNodeEarlyDataVersionedJSONParity(t *testing.T) {
	a, err := conf.ParseNodeURI("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type=ws&ed=512")
	if err != nil {
		t.Fatal(err)
	}
	j := conf.NodeDescription{
		Version: 1, Protocol: "vless", Address: "127.0.0.1", Port: 443,
		Credentials: conf.NodeCredentials{ID: "11111111-1111-4111-8111-111111111111"}, Parameters: map[string]string{"type": "ws", "ed": "512"},
	}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf.ParseNodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	left, err := a.StreamSetting.Build()
	if err != nil {
		t.Fatal(err)
	}
	right, err := b.StreamSetting.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !addedConfigEqual(left, right) {
		t.Fatal("early-data node JSON differs from URI")
	}
}
