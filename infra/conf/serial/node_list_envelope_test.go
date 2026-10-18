package serial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestVersionedSubscriptionEnvelopeFourProtocols(t *testing.T) {
	secret := "synthetic"
	ids := []conf.NodeDescription{
		{Version:1,Protocol:"vless",Address:"127.0.0.1",Port:443,Credentials:conf.NodeCredentials{ID:"11111111-1111-4111-8111-111111111111"}},
		{Version:1,Protocol:"vmess",Address:"127.0.0.1",Port:443,Credentials:conf.NodeCredentials{ID:"11111111-1111-4111-8111-111111111111"}},
		{Version:1,Protocol:"trojan",Address:"127.0.0.1",Port:443,Credentials:conf.NodeCredentials{Password:&secret}},
		{Version:1,Protocol:"ss",Address:"127.0.0.1",Port:443,Credentials:conf.NodeCredentials{Method:"aes-128-gcm",Password:&secret}},
	}
	encoded,err:=json.Marshal(struct{
		Version int `json:"version"`
		Nodes []conf.NodeDescription `json:"nodes"`
	}{Version:1,Nodes:ids})
	if err!=nil{t.Fatal(err)}
	got,err:=serial.DecodeNodeListJSONConfig(strings.NewReader(string(encoded)))
	if err!=nil{t.Fatal(err)}
	if len(got.OutboundConfigs)!=4{t.Fatal("envelope discarded a protocol")}
	for i, node:=range got.OutboundConfigs{
		if node.Tag=="" {t.Fatal("missing unique tag")}
		if i>0 && node.Tag==got.OutboundConfigs[i-1].Tag{t.Fatal("repeated tag")}
		if _,err:=node.Build();err!=nil{t.Fatal(err)}
	}
}

func TestVersionedSubscriptionEnvelopeRejectsAmbiguous(t *testing.T) {
	const item = `{"version":1,"protocol":"trojan","address":"127.0.0.1","port":443,"credentials":{"password":"synthetic"}}`
	for label,input:=range map[string]string{
		"empty-nodes":`{"version":1,"nodes":[]}`,
		"missing-version":`{"nodes":[`+item+`]}`,
		"missing-nodes":`{"version":1}`,
		"wrong-version":`{"version":2,"nodes":[`+item+`]}`,
		"string-version":`{"version":"1","nodes":[`+item+`]}`,
		"duplicate-mixed-case":`{"version":1,"Version":1,"nodes":[`+item+`]}`,
		"extra-field":`{"version":1,"nodes":[`+item+`],"routing":{"outbounds":[]}}`,
		"nodes-object":`{"version":1,"nodes":{}}`,
		"null-node":`{"version":1,"nodes":[null]}`,
		"trailing":`{"version":1,"nodes":[`+item+`]}{}`,
	}{
		t.Run(label,func(t *testing.T){
			if _,err:=serial.DecodeNodeListJSONConfig(strings.NewReader(input));err==nil {t.Fatal("unsafe subscription envelope accepted")}
		})
	}
}

func TestVersionedSubscriptionEnvelopePreservesOldReaders(t *testing.T) {
	input := `{"version":1,"nodes":[{"version":1,"protocol":"trojan","address":"127.0.0.1","port":443,"credentials":{"password":"synthetic"}}]}`
	if _,err:=serial.DecodeNodeConfig(strings.NewReader(input));err==nil{
		t.Fatal("single node import unexpectedly accepted list envelope")
	}
	if _,err:=serial.DecodeSubscriptionConfig(strings.NewReader(input));err==nil{
		t.Fatal("URI subscription import unexpectedly accepted JSON list")
	}
}
