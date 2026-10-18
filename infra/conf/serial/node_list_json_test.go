package serial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestExplicitJSONNodeListFourProtocolImport(t *testing.T) {
	secret := "synthetic"
	descriptions := []conf.NodeDescription{
		{Version: 1, Protocol: "vless", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{ID: "11111111-1111-4111-8111-111111111111"}, Parameters: map[string]string{"type": "ws"}},
		{Version: 1, Protocol: "vmess", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{ID: "11111111-1111-4111-8111-111111111111"}, Parameters: map[string]string{"type": "grpc", "serviceName": "synthetic"}},
		{Version: 1, Protocol: "trojan", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{Password: &secret}, Parameters: map[string]string{"type": "tcp"}},
		{Version: 1, Protocol: "ss", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{Method: "aes-128-gcm", Password: &secret}, Parameters: map[string]string{"type": "tcp"}},
	}
	data, err := json.Marshal(descriptions)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := serial.DecodeNodeListJSONConfig(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.OutboundConfigs) != 4 {
		t.Fatal("node list lost nodes")
	}
	for i, node := range parsed.OutboundConfigs {
		if node.Tag == "" {
			t.Fatal("missing list tag")
		}
		if i > 0 && node.Tag == parsed.OutboundConfigs[i-1].Tag {
			t.Fatal("repeated tag")
		}
		if _, err := node.Build(); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []string{"subjson", "node-list"} {
		if serial.ReaderDecoderByFormat[format] == nil {
			t.Fatal("missing explicit format registration")
		}
	}
}

func TestExplicitJSONNodeListRejectsInvalidAndOversized(t *testing.T) {
	const valid = `{"version":1,"protocol":"trojan","address":"127.0.0.1","port":443,"credentials":{"password":"synthetic"}}`
	for name, input := range map[string]string{
		"empty":            "",
		"not-array":        "{}",
		"empty-array":      "[]",
		"null":             "null",
		"trailing":         "[" + valid + "]{}",
		"repeated-field":   "[" + strings.Replace(valid, `"version":1`, `"version":1,"Version":1`, 1) + "]",
		"untrusted-field":  "[" + strings.TrimSuffix(valid, "}") + `,"privateKeyFile":"secret.key"}` + "]",
		"invalid-protocol": "[" + valid + `,{"version":1,"protocol":"wireguard","address":"127.0.0.1","port":443,"credentials":{}}` + "]",
		"over-count":       "[" + strings.TrimSuffix(strings.Repeat(valid+",", 129), ",") + "]",
		"oversized":        strings.Repeat(" ", (1<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := serial.DecodeNodeListJSONConfig(strings.NewReader(input)); err == nil {
				t.Fatal("unsupported node-list input accepted")
			}
		})
	}
}

func TestExplicitJSONNodeListPreservesSingleNodeReader(t *testing.T) {
	const raw = `{"version":1,"protocol":"trojan","address":"127.0.0.1","port":443,"credentials":{"password":"synthetic"}}`
	if _, err := serial.DecodeNodeConfig(strings.NewReader(raw)); err != nil {
		t.Fatal("original node reader regressed", err)
	}
	if _, err := serial.DecodeNodeListJSONConfig(strings.NewReader(raw)); err == nil {
		t.Fatal("JSON array reader accepted a single node")
	}
	if _, err := serial.DecodeNodeConfig(strings.NewReader("[" + raw + "]")); err == nil {
		t.Fatal("single node reader accepted array")
	}
}

func TestExplicitJSONNodeListRedactsCredentials(t *testing.T) {
	const secret = "private-synthetic-password"
	input := `[{"version":1,"protocol":"trojan","address":"127.0.0.1","port":443,"credentials":{"password":"private-synthetic-password"},"unknownLocalFile":"secret.key"}]`
	if _, err := serial.DecodeNodeListJSONConfig(strings.NewReader(input)); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("bad node-list error leaked credential")
	}
}
