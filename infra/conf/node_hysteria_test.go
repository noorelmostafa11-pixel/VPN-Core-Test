package conf_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/hysteria"
	"google.golang.org/protobuf/proto"
)

func TestNodeHysteria2AutomaticSelection(t *testing.T) {
	for _, scheme := range []string{"hy2", "hysteria2"} {
		node, err := conf.ParseNodeURI(scheme + "://synthetic@example.com/?sni=front.example")
		if err != nil {
			t.Fatal("existing Hysteria2 support is unreachable from node input", err)
		}
		if node.Protocol != "hysteria" || string(*node.StreamSetting.Network) != "hysteria" || node.StreamSetting.Security != "tls" || node.StreamSetting.HysteriaSettings.Auth != "synthetic" {
			t.Fatal("node metadata did not select original Hysteria2")
		}
	}
}

func TestNodeHysteria2EquivalentInputs(t *testing.T) {
	const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const password = "user:synthetic@password%+slash/"
	for _, scheme := range []string{"hy2", "hysteria2"} {
		for _, obfs := range []string{"", "salamander"} {
			parameters := map[string]string{"sni": "front.example", "pinSHA256": pin}
			if obfs != "" {
				parameters["obfs"], parameters["obfs-password"] = obfs, "synthetic-obfs"
			}
			secret := password
			node := &conf.NodeDescription{Version: 1, Protocol: scheme, Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{Password: &secret}, Parameters: parameters}
			selection, err := conf.ResolveNode(node)
			if err != nil || len(selection.Addons) != 0 {
				t.Fatal("original Hysteria2 was replaced with an added protocol", err)
			}
			values := url.Values{}
			for key, value := range parameters {
				values.Set(key, value)
			}
			uri := scheme + "://" + url.User(password).String() + "@127.0.0.1/?" + values.Encode()
			fromURI, err := conf.ParseNodeURI(uri)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(node)
			fromJSON, err := conf.ParseNodeJSON(data)
			if err != nil {
				t.Fatal(err)
			}
			want, err := selection.Outbound.Build()
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []*conf.OutboundDetourConfig{fromURI, fromJSON} {
				got, err := candidate.Build()
				if err != nil || !proto.Equal(got, want) {
					t.Fatal("URI/JSON/Go Hysteria2 meanings differ", err)
				}
				proxy, err := got.ProxySettings.GetInstance()
				if err != nil || proxy.(*hysteria.ClientConfig).Server.Port != 443 {
					t.Fatal("Hysteria2 default endpoint changed", err)
				}
				stream := candidate.StreamSetting
				if stream.HysteriaSettings.Auth != password || stream.TLSSettings.AllowInsecure || stream.TLSSettings.PinnedPeerCertSha256 != pin || stream.TLSSettings.ALPN == nil || fmt.Sprint(*stream.TLSSettings.ALPN) != "[h3]" {
					t.Fatal("auth or TLS metadata was changed")
				}
				if (stream.FinalMask != nil) != (obfs != "") {
					t.Fatal("obfuscation was guessed or omitted")
				}
			}
		}
	}
	// The colon-delimited userpass envelope and percent-encoded opaque auth
	// describe the same authentication bytes, without username rewriting.
	for _, credentials := range []string{"user:synthetic", "user%3Asynthetic"} {
		node, err := conf.ParseNodeURI("hy2://" + credentials + "@127.0.0.1:443")
		if err != nil || node.StreamSetting.HysteriaSettings.Auth != "user:synthetic" {
			t.Fatal("userpass URI changed authentication", err)
		}
	}
}

func TestNodeHysteria2RejectsUnsupportedMetadata(t *testing.T) {
	for _, query := range []string{
		"type=tcp", "type=quic", "security=none", "security=reality", "insecure=1", "fp=chrome", "fp=hellogolang",
		"alpn=h2", "alpn=h3%2Ch2", "pinSHA256=secret", "pinSHA256=" + strings.Repeat("a", 64) + "&pcs=" + strings.Repeat("b", 64),
		"obfs=gecko&obfs-password=secret", "obfs=unknown", "obfs-password=secret", "obfs=salamander&obfs-password=abc",
		"obfs=salamander&obfs-password=secret&obfs_password=different", "upmbps=100", "mport=443,444", "host=ignored", "path=ignored", "mode=ignored", "extra=%7B%7D", "auth=other", "unknown=secret",
	} {
		if _, err := conf.ParseNodeURI("hy2://synthetic@127.0.0.1:443?" + query); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsupported/ambiguous Hysteria2 metadata accepted or exposed", query, err)
		}
	}
	for _, input := range []string{"hysteria://synthetic@127.0.0.1:443", "hy2://127.0.0.1:443", "hy2://synthetic@127.0.0.1:0", "hy2://synthetic@127.0.0.1:443,444", "hy2://synthetic@127.0.0.1:443-444", "hy2://synthetic@127.0.0.1:443/not-a-node"} {
		if _, err := conf.ParseNodeURI(input); err == nil {
			t.Fatal("unsupported Hysteria version/auth/endpoint accepted")
		}
	}
	if _, err := conf.ParseNodeURI("vless://" + nodeID + "@127.0.0.1:443?type=hysteria"); err == nil {
		t.Fatal("unrelated node changed to Hysteria2")
	}
}
