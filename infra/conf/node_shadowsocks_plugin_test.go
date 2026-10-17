package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

func ssPluginURI(base, plugin string) string {
	return base + "?plugin=" + url.QueryEscape(plugin)
}

func TestSSPluginBasicWSParityAndSS2022(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	for _, base := range []string{
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
		"ss://aes-192-gcm:synthetic@127.0.0.1:443",
		"ss://" + url.UserPassword("2022-blake3-aes-128-gcm", key).String() + "@127.0.0.1:443",
	} {
		for _, plugin := range []string{
			"v2ray-plugin",
			"v2ray-plugin;mode=websocket;host=front.example.invalid;path=/edge",
			"v2ray-plugin;tls;mode=websocket;host=front.example.invalid;path=/edge",
		} {
			t.Run(strings.Split(base, "@")[0]+"/"+plugin, func(t *testing.T) {
				got, err := conf.ParseNodeURI(ssPluginURI(base, plugin))
				if err != nil {
					t.Fatal(err)
				}
				expected := base + "?type=ws"
				if strings.Contains(plugin, "host=") {
					expected += "&host=front.example.invalid"
				}
				if strings.Contains(plugin, "path=") {
					expected += "&path=%2Fedge"
				}
				if strings.Contains(plugin, ";tls") {
					expected += "&security=tls&sni=front.example.invalid"
				}
				want, err := conf.ParseNodeURI(expected)
				if err != nil {
					t.Fatal(err)
				}
				a, err := got.Build()
				if err != nil {
					t.Fatal(err)
				}
				b, err := want.Build()
				if err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(a, b) {
					t.Fatal("plugin mapped to different wire transport settings")
				}
			})
		}
	}
}

func TestSSPluginNodeJSONAndURIParity(t *testing.T) {
	base := "ss://aes-128-gcm:synthetic@127.0.0.1:443"
	plugin := "v2ray-plugin;tls;host=front.example.invalid;path=/secure"
	got, err := conf.ParseNodeURI(ssPluginURI(base, plugin))
	if err != nil {
		t.Fatal(err)
	}
	pass := "synthetic"
	desc := conf.NodeDescription{
		Version: 1, Protocol: "ss", Address: "127.0.0.1", Port: 443,
		Credentials: conf.NodeCredentials{Method: "aes-128-gcm", Password: &pass},
		Parameters:  map[string]string{"plugin": plugin},
	}
	x, err := json.Marshal(desc)
	if err != nil {
		t.Fatal(err)
	}
	node, err := conf.ParseNodeJSON(x)
	if err != nil {
		t.Fatal(err)
	}
	a, err := got.Build()
	if err != nil {
		t.Fatal(err)
	}
	b, err := node.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(a, b) {
		t.Fatal("URI and structured node plugin selection differ")
	}
}

func TestSSPluginExistingNodesUnchanged(t *testing.T) {
	base := "ss://aes-128-gcm:synthetic@127.0.0.1:443"
	for _, uri := range []string{base, base + "?type=tcp", base + "?type=ws&host=front.example.invalid&path=/edge", base + "?type=xhttp"} {
		t.Run(uri, func(t *testing.T) {
			got, err := conf.ParseNodeURI(uri)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := got.Build(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSPluginRejectsUnsafeAndUnsupported(t *testing.T) {
	base := "ss://aes-128-gcm:synthetic@127.0.0.1:443"
	cases := map[string]string{
		"empty":                 "",
		"binary-name":           "../../shell",
		"unknown-plugin":        "obfs-local;obfs=http",
		"unknown-simple-obfs":   "simple-obfs;obfs=tls",
		"unsupported-quic-mode": "v2ray-plugin;mode=quic",
		"external-tls-key":      "v2ray-plugin;cert=/private.key",
		"mux":                   "v2ray-plugin;mux",
		"unlisted-option":       "v2ray-plugin;server=127.0.0.1",
		"unknown-flag":          "v2ray-plugin;tls=true",
		"empty-segment":         "v2ray-plugin;;tls",
		"duplicate-flag":        "v2ray-plugin;tls;tls",
		"duplicate-host":        "v2ray-plugin;host=a.example;host=b.example",
		"injection-host":        "v2ray-plugin;host=good.example\r\nInjected: 1",
		"file-host":             "v2ray-plugin;host=env:SECRET",
		"path-with-query":       "v2ray-plugin;path=/edge?ed=1024",
		"path-with-fragment":    "v2ray-plugin;path=/edge#fragment",
		"path-with-authority":   "v2ray-plugin;path=//unexpected.example/path",
		"oversize":              "v2ray-plugin;host=" + strings.Repeat("a", 2049),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := conf.ParseNodeURI(ssPluginURI(base, p)); err == nil {
				t.Fatal("unsafe or unsupported plugin accepted")
			}
		})
	}
	for name, tail := range map[string]string{
		"explicit-network":     "&type=tcp",
		"explicit-tls":         "&security=tls",
		"explicit-host":        "&host=other.example",
		"insecure-policy":      "&allowInsecure=true",
		"explicit-fingerprint": "&fp=chrome",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := conf.ParseNodeURI(ssPluginURI(base, "v2ray-plugin;tls;host=front.example.invalid") + tail); err == nil {
				t.Fatal("conflicting settings accepted")
			}
		})
	}
	for name, uri := range map[string]string{
		"vless":  "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"vmess":  "vmess://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"trojan": "trojan://synthetic@127.0.0.1:443",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := conf.ParseNodeURI(ssPluginURI(uri, "v2ray-plugin;tls")); err == nil {
				t.Fatal("plugin incorrectly accepted for another protocol")
			}
		})
	}
}

func TestSSPluginBase64ShareURIParity(t *testing.T) {
	plain := "ss://aes-128-gcm:synthetic@127.0.0.1:443"
	plugin := "v2ray-plugin;tls;host=front.example.invalid;path=/edge"
	want, err := conf.ParseNodeURI(ssPluginURI(plain, plugin))
	if err != nil {
		t.Fatal(err)
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:synthetic"))
	full := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:synthetic@127.0.0.1:443"))
	for _, base := range []string{
		"ss://" + userinfo + "@127.0.0.1:443",
		"ss://" + full,
	} {
		t.Run(base, func(t *testing.T) {
			got, err := conf.ParseNodeURI(ssPluginURI(base, plugin))
			if err != nil {
				t.Fatal(err)
			}
			a, err := got.Build()
			if err != nil {
				t.Fatal(err)
			}
			b, err := want.Build()
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(a, b) {
				t.Fatal("base64 Shadowsocks share-link plugin conversion differs")
			}
		})
	}
}
