package conf_test

import (
	"net/url"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestAddedTransportHeadersAliasFourProtocols(t *testing.T) {
	profiles := []string{
		"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"vmess://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	}
	for _, base := range profiles {
		for _, network := range []string{"ws", "httpupgrade"} {
			t.Run(base+"/"+network, func(t *testing.T) {
				link := base + "?type=" + network + "&headers=" + url.QueryEscape("{\"X-Route\":\"synthetic\"}")
				out, err := conf.ParseNodeURI(link)
				if err != nil {
					t.Fatal(err)
				}
				if network == "ws" && out.StreamSetting.WSSettings.Headers["X-Route"] != "synthetic" {
					t.Fatal("missing WS header")
				}
				if network == "httpupgrade" && out.StreamSetting.HTTPUPGRADESettings.Headers["X-Route"] != "synthetic" {
					t.Fatal("missing HTTPUpgrade header")
				}
				if _, err := out.Build(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestAddedTransportHeadersAliasRefusesConflicts(t *testing.T) {
	base := "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type="
	cases := []string{
		"tcp&headers=" + url.QueryEscape("{\"X-Route\":\"synthetic\"}"),
		"grpc&headers=" + url.QueryEscape("{\"X-Route\":\"synthetic\"}"),
		"ws&headers=" + url.QueryEscape("{\"Host\":\"bad.example\"}"),
		"httpupgrade&headers=" + url.QueryEscape("{\"Connection\":\"close\"}"),
		"ws&headers=" + url.QueryEscape("{\"X-Route\":\"one\"}") + "&wsHeaders=" + url.QueryEscape("{\"X-Route\":\"two\"}"),
	}
	for _, suffix := range cases {
		if _, err := conf.ParseNodeURI(base + suffix); err == nil {
			t.Fatal("unsafe headers alias accepted", suffix)
		}
	}
}
