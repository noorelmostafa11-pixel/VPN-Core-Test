package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/socks"
)

func TestForkLegacySocksConfiguration(t *testing.T) {
	for _, protocol := range []string{"socks4", "socks4a"} {
		t.Run(protocol, func(t *testing.T) {
			settings := json.RawMessage(`{"address":"127.0.0.1","port":1080,"user":"synthetic"}`)
			built, err := (&conf.OutboundDetourConfig{Protocol: protocol, Settings: &settings}).Build()
			if err != nil {
				t.Fatal(err)
			}
			value, err := built.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			want := socks.ClientVersion_SOCKS4
			if protocol == "socks4a" {
				want = socks.ClientVersion_SOCKS4A
			}
			if value.(*socks.ClientConfig).Version != want {
				t.Fatal("version silently substituted")
			}
		})
	}
}

func TestForkLegacySocksVersionAndGuards(t *testing.T) {
	for _, version := range []string{"", "5", "4", "4a", "4A", "6", "unknown"} {
		for _, flat := range []bool{true, false} {
			settings := `{"version":"` + version + `","address":"127.0.0.1","port":1080,"user":"synthetic"}`
			if !flat {
				settings = `{"version":"` + version + `","servers":[{"address":"127.0.0.1","port":1080,"users":[{"user":"synthetic"}]}]}`
			}
			var config conf.SocksClientConfig
			if err := json.Unmarshal([]byte(settings), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			valid := version == "" || version == "5" || version == "4" || strings.EqualFold(version, "4a")
			if (err == nil) != valid {
				t.Fatal("version acceptance changed", version, flat, err)
			}
			if !valid {
				continue
			}
			want := socks.ClientVersion_SOCKS5
			if version == "4" {
				want = socks.ClientVersion_SOCKS4
			} else if strings.EqualFold(version, "4a") {
				want = socks.ClientVersion_SOCKS4A
			}
			if built.(*socks.ClientConfig).Version != want {
				t.Fatal("wrong selected version", version, flat)
			}
		}
	}
	for _, version := range []string{"4", "4a"} {
		for _, test := range []struct {
			user, password string
			valid          bool
		}{
			{"", "", true},
			{strings.Repeat("u", 255), "", true},
			{strings.Repeat("u", 256), "", false},
			{"bad\x00id", "", false},
			{"bad\r\nid", "", false},
			{"user", "not-auth", false},
			{"", "not-auth", false},
		} {
			config := conf.SocksClientConfig{Version: version, Address: &conf.Address{Address: net.LocalHostIP}, Port: 1080, Username: test.user, Password: test.password}
			if _, err := config.Build(); (err == nil) != test.valid {
				t.Fatal("legacy credential policy mismatch", version, err)
			}
		}
	}
	for _, protocol := range []string{"socks4", "socks4a"} {
		settings := json.RawMessage(`{"version":"5","address":"127.0.0.1","port":1080}`)
		if _, err := (&conf.OutboundDetourConfig{Protocol: protocol, Settings: &settings}).Build(); err == nil {
			t.Fatal("alias/version conflict accepted")
		}
	}
}
