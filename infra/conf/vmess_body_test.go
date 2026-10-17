package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
)

func TestForkVMessExplicitBodySecurity(t *testing.T) {
	for _, test := range []struct {
		name string
		want int32
	}{{"aes-128-cfb", 1}, {"none", 5}, {"zero", 6}} {
		account := (&conf.VMessAccount{ID: "00000000-0000-4000-8000-000000000001", LegacySettings: &conf.VMessLegacySettings{Security: test.name}}).Build()
		if int32(account.SecuritySettings.Type) != test.want {
			t.Errorf("%s silently substituted: %v", test.name, account.SecuritySettings.Type)
		}
	}
}

func TestForkVMessBodyConfigurationGuards(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	for _, security := range []string{"", "auto", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb", "none", "zero", "typo"} {
		for _, alter := range []uint32{0, 1, 16, 64, 65, ^uint32(0)} {
			config := conf.VMessOutboundConfig{Address: &conf.Address{Address: net.LocalHostIP}, Port: 443, ID: id, LegacySettings: &conf.VMessLegacySettings{Security: security, AlterID: alter}}
			_, err := config.Build()
			if (err == nil) != (security != "typo" && alter <= 64) {
				t.Fatal("unexpected config acceptance", security, alter, err)
			}
			user, _ := json.Marshal(map[string]any{"id": id, "legacySettings": map[string]any{"security": security, "alterId": alter, "allowLegacyBody": true}})
			_, nestedErr := (&conf.VMessOutboundConfig{Receivers: []*conf.VMessOutboundTarget{{Address: &conf.Address{Address: net.LocalHostIP}, Port: 443, Users: []json.RawMessage{user}}}}).Build()
			if (nestedErr == nil) != (security != "typo" && alter <= 64) {
				t.Fatal("vnext user security or alterId silently substituted", security, alter, nestedErr)
			}
			server, err := (&conf.VMessInboundConfig{Clients: []json.RawMessage{user}}).Build()
			if (err == nil) != (security != "typo" && alter <= 64) {
				t.Fatal("inbound config silently substituted", security, alter, err)
			}
			if err == nil {
				value, err := server.(*inbound.Config).User[0].Account.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				if !value.(*vmess.Account).LegacyCompatibility || !value.(*vmess.Account).AllowLegacyBody || value.(*vmess.Account).AlterId != alter {
					t.Fatal("legacy inbound opt-in or alter ID lost")
				}
			}
		}
	}
	for _, security := range []string{"aes-128-cfb", "none", "zero"} {
		config := conf.VMessOutboundConfig{Address: &conf.Address{Address: net.LocalHostIP}, Port: 443, ID: id, LegacySettings: &conf.VMessLegacySettings{Security: security}, Experiments: "AuthenticatedLength"}
		if _, err := config.Build(); err == nil {
			t.Fatal("incompatible authenticated length accepted", security)
		}
	}
}
