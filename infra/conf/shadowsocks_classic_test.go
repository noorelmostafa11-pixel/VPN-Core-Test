package conf_test

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

var classicMethods = []struct {
	name    string
	key, iv int
}{
	{"bf-cfb", 16, 8},
	{"cast5-cfb", 16, 8},
	{"des-cfb", 8, 8},
	{"rc4", 16, 0},
	{"rc4-md5", 16, 16},
	{"salsa20", 32, 8},
	{"chacha20", 32, 8},
	{"chacha20-ietf", 32, 12},
	{"table", 16, 0},
	{"none", 0, 0},
	{"plain", 0, 0},
	{"camellia-128-cfb", 16, 16},
	{"camellia-192-cfb", 24, 16},
	{"camellia-256-cfb", 32, 16},
	{"idea-cfb", 16, 8},
	{"rc2-cfb", 16, 8},
	{"seed-cfb", 16, 16},
}

func TestForkClassicConfiguration(t *testing.T) {
	for _, method := range classicMethods {
		for _, server := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/server=%t", method.name, server), func(t *testing.T) {
				var typed *shadowsocks.Account
				password := "synthetic"
				if method.key == 0 {
					password = "" // Plaintext requires explicit method, not a fake secret.
				}
				if server {
					built, err := (&conf.ShadowsocksServerConfig{Cipher: method.name, Password: password}).Build()
					if err != nil {
						t.Fatal(err)
					}
					account, err := built.(*shadowsocks.ServerConfig).Users[0].Account.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					typed = account.(*shadowsocks.Account)
				} else {
					built, err := (&conf.ShadowsocksClientConfig{Servers: []*conf.ShadowsocksServerTarget{{Address: &conf.Address{Address: net.LocalHostIP}, Port: 8388, Cipher: method.name, Password: password}}}).Build()
					if err != nil {
						t.Fatal(err)
					}
					account, err := built.(*shadowsocks.ClientConfig).Server.User.Account.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					typed = account.(*shadowsocks.Account)
				}
				account, err := typed.AsAccount()
				if err != nil {
					t.Fatal(err)
				}
				memory := account.(*shadowsocks.MemoryAccount)
				if memory.Cipher.IsAEAD() || len(memory.Key) != method.key || int(memory.Cipher.KeySize()) != method.key || int(memory.Cipher.IVSize()) != method.iv {
					t.Fatal("classic method substituted or incorrect key/IV sizes")
				}
			})
		}
	}
}

func TestForkClassicConfigurationGuards(t *testing.T) {
	for _, method := range classicMethods {
		if _, err := (&conf.ShadowsocksServerConfig{Users: []*conf.ShadowsocksUserConfig{{Cipher: method.name, Password: "synthetic"}}}).Build(); err == nil {
			t.Fatal("unauthenticated per-user list accepted", method.name)
		}
	}
	for _, method := range []string{"", "unknown", "aes-128-gcm", "aes-128-cfb", "rc4-md5", "table"} {
		if _, err := (&conf.ShadowsocksServerConfig{Cipher: method}).Build(); err == nil {
			t.Fatal("empty password or implicit plaintext accepted", method)
		}
		if _, err := (&conf.ShadowsocksClientConfig{Servers: []*conf.ShadowsocksServerTarget{{Address: &conf.Address{Address: net.LocalHostIP}, Port: 8388, Cipher: method}}}).Build(); err == nil {
			t.Fatal("client empty password or implicit plaintext accepted", method)
		}
	}
}
