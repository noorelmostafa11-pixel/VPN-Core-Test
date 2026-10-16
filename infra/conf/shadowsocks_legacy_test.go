package conf_test

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestForkLegacyAESConfiguration(t *testing.T) {
	for _, mode := range []string{"cfb", "ctr", "ofb"} {
		for _, bits := range []int{128, 192, 256} {
			method := fmt.Sprintf("aes-%d-%s", bits, mode)
			for _, server := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/server=%t", method, server), func(t *testing.T) {
					var raw *shadowsocks.Account
					if server {
						built, err := (&conf.ShadowsocksServerConfig{Cipher: method, Password: "synthetic"}).Build()
						if err != nil {
							t.Fatal(err)
						}
						account, err := built.(*shadowsocks.ServerConfig).Users[0].Account.GetInstance()
						if err != nil {
							t.Fatal(err)
						}
						raw = account.(*shadowsocks.Account)
					} else {
						built, err := (&conf.ShadowsocksClientConfig{Servers: []*conf.ShadowsocksServerTarget{{Address: &conf.Address{Address: net.LocalHostIP}, Port: 8388, Cipher: method, Password: "synthetic"}}}).Build()
						if err != nil {
							t.Fatal(err)
						}
						account, err := built.(*shadowsocks.ClientConfig).Server.User.Account.GetInstance()
						if err != nil {
							t.Fatal(err)
						}
						raw = account.(*shadowsocks.Account)
					}
					account, err := raw.AsAccount()
					if err != nil {
						t.Fatal(err)
					}
					memory := account.(*shadowsocks.MemoryAccount)
					if memory.Cipher.IsAEAD() || len(memory.Key) != bits/8 || memory.Cipher.IVSize() != 16 {
						t.Fatal("legacy AES method was substituted or has incorrect parameters")
					}
				})
			}
		}
	}
}

func TestForkLegacyAESMultiUserRejected(t *testing.T) {
	for _, method := range []string{"aes-128-cfb", "aes-192-ctr", "aes-256-ofb"} {
		if _, err := (&conf.ShadowsocksServerConfig{Users: []*conf.ShadowsocksUserConfig{{Cipher: method, Password: "synthetic"}}}).Build(); err == nil {
			t.Fatal("unauthenticated cipher accepted in multi-user configuration", method)
		}
	}
}
