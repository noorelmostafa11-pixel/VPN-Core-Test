package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestForkAES192GCMConfiguration(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		config := &ShadowsocksClientConfig{Servers: []*ShadowsocksServerTarget{{
			Address: &Address{Address: net.LocalHostIP}, Port: 8388,
			Cipher: "aes-192-gcm", Password: "test",
		}}}
		built, err := config.Build()
		if err != nil {
			t.Fatal(err)
		}
		account, err := built.(*shadowsocks.ClientConfig).Server.User.Account.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		memory, err := account.(*shadowsocks.Account).AsAccount()
		if err != nil || len(memory.(*shadowsocks.MemoryAccount).Key) != 24 {
			t.Fatal("AES192 client did not retain its 24-byte key", err)
		}
	})
	for _, multiple := range []bool{false, true} {
		name := "server"
		if multiple {
			name = "multi-user-server"
		}
		t.Run(name, func(t *testing.T) {
			config := &ShadowsocksServerConfig{Cipher: "aes-192-gcm", Password: "test"}
			if multiple {
				config.Users = []*ShadowsocksUserConfig{{Cipher: "aes-192-gcm", Password: "test", Email: "synthetic@example.invalid"}}
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			account, err := built.(*shadowsocks.ServerConfig).Users[0].Account.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			memory, err := account.(*shadowsocks.Account).AsAccount()
			if err != nil || len(memory.(*shadowsocks.MemoryAccount).Key) != 24 {
				t.Fatal("AES192 server did not retain its 24-byte key", err)
			}
		})
	}
}
