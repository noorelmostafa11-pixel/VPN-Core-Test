package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
)

const nodeID = "00000000-0000-4000-8000-000000000001"

func nodeVMessURI(t *testing.T, cipher string, count uint32) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"v": "2", "ps": "synthetic", "add": "127.0.0.1", "port": "443", "id": nodeID, "aid": count, "scy": cipher, "net": "tcp", "type": "none", "tls": ""})
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.RawStdEncoding.EncodeToString(data)
}

func TestNodeVMessAutomaticSelection(t *testing.T) {
	for _, cipher := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb", "none", "zero"} {
		for _, count := range []uint32{0, 16, 64} {
			for _, envelope := range []string{"json-link", "userinfo-link"} {
				t.Run(fmt.Sprintf("%s/%d/%s", cipher, count, envelope), func(t *testing.T) {
					input := nodeVMessURI(t, cipher, count)
					if envelope == "userinfo-link" {
						input = fmt.Sprintf("vmess://%s@127.0.0.1:443?encryption=%s&aid=%d", nodeID, cipher, count)
					}
					node, err := conf.ParseNodeURI(input)
					if err != nil {
						t.Fatal(err)
					}
					built, err := node.Build()
					if err != nil {
						t.Fatal(err)
					}
					proxy, err := built.ProxySettings.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					value, err := proxy.(*outbound.Config).Receiver.User.Account.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					account := value.(*vmess.Account)
					weak := cipher == "none" || cipher == "zero" || cipher == "aes-128-cfb"
					if account.AlterId != count || account.LegacyCompatibility != (weak || count != 0) || account.AllowLegacyBody {
						t.Fatal("node did not select exactly its own header/body mode")
					}
					want := map[string]protocol.SecurityType{"auto": protocol.SecurityType_AUTO, "aes-128-gcm": protocol.SecurityType_AES128_GCM, "chacha20-poly1305": protocol.SecurityType_CHACHA20_POLY1305, "aes-128-cfb": protocol.SecurityType_AES128_CFB, "none": protocol.SecurityType_NONE, "zero": protocol.SecurityType_ZERO}[cipher]
					if account.SecuritySettings.Type != want {
						t.Fatal("body cipher substituted")
					}
				})
			}
		}
	}
}

func TestNodeShadowsocksCredentialsAndMethods(t *testing.T) {
	methods := []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-ofb", "aes-192-ofb", "aes-256-ofb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "rc4", "rc4-md5", "salsa20", "chacha20", "chacha20-ietf", "table", "none", "plain"}
	for _, method := range methods {
		for _, envelope := range []string{"userinfo", "base64-user", "base64-all"} {
			t.Run(method+"/"+envelope, func(t *testing.T) {
				const password = "synthetic@with:colon%+and/slash"
				auth := method + ":" + password
				input := "ss://" + url.UserPassword(method, password).String() + "@127.0.0.1:443#node"
				if envelope == "base64-user" {
					input = "ss://" + base64.RawURLEncoding.EncodeToString([]byte(auth)) + "@127.0.0.1:443#node"
				} else if envelope == "base64-all" {
					input = "ss://" + base64.StdEncoding.EncodeToString([]byte(auth+"@127.0.0.1:443")) + "#node"
				}
				node, err := conf.ParseNodeURI(input)
				if err != nil {
					t.Fatal(err)
				}
				built, err := node.Build()
				if err != nil {
					t.Fatal(err)
				}
				proxy, _ := built.ProxySettings.GetInstance()
				client := proxy.(*shadowsocks.ClientConfig)
				account, err := client.Server.User.Account.GetInstance()
				if err != nil || account.(*shadowsocks.Account).Password != password || !client.ServerFirstCompatibility {
					t.Fatal("credentials altered or automatic server-first support missing", err)
				}
			})
		}
	}
}

func TestNodeOriginalAndAddedTransports(t *testing.T) {
	for _, network := range []string{"tcp", "raw", "ws", "websocket", "httpupgrade", "grpc", "xhttp", "splithttp", "http", "h2", "http2", "h2c", "kcp", "mkcp"} {
		node, err := conf.ParseNodeURI("vless://" + nodeID + "@127.0.0.1:443?type=" + network)
		if err != nil {
			t.Fatal(network, err)
		}
		if _, err := node.Build(); err != nil {
			t.Fatal(network, err)
		}
	}
	for _, scheme := range []string{"socks", "socks5", "socks4", "socks4a", "http", "https", "trojan"} {
		node, err := conf.ParseNodeURI(scheme + "://synthetic@127.0.0.1:443")
		if err != nil {
			t.Fatal(scheme, err)
		}
		if scheme == "trojan" || scheme == "https" {
			if node.StreamSetting.Security != "tls" || node.StreamSetting.TLSSettings.AllowInsecure {
				t.Fatal("default TLS policy weakened", scheme)
			}
		}
		if scheme == "socks4" || scheme == "socks4a" {
			built, _ := node.Build()
			value, _ := built.ProxySettings.GetInstance()
			want := socks.ClientVersion_SOCKS4
			if scheme == "socks4a" {
				want = socks.ClientVersion_SOCKS4A
			}
			if value.(*socks.ClientConfig).Version != want {
				t.Fatal("SOCKS version substituted")
			}
		}
	}
}

func TestNodeSecurityMetadataPreserved(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	input := "vless://" + nodeID + "@127.0.0.1:443?security=reality&sni=example.invalid&fp=chrome&pbk=" + key + "&sid=ab&flow=xtls-rprx-vision"
	node, err := conf.ParseNodeURI(input)
	if err != nil || node.StreamSetting.Security != "reality" || node.StreamSetting.REALITYSettings.PublicKey != key || node.StreamSetting.REALITYSettings.ShortId != "ab" {
		t.Fatal("REALITY parameters changed", err)
	}
	for _, path := range []string{"/%zz", "//another.invalid/path", "/path#fragment"} {
		if _, err := conf.ParseNodeURI(input + "&spx=" + url.QueryEscape(path)); err == nil {
			t.Fatal("invalid REALITY spider target accepted")
		}
	}
	node, err = conf.ParseNodeURI("vless://" + nodeID + "@example.invalid:443?security=tls&sni=front.invalid&alpn=h2%2Chttp%2F1.1&fp=chrome&type=ws&host=authority.invalid&path=%2Fa%3Fkey%3Dvalue")
	if err != nil || node.StreamSetting.TLSSettings.AllowInsecure || node.StreamSetting.TLSSettings.ServerName != "front.invalid" || len(*node.StreamSetting.TLSSettings.ALPN) != 2 || node.StreamSetting.WSSettings.Host != "authority.invalid" || node.StreamSetting.WSSettings.Path != "/a?key=value" {
		t.Fatal("TLS/host/path selection changed", err)
	}
	for _, extra := range []string{`{"downloadSettings":{"tlsSettings":{"certificates":[{"keyFile":"private.key"}]}}}`, `{"unknown":true}`, `{"xmux":{"unknown":1}}`} {
		if _, err := conf.ParseNodeURI("vless://" + nodeID + "@127.0.0.1:443?type=xhttp&extra=" + url.QueryEscape(extra)); err == nil {
			t.Fatal("untrusted URI extra admitted arbitrary configuration")
		}
	}
}

func TestNodeMalformedAndAmbiguousInputs(t *testing.T) {
	for index, input := range []string{
		"", "not-a-node", "socks4a://127.0.0.1:0", "socks4://user:secret@127.0.0.1:1080", "socks5://:secret@127.0.0.1:1080",
		"socks4a://127.0.0.1:65536", "socks4a://127.0.0.1:1?unknown=secret", "socks4a://127.0.0.1:1?security=tls&security=none",
		"ss://YWVzLTEyOC1nY206c2VjcmV0@127.0.0.1:443?plugin=not-implemented", "ss://bad-secret-profile", "ss://aes-128-gcm:%FF@127.0.0.1:443",
		"vmess://" + nodeID + "@127.0.0.1:443?encryption=typo", "vmess://" + nodeID + "@127.0.0.1:443?aid=65", "vmess://" + nodeID + "@127.0.0.1:443?aid=1&alterId=2",
		"vless://" + nodeID + "@1.1.1.1:443?security=none", "vless://" + nodeID + "@127.0.0.1:443?type=h2c&security=tls", "vless://" + nodeID + "@127.0.0.1:443?type=quic&quicsecurity=unknown",
		"vless://" + nodeID + "@127.0.0.1:443?security=tls&pbk=secret", "vless://" + nodeID + "@127.0.0.1:443?sni=secret", "vless://" + nodeID + "@127.0.0.1:443?type=ws&extra=%7B%7D",
		"vless://" + nodeID + "@127.0.0.1:443?type=ws&mode=packet-up", "vless://" + nodeID + "@127.0.0.1:443?type=tcp&path=ignored", "vless://" + nodeID + "@127.0.0.1:443?type=grpc&mode=invalid",
		"trojan://secret@127.0.0.1:443?security=invalid", "trojan://secret@127.0.0.1:443?security=tls&insecure=invalid", "trojan://secret@127.0.0.1:443#%0Abad",
		"trojan://secret@127.0.0.1:bad", "trojan://secret@127.0.0.1:443?%zz", "tuic://secret@127.0.0.1:443", strings.Repeat("x", conf.MaxNodeURIBytes+1),
	} {
		if _, err := conf.ParseNodeURI(input); err == nil {
			t.Fatal("malformed or unsupported node was silently accepted", index)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), nodeID) {
			t.Fatal("import error exposed credentials")
		}
	}
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"add":"127.0.0.1","port":443,"id":"` + nodeID + `","aid":0,"aid":16}`,
		`{"add":"127.0.0.1","port":443,"id":"` + nodeID + `","ALPN":"h2","alpn":"http/1.1"}`,
		`{"add":"127.0.0.1","port":443,"id":"` + nodeID + `"} {}`,
	} {
		if _, err := conf.ParseNodeURI("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(body))); err == nil {
			t.Fatal("malformed VMess envelope accepted")
		}
	}
}

func TestNodeConcurrentSelection(t *testing.T) {
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			for range 4 {
				if _, err := conf.ParseNodeURI("socks4a://synthetic@127.0.0.1:1080"); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
}

func FuzzNodeURI(f *testing.F) {
	f.Add("hy2://synthetic@127.0.0.1/?sni=node-hy.example")
	f.Add("hysteria2://user:synthetic@127.0.0.1:443?obfs=salamander&obfs-password=synthetic-obfs")
	for _, seed := range []string{"", "socks4a://127.0.0.1:1080", "ss://YWVzLTEyOC1nY206c3ludGhldGlj@127.0.0.1:443", "vless://" + nodeID + "@127.0.0.1:443?type=ws", "vmess://" + nodeID + "@127.0.0.1:443?aid=16&encryption=aes-128-cfb", "trojan://synthetic@127.0.0.1:443"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		node, err := conf.ParseNodeURI(input)
		if err == nil {
			if node == nil {
				t.Fatal("successful import without a node")
			}
			if _, err := node.Build(); err != nil {
				t.Fatal("import returned an invalid configuration", err)
			}
		}
	})
}
