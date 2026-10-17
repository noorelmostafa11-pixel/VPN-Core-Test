package conf_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

// This file uses only APIs present at pinned upstream 701af607. Run the exact
// same source against that revision and the fork; do not derive expectations
// from the fork's new configuration builders.
func TestOriginalVMessConfiguration(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	for _, security := range []string{"", "auto", "AUTO", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb", "none", "zero", "typo"} {
		want := protocol.SecurityType_AUTO
		if security == "aes-128-gcm" {
			want = protocol.SecurityType_AES128_GCM
		} else if security == "chacha20-poly1305" {
			want = protocol.SecurityType_CHACHA20_POLY1305
		}
		for _, alter := range []string{"0", "16", "64", "65", "4294967295", "-1", `"ignored"`, "true", "{}"} {
			t.Run(security+"/"+alter, func(t *testing.T) {
				user := fmt.Sprintf(`{"id":%q,"security":%q,"alterId":%s,"allowLegacyBody":"ignored","experiments":"AuthenticatedLength"}`, id, security, alter)
				wantAccount := &vmess.Account{Id: id, SecuritySettings: &protocol.SecurityConfig{Type: want}, TestsEnabled: "AuthenticatedLength"}
				for _, settings := range []string{
					fmt.Sprintf(`{"address":"127.0.0.1","port":443,"id":%q,"security":%q,"alterId":%s,"experiments":"AuthenticatedLength"}`, id, security, alter),
					`{"vnext":[{"address":"127.0.0.1","port":443,"users":[` + user + `]}]}`,
				} {
					var c conf.VMessOutboundConfig
					if err := json.Unmarshal([]byte(settings), &c); err != nil {
						t.Fatal("previously ignored alterId rejected", err)
					}
					built, err := c.Build()
					if err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(built.(*outbound.Config).Receiver.User.Account, serial.ToTypedMessage(wantAccount)) {
						t.Fatal("original outbound account changed", built)
					}
				}
				built, err := (&conf.VMessInboundConfig{Clients: []json.RawMessage{json.RawMessage(user)}}).Build()
				if err != nil || !proto.Equal(built.(*inbound.Config).User[0].Account, serial.ToTypedMessage(wantAccount)) {
					t.Fatal("original inbound account changed", err, built)
				}
			})
		}
	}
}

func TestOriginalSOCKSConfiguration(t *testing.T) {
	for _, version := range []string{`"4"`, `"4a"`, `"5"`, `"6"`, `"unknown"`, "4", "{}", "true"} {
		for _, port := range []int{0, 1080} {
			for _, nested := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/%t", version, port, nested), func(t *testing.T) {
					settings := fmt.Sprintf(`{"version":%s,"address":"127.0.0.1","port":%d,"user":"synthetic","pass":"secret"}`, version, port)
					if nested {
						settings = fmt.Sprintf(`{"version":%s,"servers":[{"address":"127.0.0.1","port":%d,"users":[{"user":"synthetic","pass":"secret"}]}]}`, version, port)
					}
					var c conf.SocksClientConfig
					if err := json.Unmarshal([]byte(settings), &c); err != nil {
						t.Fatal(err)
					}
					got, err := c.Build()
					want := &socks.ClientConfig{Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(&socks.Account{Username: "synthetic", Password: "secret"})}}}
					if err != nil || !proto.Equal(got, want) {
						t.Fatal("original SOCKS5 config changed", err, got)
					}
				})
			}
		}
	}
}

func TestOriginalInactiveHTTPSettings(t *testing.T) {
	for _, network := range []string{"tcp", "raw", "xhttp", "ws", "grpc"} {
		for _, ignored := range []string{`{"method":"invalid method","path":"bad"}`, `{"host":true}`, `"ignored"`, "[]"} {
			t.Run(network+"/"+ignored, func(t *testing.T) {
				build := func(extra string) proto.Message {
					var c conf.StreamConfig
					if err := json.Unmarshal([]byte(fmt.Sprintf(`{"network":%q%s}`, network, extra)), &c); err != nil {
						t.Fatal(err)
					}
					got, err := c.Build()
					if err != nil {
						t.Fatal(err)
					}
					return got
				}
				if !proto.Equal(build(",\"httpSettings\":"+ignored), build("")) {
					t.Fatal("inactive HTTP2 settings changed an original transport")
				}
			})
		}
	}
}

func TestOriginalShadowsocksAccountEquality(t *testing.T) {
	for _, left := range []shadowsocks.CipherType{shadowsocks.CipherType_AES_256_GCM, shadowsocks.CipherType_CHACHA20_POLY1305, shadowsocks.CipherType_XCHACHA20_POLY1305} {
		for _, right := range []shadowsocks.CipherType{shadowsocks.CipherType_AES_256_GCM, shadowsocks.CipherType_CHACHA20_POLY1305, shadowsocks.CipherType_XCHACHA20_POLY1305} {
			a, err := (&shadowsocks.Account{CipherType: left, Password: "synthetic"}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			b, err := (&shadowsocks.Account{CipherType: right, Password: "synthetic"}).AsAccount()
			if err != nil || !a.Equals(b) || !b.Equals(a) {
				t.Fatal("original key-based equality changed", left, right, err)
			}
		}
	}
}

func TestOriginalSOCKSHandshakeAPI(t *testing.T) {
	for _, version := range []byte{0, 4, 5, 255} {
		var wire bytes.Buffer
		request := &protocol.RequestHeader{Version: version, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 443}
		reply := []byte{5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 1, 187}
		response, err := socks.ClientHandshake(request, bytes.NewReader(reply), &wire)
		want := []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187}
		if err != nil || response != nil || !bytes.Equal(wire.Bytes(), want) {
			t.Fatal("original SOCKS5 handshake API changed", version, err, wire.Bytes())
		}
	}
}
