package shadowsocks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"net/url"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestForkShadowsocksOriginalAndServerFirst(t *testing.T) {
	for _, method := range []shadowsocks.CipherType{shadowsocks.CipherType_AES_128_GCM, shadowsocks.CipherType_AES_256_GCM, shadowsocks.CipherType_CHACHA20_POLY1305, shadowsocks.CipherType_XCHACHA20_POLY1305, shadowsocks.CipherType_AES_192_GCM, shadowsocks.CipherType_AES_128_CFB} {
		for _, serverFirst := range []bool{false, true} {
			for _, inputFormat := range []string{"json", "uri"} {
				t.Run(fmt.Sprintf("%s/serverFirst%t/%s", method, serverFirst, inputFormat), func(t *testing.T) {
					listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close() })
					account, err := (&shadowsocks.Account{CipherType: method, Password: "synthetic"}).AsAccount()
					if err != nil {
						t.Fatal(err)
					}
					validator := new(shadowsocks.Validator)
					if err := validator.Add(&protocol.MemoryUser{Account: account}); err != nil {
						t.Fatal(err)
					}
					body := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
					greeting := []byte("server-first\n")
					done := make(chan error, 1)
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							done <- err
							return
						}
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(8 * time.Second))
						request, reader, err := shadowsocks.ReadTCPSession(validator, conn)
						if err != nil {
							done <- err
							return
						}
						if request.Address.String() != "127.0.0.1" || request.Port != 443 {
							done <- fmt.Errorf("target changed")
							return
						}
						writer, err := shadowsocks.WriteTCPResponse(request, conn)
						if err != nil {
							done <- err
							return
						}
						if serverFirst {
							if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, greeting)); err != nil {
								done <- err
								return
							}
						}
						got := make([]byte, len(body))
						if _, err := io.ReadFull(&buf.BufferedReader{Reader: reader}, got); err != nil {
							done <- err
							return
						}
						if !bytes.Equal(got, body) {
							done <- fmt.Errorf("request body changed")
							return
						}
						done <- writer.WriteMultiBuffer(buf.MergeBytes(nil, got))
					}()
					t.Cleanup(func() {
						listener.Close()
						select {
						case err := <-done:
							if err != nil {
								t.Error(err)
							}
						case <-time.After(10 * time.Second):
							t.Error("Shadowsocks test peer did not join")
						}
					})
					methodName := map[shadowsocks.CipherType]string{
						shadowsocks.CipherType_AES_128_GCM: "aes-128-gcm", shadowsocks.CipherType_AES_256_GCM: "aes-256-gcm", shadowsocks.CipherType_CHACHA20_POLY1305: "chacha20-ietf-poly1305", shadowsocks.CipherType_XCHACHA20_POLY1305: "xchacha20-ietf-poly1305", shadowsocks.CipherType_AES_192_GCM: "aes-192-gcm", shadowsocks.CipherType_AES_128_CFB: "aes-128-cfb",
					}[method]
					config, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"address": "127.0.0.1", "port": listener.Addr().(*stdnet.TCPAddr).Port, "method": methodName, "password": "synthetic", "serverFirstCompatibility": serverFirst}}}})
					if err != nil {
						t.Fatal(err)
					}
					if inputFormat == "uri" {
						config = []byte("ss://" + url.UserPassword(methodName, "synthetic").String() + "@" + listener.Addr().String())
					}
					instance, err := core.StartInstance(inputFormat, config)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { instance.Close() })
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					t.Cleanup(cancel)
					conn, err := core.Dial(ctx, instance, net.TCPDestination(net.LocalHostIP, 443))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { conn.Close() })
					if serverFirst {
						got := make([]byte, len(greeting))
						if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, greeting) {
							t.Fatal("server-first failed", err)
						}
					}
					for _, part := range [][]byte{body[:1], body[1:65], body[65:8193], body[8193:]} {
						if err := buf.WriteAllBytes(conn, part, nil); err != nil {
							t.Fatal(err)
						}
					}
					got := make([]byte, len(body))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, body) {
						t.Fatal("TCP echo changed", err)
					}
				})
			}
		}
	}
}
