package encoding_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
)

func TestForkVMessLegacyOutboundServerFirst(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	for _, alter := range []uint32{0, 16, 64} {
		for _, security := range []string{"aes-128-cfb", "none", "zero", "aes-128-gcm", "chacha20-poly1305"} {
			for _, legacy := range []bool{false, true} {
				formats := []string{"json"}
				if legacy {
					formats = append(formats, "uri")
				}
				for _, inputFormat := range formats {
					t.Run(fmt.Sprintf("%s/alter%d/legacy%t/%s", security, alter, legacy, inputFormat), func(t *testing.T) {
						listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { listener.Close() })
						account, err := (&vmess.Account{Id: id, LegacyCompatibility: legacy, AllowLegacyBody: legacy, AlterId: alter}).AsAccount()
						if err != nil {
							t.Fatal(err)
						}
						validator := vmess.NewTimedUserValidator()
						if err := validator.Add(&protocol.MemoryUser{Account: account}); err != nil {
							t.Fatal(err)
						}
						history := encoding.NewSessionHistory()
						t.Cleanup(func() { history.Close() })
						greeting := []byte("server-first\n")
						body := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
						done := make(chan error, 1)
						go func() {
							conn, err := listener.Accept()
							if err != nil {
								done <- err
								return
							}
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(8 * time.Second))
							server := encoding.NewServerSession(validator, history)
							request, err := server.DecodeRequestHeader(conn, false)
							if err != nil {
								done <- err
								return
							}
							want := protocol.SecurityType_NONE
							if security == "aes-128-cfb" {
								want = protocol.SecurityType_AES128_CFB
							} else if security == "aes-128-gcm" {
								want = protocol.SecurityType_AES128_GCM
							} else if security == "chacha20-poly1305" {
								want = protocol.SecurityType_CHACHA20_POLY1305
							}
							if !legacy && security != "aes-128-gcm" && security != "chacha20-poly1305" {
								want = (&protocol.SecurityConfig{Type: protocol.SecurityType_AUTO}).GetSecurityType()
							}
							if request.Security != want || request.Address.String() != "127.0.0.1" || request.Port != 443 {
								done <- fmt.Errorf("body/target selection mismatch")
								return
							}
							if legacy && security == "zero" && request.Option != 0 {
								done <- fmt.Errorf("zero not sent as raw NONE")
								return
							}
							server.EncodeResponseHeader(&protocol.ResponseHeader{}, conn)
							writer, err := server.EncodeResponseBody(request, conn)
							if err != nil {
								done <- err
								return
							}
							if err = writer.WriteMultiBuffer(buf.MergeBytes(nil, greeting)); err != nil {
								done <- err
								return
							}
							reader, err := server.DecodeRequestBody(request, conn)
							if err != nil {
								done <- err
								return
							}
							got := make([]byte, len(body))
							if _, err = io.ReadFull(&buf.BufferedReader{Reader: reader}, got); err != nil {
								done <- err
								return
							}
							if !bytes.Equal(got, body) {
								done <- fmt.Errorf("request payload changed")
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
								t.Error("VMess test peer did not join")
							}
						})
						settings := map[string]any{"address": "127.0.0.1", "port": listener.Addr().(*stdnet.TCPAddr).Port, "id": id, "security": security, "alterId": alter}
						if legacy {
							settings["legacySettings"] = map[string]any{"security": security, "alterId": alter}
						}
						config, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "vmess", "settings": settings}}})
						if err != nil {
							t.Fatal(err)
						}
						if inputFormat == "uri" {
							profile, err := json.Marshal(map[string]any{"add": "127.0.0.1", "port": listener.Addr().(*stdnet.TCPAddr).Port, "id": id, "scy": security, "aid": alter, "net": "tcp"})
							if err != nil {
								t.Fatal(err)
							}
							config = []byte("vmess://" + base64.RawStdEncoding.EncodeToString(profile))
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
						got := make([]byte, len(greeting))
						if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, greeting) {
							t.Fatal("server-first failed", err)
						}
						for _, piece := range [][]byte{body[:1], body[1:65], body[65:8193], body[8193:]} {
							if err := buf.WriteAllBytes(conn, piece, nil); err != nil {
								t.Fatal(err)
							}
						}
						got = make([]byte, len(body))
						if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, body) {
							t.Fatal("TCP echo mismatch", err)
						}
					})
				}
			}
		}
	}
}
