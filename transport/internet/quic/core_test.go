package quic_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	headertls "github.com/xtls/xray-core/transport/internet/headers/tls"
	"github.com/xtls/xray-core/transport/internet/quic"
	"google.golang.org/protobuf/proto"
)

func TestForkLegacyQUICCoreVLESS(t *testing.T) {
	for _, format := range []string{"json", "uri", "protobuf", "node"} {
		t.Run(format, func(t *testing.T) {
			const id = "00000000-0000-4000-8000-000000000001"
			echo, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			greeting := []byte("core QUIC server-first\n")
			go func() {
				defer close(done)
				conn, err := echo.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				if _, err := conn.Write(greeting); err == nil {
					io.Copy(conn, conn)
				}
			}()
			t.Cleanup(func() {
				echo.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("echo did not join")
				}
			})
			echoPort := echo.Addr().(*net.TCPAddr).Port
			port := udp.PickPort()
			stream := map[string]any{"network": "quic", "security": "none", "quicSettings": map[string]any{"security": "aes-128-gcm", "key": "synthetic", "header": map[string]any{"type": "dtls"}}}
			serverConfig, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": id}}, "decryption": "none"}, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "port": echoPort, "ip": []string{"127.0.0.1"}}}}}}})
			serverFormat := "json"
			if format == "protobuf" {
				serverFormat = "protobuf"
				serverConfig = historicalQUICProtobuf(t, serverConfig)
			}
			server, err := core.StartInstance(serverFormat, serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			clientConfig, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"address": "127.0.0.1", "port": port, "id": id, "encryption": "none"}, "streamSettings": stream}}})
			if format == "uri" {
				clientConfig = []byte(fmt.Sprintf("vless://%s@127.0.0.1:%d?type=quic&quicsecurity=aes-128-gcm&quickey=synthetic&headerType=dtls", id, port))
			}
			if format == "protobuf" {
				clientConfig = historicalQUICProtobuf(t, clientConfig)
			}
			if format == "node" {
				clientConfig, err = json.Marshal(&conf.NodeDescription{Version: 1, Protocol: "vless", Address: "127.0.0.1", Port: uint16(port), Credentials: conf.NodeCredentials{ID: id}, Parameters: map[string]string{"type": "quic", "quicsecurity": "aes-128-gcm", "quickey": "synthetic", "headertype": "dtls"}})
				if err != nil {
					t.Fatal(err)
				}
			}
			client, err := core.StartInstance(format, clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echoPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			got := make([]byte, len(greeting))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, greeting) {
				t.Fatal("core server-first failed", err)
			}
			payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
			for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
				if n, err := conn.Write(piece); err != nil || n != len(piece) {
					t.Fatal("core upload failed", n, err)
				}
			}
			got = make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("core exact echo failed", err)
			}
		})
	}
}

// Enter through the ordinary distribution's protobuf loader, not direct
// transport calls. Both roles carry historical QUIC field 3 all the way through
// nested receiver/sender TypedMessages to the actual stream transport.
func historicalQUICProtobuf(t *testing.T, input []byte) []byte {
	t.Helper()
	config, err := core.LoadConfig("json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	converted := 0
	convertStream := func(stream *internet.StreamConfig) {
		if stream == nil {
			return
		}
		for _, transport := range stream.TransportSettings {
			if transport.ProtocolName != "quic" {
				continue
			}
			message, err := transport.Settings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			legacy := message.(*quic.Config)
			legacy.HeaderType, legacy.HeaderDomain = "", ""
			legacy.Header = serial.ToTypedMessage(&headertls.PacketConfig{})
			transport.Settings = serial.ToTypedMessage(legacy)
			converted++
		}
	}
	for _, inbound := range config.Inbound {
		message, err := inbound.ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		receiver := message.(*proxyman.ReceiverConfig)
		convertStream(receiver.StreamSettings)
		inbound.ReceiverSettings = serial.ToTypedMessage(receiver)
	}
	for _, outbound := range config.Outbound {
		message, err := outbound.SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		sender := message.(*proxyman.SenderConfig)
		convertStream(sender.StreamSettings)
		outbound.SenderSettings = serial.ToTypedMessage(sender)
	}
	if converted != 1 {
		t.Fatal("historical QUIC was not actually encoded", converted)
	}
	output, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return output
}
