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

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestForkLegacyQUICCoreVLESS(t *testing.T) {
	for _, format := range []string{"json", "uri"} {
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
			port := tcp.PickPort()
			stream := map[string]any{"network": "quic", "security": "none", "quicSettings": map[string]any{"security": "aes-128-gcm", "key": "synthetic", "header": map[string]any{"type": "dtls"}}}
			serverConfig, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": id}}, "decryption": "none"}, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "port": echoPort, "ip": []string{"127.0.0.1"}}}}}}})
			server, err := core.StartInstance("json", serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			clientConfig, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"address": "127.0.0.1", "port": port, "id": id, "encryption": "none"}, "streamSettings": stream}}})
			if format == "uri" {
				clientConfig = []byte(fmt.Sprintf("vless://%s@127.0.0.1:%d?type=quic&quicsecurity=aes-128-gcm&quickey=synthetic&headerType=dtls", id, port))
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
