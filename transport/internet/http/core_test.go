package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestForkLegacyHTTP2CoreVLESS(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	echo, err := gonet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	greeting := []byte("independent TCP server-first\n")
	go func() {
		defer close(finished)
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
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("echo peer did not join")
		}
	})
	echoPort := echo.Addr().(*gonet.TCPAddr).Port
	tunnelPort := tcp.PickPort()
	stream := map[string]any{"network": "h2c", "security": "none", "httpSettings": map[string]any{"host": []string{"tunnel.example"}, "path": "/legacy"}}
	serverConfig, _ := json.Marshal(map[string]any{
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": tunnelPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": id}}, "decryption": "none"}, "streamSettings": stream}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "port": echoPort, "ip": []string{"127.0.0.1"}}}}}},
	})
	server, err := core.StartInstance("json", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	clientConfig, _ := json.Marshal(map[string]any{
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": tunnelPort, "users": []any{map[string]any{"id": id, "encryption": "none"}}}}}, "streamSettings": stream}},
	})
	client, err := core.StartInstance("json", clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, client, net.TCPDestination(net.LocalHostIP, net.Port(echoPort)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, greeting) {
		t.Fatal("configured core server-first failed", err)
	}
	payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
	for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
		if _, err := conn.Write(piece); err != nil {
			t.Fatal(err)
		}
	}
	got = make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("configured core echo mismatch", err)
	}
}
