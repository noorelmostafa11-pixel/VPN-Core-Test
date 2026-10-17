package http_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestForkLegacyHTTP2CoreVLESS(t *testing.T) {
	for _, inputFormat := range []string{"json", "uri", "node"} {
		t.Run(inputFormat, func(t *testing.T) { testLegacyHTTP2CoreVLESS(t, inputFormat, "h2c") })
	}
}

func TestForkHTTP2RealityCoreVLESS(t *testing.T) {
	for _, mode := range []string{"h2", "tcp"} {
		for _, format := range []string{"json", "uri", "node"} {
			t.Run(mode+"/"+format, func(t *testing.T) { testLegacyHTTP2CoreVLESS(t, format, mode) })
		}
	}
}

func coreRealitySettings(t *testing.T) (map[string]any, map[string]any, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("application request reached REALITY target")
		w.WriteHeader(404)
	}))
	target.EnableHTTP2 = true
	target.TLS = &gotls.Config{MinVersion: gotls.VersionTLS13, CurvePreferences: []gotls.CurveID{gotls.X25519}}
	target.StartTLS()
	t.Cleanup(target.Close)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	server := map[string]any{"target": target.Listener.Addr().String(), "serverNames": []string{"reality.example"}, "privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"0102030405060708"}}
	client := map[string]any{"serverName": "reality.example", "fingerprint": "chrome", "publicKey": publicKey, "shortId": "0102030405060708"}
	config := &reality.Config{Type: "tcp", Dest: target.Listener.Addr().String(), ServerNames: []string{"reality.example"}, PrivateKey: key.Bytes(), ShortIds: [][]byte{{1, 2, 3, 4, 5, 6, 7, 8}}}
	goreality.DetectPostHandshakeRecordsLens(config.GetREALITYConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		value, _ := goreality.GlobalPostHandshakeRecordsLens.Load(config.Dest + " reality.example 2")
		if _, ready := value.([]int); ready {
			return server, client, publicKey
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("core REALITY target detection did not complete")
		}
	}
}

func testLegacyHTTP2CoreVLESS(t *testing.T, inputFormat, mode string) {
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
	stream := map[string]any{"network": mode, "security": "none", "httpSettings": map[string]any{"host": []string{"tunnel.example"}, "path": "/legacy"}}
	clientStream := stream
	query := url.Values{"type": {mode}}
	if mode != "tcp" {
		query.Set("host", "tunnel.example")
		query.Set("path", "/legacy")
	}
	if mode != "h2c" {
		serverSecurity, clientSecurity, publicKey := coreRealitySettings(t)
		stream["security"], stream["realitySettings"] = "reality", serverSecurity
		clientStream = map[string]any{"network": mode, "security": "reality", "realitySettings": clientSecurity, "httpSettings": stream["httpSettings"]}
		query.Set("security", "reality")
		query.Set("sni", "reality.example")
		query.Set("pbk", publicKey)
		query.Set("sid", "0102030405060708")
	}
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
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": tunnelPort, "users": []any{map[string]any{"id": id, "encryption": "none"}}}}}, "streamSettings": clientStream}},
	})
	if inputFormat == "uri" {
		clientConfig = []byte(fmt.Sprintf("vless://%s@127.0.0.1:%d?%s", id, tunnelPort, query.Encode()))
	}
	if inputFormat == "node" {
		parameters := make(map[string]string)
		for key, values := range query {
			parameters[key] = values[0]
		}
		clientConfig, err = json.Marshal(&conf.NodeDescription{Version: 1, Protocol: "vless", Address: "127.0.0.1", Port: uint16(tunnelPort), Credentials: conf.NodeCredentials{ID: id}, Parameters: parameters})
		if err != nil {
			t.Fatal(err)
		}
	}
	client, err := core.StartInstance(inputFormat, clientConfig)
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
