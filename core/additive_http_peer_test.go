package core_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestAddedHTTPMetadataIndependentPeers(t *testing.T) {
	for _, carrier := range []string{"ws", "httpupgrade", "h2c"} {
		t.Run(carrier, func(t *testing.T) {
			first := bytes.Repeat([]byte{0x51}, 32)
			rest := bytes.Repeat([]byte{0, 255, 0x5a}, 40001)
			payload := append(bytes.Clone(first), rest...)
			done := make(chan error, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "front.example.invalid" || r.URL.Path != "/edge" || r.Header.Get("X-Route") != "synthetic" {
					w.WriteHeader(400)
					done <- fmt.Errorf("HTTP metadata changed")
					return
				}
				switch carrier {
				case "ws":
					early, err := base64.RawURLEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Protocol"))
					if err != nil || !bytes.Equal(early, first) {
						w.WriteHeader(400)
						done <- fmt.Errorf("WS early bytes changed")
						return
					}
					upgrader := websocket.Upgrader{}
					conn, err := upgrader.Upgrade(w, r, nil)
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					_, got, err := conn.ReadMessage()
					if err == nil && !bytes.Equal(got, rest) {
						err = fmt.Errorf("WS payload changed")
					}
					if err == nil {
						err = conn.WriteMessage(websocket.BinaryMessage, payload)
					}
					done <- err
				case "httpupgrade":
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
					if err == nil {
						err = rw.Flush()
					}
					got := make([]byte, len(payload))
					if err == nil {
						_, err = io.ReadFull(rw, got)
					}
					if err == nil && !bytes.Equal(got, payload) {
						err = fmt.Errorf("HTTPUpgrade application bytes changed")
					}
					if err == nil {
						_, err = conn.Write(got)
					}
					done <- err
				case "h2c":
					if r.Method != "PATCH" || r.ProtoMajor != 2 {
						w.WriteHeader(400)
						done <- fmt.Errorf("HTTP/2 method changed")
						return
					}
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					got := make([]byte, len(payload))
					_, err := io.ReadFull(r.Body, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = fmt.Errorf("HTTP/2 payload changed")
					}
					if err == nil {
						_, err = w.Write(got)
					}
					done <- err
				}
			})
			var wrapped http.Handler = handler
			if carrier == "h2c" {
				wrapped = h2c.NewHandler(handler, &http2.Server{})
			}
			server := httptest.NewServer(wrapped)
			defer server.Close()
			parameters := url.Values{"type": {carrier}, "security": {"none"}, "host": {"front.example.invalid"}, "path": {"/edge"}}
			if carrier == "h2c" {
				parameters.Set("httpMethod", "PATCH")
				parameters.Set("httpHeaders", `{"X-Route":"synthetic"}`)
				parameters.Set("httpReadIdleTimeout", "2")
				parameters.Set("httpHealthCheckTimeout", "1")
			} else {
				parameters.Set("headers", `{"X-Route":"synthetic"}`)
				parameters.Set("ed", "64")
			}
			node, err := conf.ParseNodeURI("vless://" + additiveID + "@127.0.0.1:443?" + parameters.Encode())
			if err != nil {
				t.Fatal(err)
			}
			stream, err := node.StreamSetting.Build()
			if err != nil {
				t.Fatal(err)
			}
			memory, err := internet.ToMemoryStreamConfig(stream)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			port := server.Listener.Addr().(*net.TCPAddr).Port
			conn, err := internet.Dial(ctx, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port)), memory)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write(first); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(rest); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			read := make(chan error, 1)
			go func() { _, e := io.ReadFull(conn, got); read <- e }()
			select {
			case err := <-read:
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("independent download mismatch", err)
				}
			case <-ctx.Done():
				conn.Close()
				<-read
				t.Fatal("independent download timed out")
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("independent peer did not join")
			}
		})
	}
}
