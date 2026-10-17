package socks_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func TestForkLegacySocksOutboundWire(t *testing.T) {
	for _, test := range []struct {
		version, target string
		domain          bool
	}{
		{"socks4", "127.0.0.1", false},
		{"socks4", "localhost", false},
		{"socks4a", "127.0.0.1", false},
		{"socks4a", "no-local-dns.invalid", true},
	} {
		for _, inputFormat := range []string{"json", "uri", "node"} {
			t.Run(test.version+"/"+test.target+"/"+inputFormat, func(t *testing.T) {
				listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				body := bytes.Repeat([]byte{0x5a, 0, 0xff}, 33334)
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
					reader := bufio.NewReader(conn)
					var header [8]byte
					if _, err = io.ReadFull(reader, header[:]); err != nil {
						done <- err
						return
					}
					if header[0] != 4 || header[1] != 1 || binary.BigEndian.Uint16(header[2:4]) != 443 {
						done <- fmt.Errorf("bad SOCKS4 CONNECT header %x", header)
						return
					}
					user, err := reader.ReadString(0)
					if err != nil || user != "synthetic\x00" {
						done <- fmt.Errorf("wrong user ID: %q, %v", user, err)
						return
					}
					if test.domain {
						if !bytes.Equal(header[4:8], []byte{0, 0, 0, 1}) {
							done <- fmt.Errorf("SOCKS4a domain flag missing")
							return
						}
						domain, err := reader.ReadString(0)
						if err != nil || domain != test.target+"\x00" {
							done <- fmt.Errorf("remote DNS name changed: %q, %v", domain, err)
							return
						}
					} else if !bytes.Equal(header[4:8], []byte{127, 0, 0, 1}) {
						done <- fmt.Errorf("wrong IPv4 target %x", header)
						return
					}
					for _, b := range []byte{0, 90, 0, 0, 0, 0, 0, 0} {
						if err = buf.WriteAllBytes(conn, []byte{b}, nil); err != nil {
							done <- err
							return
						}
					}
					if err = buf.WriteAllBytes(conn, greeting, nil); err != nil {
						done <- err
						return
					}
					incoming := make([]byte, len(body))
					if _, err = io.ReadFull(reader, incoming); err != nil {
						done <- err
						return
					}
					if !bytes.Equal(incoming, body) {
						done <- fmt.Errorf("outbound payload changed")
						return
					}
					done <- buf.WriteAllBytes(conn, incoming, nil)
				}()
				// Always join the peer, including assertion-failure paths.
				t.Cleanup(func() {
					listener.Close()
					select {
					case err := <-done:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(10 * time.Second):
						t.Error("SOCKS4 peer did not stop")
					}
				})
				config, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": test.version, "settings": map[string]any{"address": "127.0.0.1", "port": listener.Addr().(*stdnet.TCPAddr).Port, "user": "synthetic"}}}})
				if err != nil {
					t.Fatal(err)
				}
				if inputFormat == "uri" {
					config = []byte(fmt.Sprintf("%s://synthetic@%s", test.version, listener.Addr().String()))
				}
				if inputFormat == "node" {
					config, err = json.Marshal(&conf.NodeDescription{Version: 1, Protocol: test.version, Address: "127.0.0.1", Port: uint16(listener.Addr().(*stdnet.TCPAddr).Port), Credentials: conf.NodeCredentials{Username: "synthetic"}})
					if err != nil {
						t.Fatal(err)
					}
				}
				instance, err := core.StartInstance(inputFormat, config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { instance.Close() })
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				t.Cleanup(cancel)
				conn, err := core.Dial(ctx, instance, net.TCPDestination(net.ParseAddress(test.target), 443))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				// No application bytes are sent before the independent peer's greeting.
				got := make([]byte, len(greeting))
				if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, greeting) {
					t.Fatal("server-first greeting failed", err)
				}
				for _, piece := range [][]byte{body[:1], body[1:65], body[65:8193], body[8193:]} {
					if err = buf.WriteAllBytes(conn, piece, nil); err != nil {
						t.Fatal(err)
					}
				}
				got = make([]byte, len(body))
				if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, body) {
					t.Fatal("TCP echo changed", err)
				}
			})
		}
	}
}
