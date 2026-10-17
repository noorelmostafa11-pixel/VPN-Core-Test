package quic

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	q "github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestForkLegacyQUICTypedHeaderIndependentPeers(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		for _, security := range ciphers {
			for _, fixture := range historicalHeaders {
				t.Run(role+"/"+security.String()+"/"+fixture.name, func(t *testing.T) {
					serverTLS, clientTLS := certificateSettings(t)
					config := historicalConfig(t, fixture.name, fixture.value)
					config.Security = &protocol.SecurityConfig{Type: security}
					settings := &internet.MemoryStreamConfig{ProtocolName: "quic", ProtocolSettings: config, SecurityType: "tls", SecuritySettings: clientTLS}
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					done := make(chan error, 1)
					prefix, err := hex.DecodeString(fixture.prefix)
					if err != nil {
						t.Fatal(err)
					}
					var conn net.Conn
					var half func() error
					if role == "client" {
						peerConfig := &Config{Security: config.Security, HeaderType: fixture.kind}
						// Apply the literal historical wire prefix before starting the listener.
						listener, _ := peerListener(t, peerConfig, serverTLS, false, prefix)
						go func() {
							parent, err := listener.Accept(ctx)
							if err != nil {
								done <- err
								return
							}
							stream, err := parent.AcceptStream(ctx)
							if err == nil {
								err = echoStream(stream)
							}
							done <- err
						}()
						conn, err = Dial(ctx, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.UDPAddr).Port)), settings)
						if err == nil {
							half = conn.(*streamConn).CloseWrite
						}
					} else {
						settings.SecuritySettings = serverTLS
						listener, listenErr := Listen(ctx, xnet.LocalHostIP, 0, settings, func(conn stat.Connection) {
							go func() { defer conn.Close(); done <- echoStream(conn.(*streamConn).Stream) }()
						})
						if listenErr != nil {
							t.Fatal(listenErr)
						}
						t.Cleanup(func() { listener.Close() })
						raw, listenErr := net.ListenPacket("udp4", "127.0.0.1:0")
						if listenErr != nil {
							t.Fatal(listenErr)
						}
						t.Cleanup(func() { raw.Close() })
						packet := oracle(t, raw, security, fixture.kind)
						packet.prefix = prefix
						transport := &q.Transport{Conn: packet, DisableGSO: true}
						t.Cleanup(func() { transport.Close() })
						parent, dialErr := transport.Dial(ctx, listener.Addr(), clientTLS.GetTLSConfig(), &q.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
						if dialErr != nil {
							t.Fatal(dialErr)
						}
						t.Cleanup(func() { parent.CloseWithError(0, "") })
						var stream *q.Stream
						stream, err = parent.OpenStreamSync(ctx)
						if err == nil {
							conn, half = &streamConn{Stream: stream, parent: parent}, stream.Close
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					streamExchange(t, conn, half)
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("typed-header peer did not finish")
					}
				})
			}
		}
	}
}
