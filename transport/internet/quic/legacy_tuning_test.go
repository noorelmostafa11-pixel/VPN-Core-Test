package quic

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	q "github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestLegacyQUICTuningUnspecifiedDefaults(t *testing.T) {
	if err := ValidateLegacyQUICParams(nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tunedLegacyQUICConfig(nil), quicConfig()) {
		t.Fatal("legacy QUIC defaults changed")
	}
	if !reflect.DeepEqual(tunedLegacyQUICConfig(&internet.QuicParams{}), quicConfig()) {
		t.Fatal("empty tuning changed defaults")
	}
	// The shared StreamConfig.Build() historically inserts this value when any
	// finalmask.quicParams object is selected. It is not a BBR enable switch.
	if err := ValidateLegacyQUICParams(&internet.QuicParams{BbrProfile: "standard", MaxIdleTimeout: 80}); err != nil {
		t.Fatal("stream builder default BBR profile rejected:", err)
	}
}

func TestAddedLegacyQUICTuningIndependentPeers(t *testing.T) {
	for name, params := range map[string]*internet.QuicParams{
		"reno":             {Congestion: "reno", MaxIdleTimeout: 30, KeepAlivePeriod: 5, MaxIncomingStreams: 16, InitStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 131072},
		"bbr-standard":     {Congestion: "bbr", BbrProfile: "standard"},
		"bbr-conservative": {Congestion: "bbr", BbrProfile: "conservative"},
		"bbr-aggressive":   {Congestion: "bbr", BbrProfile: "aggressive"},
		"brutal":           {Congestion: "force-brutal", BrutalUp: 2 * 1024 * 1024, BrutalDown: 4 * 1024 * 1024, BrutalDisableLossCompensation: true},
	} {
		for _, server := range []bool{false, true} {
			direction := "client"
			if server {
				direction = "server"
			}
			t.Run(name+"/"+direction, func(t *testing.T) {
				serverTLS, clientTLS := certificateSettings(t)
				config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}, HeaderType: "dtls"}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				done := make(chan error, 1)
				if !server {
					listener, _ := peerListener(t, config, serverTLS, false)
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
					conn, err := Dial(ctx, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.UDPAddr).Port)), &internet.MemoryStreamConfig{ProtocolSettings: config, SecurityType: "tls", SecuritySettings: clientTLS, QuicParams: params})
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					streamExchange(t, conn, conn.(*streamConn).CloseWrite)
				} else {
					listener, err := Listen(ctx, xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{ProtocolSettings: config, SecurityType: "tls", SecuritySettings: serverTLS, QuicParams: params}, func(conn stat.Connection) {
						go func() { defer conn.Close(); done <- echoStream(conn.(*streamConn).Stream) }()
					})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					transport := &q.Transport{Conn: oracle(t, raw, config.Security.Type, config.HeaderType), DisableGSO: true}
					defer transport.Close()
					parent, err := transport.Dial(ctx, listener.Addr(), clientTLS.GetTLSConfig(), &q.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
					if err != nil {
						t.Fatal(err)
					}
					defer parent.CloseWithError(0, "")
					stream, err := parent.OpenStreamSync(ctx)
					if err != nil {
						t.Fatal(err)
					}
					streamExchange(t, &streamConn{Stream: stream, parent: parent}, stream.Close)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("independent QUIC peer did not join")
				}
			})
		}
	}
}

func TestLegacyQUICTuningAppliesBoundedOnly(t *testing.T) {
	options := &internet.QuicParams{
		MaxIdleTimeout: 80, KeepAlivePeriod: 20, MaxIncomingStreams: 64,
		InitStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 131072,
		InitConnReceiveWindow: 262144, MaxConnReceiveWindow: 524288,
	}
	if err := ValidateLegacyQUICParams(options); err != nil {
		t.Fatal(err)
	}
	got := tunedLegacyQUICConfig(options)
	if got.HandshakeIdleTimeout != 4*time.Second || !got.DisablePathMTUDiscovery ||
		got.MaxIdleTimeout != 80*time.Second || got.KeepAlivePeriod != 20*time.Second ||
		got.MaxIncomingStreams != 64 || got.InitialStreamReceiveWindow != 65536 ||
		got.MaxStreamReceiveWindow != 131072 || got.InitialConnectionReceiveWindow != 262144 ||
		got.MaxConnectionReceiveWindow != 524288 {
		t.Fatal("legacy QUIC options or invariants changed")
	}
}

func TestLegacyQUICTuningRejectsUnsupported(t *testing.T) {
	for name, params := range map[string]*internet.QuicParams{
		"browser-parrot":          {DisableChromeParrot: true},
		"unsupported-bbr-profile": {BbrProfile: "aggressive"},
		"bbr-and-brutal":          {Congestion: "bbr", BbrProfile: "standard", BrutalUp: 102400},
		"brutal-without-down":     {Congestion: "force-brutal", BrutalUp: 102400},
		"brutal-rate-overflow":    {Congestion: "force-brutal", BrutalUp: 1 << 42, BrutalDown: 102400},
		"unsupported-mode":        {Congestion: "cubic"},

		"congestion":         {Congestion: "cubic"},
		"brutal":             {BrutalUp: 102400},
		"mtu":                {DisablePathMtuDiscovery: true},
		"gso":                {DisableGSO: true},
		"stateless-reset":    {DisableStatelessReset: true},
		"too-few-streams":    {MaxIncomingStreams: 7},
		"too-many-streams":   {MaxIncomingStreams: 129},
		"bad-idle":           {MaxIdleTimeout: 3},
		"keepalive-conflict": {MaxIdleTimeout: 30, KeepAlivePeriod: 30},
		"window-unpaired":    {InitConnReceiveWindow: 65536},
		"window-reversed":    {InitStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 32768},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateLegacyQUICParams(params); err == nil {
				t.Fatal("unsupported tuning accepted")
			}
		})
	}
}

func TestLegacyQUICOptInCongestionControllers(t *testing.T) {
	for name, params := range map[string]*internet.QuicParams{
		"bbr":                  {Congestion: "bbr", BbrProfile: "standard"},
		"bbr-conservative":     {Congestion: "bbr", BbrProfile: "conservative"},
		"bbr-aggressive":       {Congestion: "bbr", BbrProfile: "aggressive"},
		"reno":                 {Congestion: "reno", BbrProfile: "standard"},
		"brutal-bidirectional": {Congestion: "force-brutal", BrutalUp: 102400, BrutalDown: 204800, BrutalDisableLossCompensation: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateLegacyQUICParams(params); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tunedLegacyQUICConfig(params), quicConfig()) {
				t.Fatal("congestion selection changed flow defaults")
			}
		})
	}
}
