package quic

import (
	"testing"
	q "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestLegacyQUICChromeProfileOptInDefaults(t *testing.T) {
	baseline := quicConfig()
	if baseline.ChromeParrot || baseline.MaxIncomingStreams != 32 ||
		baseline.InitialPacketSize != 1200 {
		t.Fatal("legacy QUIC defaults were unexpectedly changed")
	}
	for _, profile := range []string{"","hellogolang","unsafe","chrome"} {
		settings:=&internet.MemoryStreamConfig{
			SecurityType:"tls",
			SecuritySettings:&tls.Config{Fingerprint:profile},
		}
		config:=tunedLegacyQUICConfig(&internet.QuicParams{MaxIdleTimeout:80})
		tr:=&q.Transport{ConnectionIDLength:12}
		applyLegacyQUICChromeProfile(settings,tr,config)
		if got:=config.ChromeParrot;got!=(profile=="chrome"){
			t.Fatal("unexpected opt-in chrome profile selection",profile,got)
		}
		if (tr.ConnectionIDGenerator!=nil)!=(profile=="chrome"){
			t.Fatal("non-Chrome CID generator changed",profile)
		}
		if quicConfig().ChromeParrot {
			t.Fatal("Chrome QUIC profile mutated legacy defaults")
		}
	}
}
