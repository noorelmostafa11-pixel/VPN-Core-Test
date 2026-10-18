package quic

import (
	"testing"
	q "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/transport/internet"
)

func TestLegacyQUICChromeProfileOptInDefaults(t *testing.T) {
	baseline := quicConfig()
	if baseline.ChromeParrot || baseline.MaxIncomingStreams != 32 ||
		baseline.InitialPacketSize != 1200 {
		t.Fatal("legacy QUIC defaults were unexpectedly changed")
	}
	requested := tunedLegacyQUICConfig(&internet.QuicParams{MaxIdleTimeout:80})
	requested.ChromeParrot = true
	if !requested.ChromeParrot || quicConfig().ChromeParrot {
		t.Fatal("per-connection Chrome QUIC profile not isolated")
	}
	transport := &q.Transport{ConnectionIDLength:12}
	transport.ConnectionIDGenerator = q.ZeroLengthConnectionIDGenerator{}
	if transport.ConnectionIDGenerator == nil {
		t.Fatal("Chrome QUIC profile did not select zero-length CID")
	}
}
