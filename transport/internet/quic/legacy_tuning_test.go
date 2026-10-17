package quic

import (
	"reflect"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func TestLegacyQUICTuningUnspecifiedDefaults(t *testing.T) {
	if err := ValidateLegacyQUICParams(nil); err != nil {t.Fatal(err)}
	if !reflect.DeepEqual(tunedLegacyQUICConfig(nil), quicConfig()) {t.Fatal("legacy QUIC defaults changed")}
	if !reflect.DeepEqual(tunedLegacyQUICConfig(&internet.QuicParams{}), quicConfig()) {t.Fatal("empty tuning changed defaults")}
}

func TestLegacyQUICTuningAppliesBoundedOnly(t *testing.T) {
	options := &internet.QuicParams{
		MaxIdleTimeout:80, KeepAlivePeriod:20, MaxIncomingStreams:64,
		InitStreamReceiveWindow:65536, MaxStreamReceiveWindow:131072,
		InitConnReceiveWindow:262144, MaxConnReceiveWindow:524288,
	}
	if err:=ValidateLegacyQUICParams(options);err!=nil{t.Fatal(err)}
	got:=tunedLegacyQUICConfig(options)
	if got.HandshakeIdleTimeout != 4*time.Second || !got.DisablePathMTUDiscovery ||
		got.MaxIdleTimeout != 80*time.Second || got.KeepAlivePeriod != 20*time.Second ||
		got.MaxIncomingStreams != 64 || got.InitialStreamReceiveWindow != 65536 ||
		got.MaxStreamReceiveWindow != 131072 || got.InitialConnectionReceiveWindow != 262144 ||
		got.MaxConnectionReceiveWindow != 524288 {t.Fatal("legacy QUIC options or invariants changed")}
}

func TestLegacyQUICTuningRejectsUnsupported(t *testing.T) {
	for name, params := range map[string]*internet.QuicParams{
		"browser-parrot":{DisableChromeParrot:true},
		"congestion":{Congestion:"bbr"},
		"brutal":{BrutalUp:102400},
		"mtu":{DisablePathMtuDiscovery:true},
		"gso":{DisableGSO:true},
		"stateless-reset":{DisableStatelessReset:true},
		"too-few-streams":{MaxIncomingStreams:7},
		"too-many-streams":{MaxIncomingStreams:129},
		"bad-idle":{MaxIdleTimeout:3},
		"keepalive-conflict":{MaxIdleTimeout:30,KeepAlivePeriod:30},
		"window-unpaired":{InitConnReceiveWindow:65536},
		"window-reversed":{InitStreamReceiveWindow:65536,MaxStreamReceiveWindow:32768},
	} {
		t.Run(name,func(t *testing.T){if err:=ValidateLegacyQUICParams(params);err==nil {t.Fatal("unsupported tuning accepted")}})
	}
}
