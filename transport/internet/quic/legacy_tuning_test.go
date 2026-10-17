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
	// The shared StreamConfig.Build() historically inserts this value when any
	// finalmask.quicParams object is selected. It is not a BBR enable switch.
	if err:=ValidateLegacyQUICParams(&internet.QuicParams{BbrProfile:"standard",MaxIdleTimeout:80});err!=nil{t.Fatal("stream builder default BBR profile rejected:",err)}
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
		"unsupported-bbr-profile":{BbrProfile:"aggressive"},
		"bbr-and-brutal":{Congestion:"bbr",BbrProfile:"standard",BrutalUp:102400},
		"brutal-without-down":{Congestion:"force-brutal",BrutalUp:102400},
		"brutal-rate-overflow":{Congestion:"force-brutal",BrutalUp:1<<42,BrutalDown:102400},
		"unsupported-mode":{Congestion:"cubic"},

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

func TestLegacyQUICOptInCongestionControllers(t *testing.T) {
	for name, params := range map[string]*internet.QuicParams{
		"bbr":{Congestion:"bbr",BbrProfile:"standard"},
		"bbr-conservative":{Congestion:"bbr",BbrProfile:"conservative"},
		"bbr-aggressive":{Congestion:"bbr",BbrProfile:"aggressive"},
		"reno":{Congestion:"reno",BbrProfile:"standard"},
		"brutal-bidirectional":{Congestion:"force-brutal",BrutalUp:102400,BrutalDown:204800,BrutalDisableLossCompensation:true},
	} {
		t.Run(name,func(t *testing.T){
			if err:=ValidateLegacyQUICParams(params);err!=nil{t.Fatal(err)}
			if !reflect.DeepEqual(tunedLegacyQUICConfig(params),quicConfig()) {
				t.Fatal("congestion selection changed flow defaults")
			}
		})
	}
}
