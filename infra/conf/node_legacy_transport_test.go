package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

const legacyNodeID = "11111111-1111-4111-8111-111111111111"

func legacyProfiles() []string {
	return []string{
		"vless://" + legacyNodeID + "@127.0.0.1:443",
		"vmess://" + legacyNodeID + "@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	}
}

func assertLegacyStreamMatches(t *testing.T, got, want *conf.StreamConfig) {
	t.Helper()
	observed, err := got.Build()
	if err != nil { t.Fatal("node stream build:", err) }
	expected, err := want.Build()
	if err != nil { t.Fatal("explicit transport build:", err) }
	if !proto.Equal(observed, expected) { t.Fatal("node and explicit transport configurations differ") }
}

func TestAddedTCPHeaderNodeParityAcrossFourProtocols(t *testing.T) {
	for _, base := range legacyProfiles() {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			got, err := conf.ParseNodeURI(base + "?type=tcp&headerType=http&host=cdn.example.invalid&path=/edge")
			if err != nil { t.Fatal(err) }
			network := conf.TransportProtocol("tcp")
			header := json.RawMessage("{\"type\":\"http\",\"request\":{\"headers\":{\"Host\":[\"cdn.example.invalid\"]},\"path\":[\"/edge\"]}}")
			want := &conf.StreamConfig{Network: &network, Security: got.StreamSetting.Security, TLSSettings: got.StreamSetting.TLSSettings, TCPSettings: &conf.TCPConfig{HeaderConfig: header}}
			assertLegacyStreamMatches(t, got.StreamSetting, want)
		})
	}
}

func TestAddedMKCPNodeParityAcrossFourProtocols(t *testing.T) {
	for _, base := range legacyProfiles() {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			uri := base + "?type=mkcp&headerType=srtp&seed=synthetic&mtu=1350&tti=35&uplinkCapacity=5&downlinkCapacity=20&cwndMultiplier=2&maxSendingWindow=2097152"
			got, err := conf.ParseNodeURI(uri)
			if err != nil { t.Fatal(err) }
			network := conf.TransportProtocol("mkcp")
			mtu, tti, up, down, cwnd, window := uint32(1350), uint32(35), uint32(5), uint32(20), uint32(2), uint32(2097152)
			seed := json.RawMessage("{\"value\":\"synthetic\"}")
			header := json.RawMessage("{\"header\":\"srtp\"}")
			want := &conf.StreamConfig{
				Network: &network, Security: got.StreamSetting.Security, TLSSettings: got.StreamSetting.TLSSettings,
				KCPSettings: &conf.KCPConfig{Mtu: &mtu, Tti: &tti, UpCap: &up, DownCap: &down, CwndMultiplier: &cwnd, MaxSendingWindow: &window},
				FinalMask: &conf.FinalMask{Udp: []conf.Mask{{Type:"mkcp-legacy", Settings: &seed},{Type:"mkcp-legacy", Settings: &header}}},
			}
			assertLegacyStreamMatches(t, got.StreamSetting, want)
		})
	}
}

func TestAddedLegacyTransportDefaultPreservation(t *testing.T) {
	for _, base := range legacyProfiles() {
		for _, network := range []string{"tcp", "mkcp"} {
			t.Run(strings.SplitN(base, "://", 2)[0]+"/"+network, func(t *testing.T) {
				got, err := conf.ParseNodeURI(base + "?type=" + network)
				if err != nil { t.Fatal(err) }
				if got.StreamSetting.FinalMask != nil || got.StreamSetting.TCPSettings != nil || got.StreamSetting.KCPSettings != nil { t.Fatal("implicit metadata changed default transport") }
				n := conf.TransportProtocol(network)
				want := &conf.StreamConfig{Network: &n, Security: got.StreamSetting.Security, TLSSettings: got.StreamSetting.TLSSettings}
				assertLegacyStreamMatches(t, got.StreamSetting, want)
			})
		}
	}
}

func TestAddedLegacyTransportVMessJSONEnvelope(t *testing.T) {
	body := fmt.Sprintf("{\"v\":\"2\",\"ps\":\"synthetic\",\"add\":\"127.0.0.1\",\"port\":\"443\",\"id\":\"%s\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"tcp\",\"type\":\"http\",\"host\":\"cdn.example.invalid\",\"path\":\"/edge\"}", legacyNodeID)
	got, err := conf.ParseNodeURI("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(body)))
	if err != nil { t.Fatal(err) }
	if got.StreamSetting.TCPSettings == nil { t.Fatal("legacy VMess HTTP header not selected") }
	if _, err := got.Build(); err != nil { t.Fatal(err) }
}

func TestAddedLegacyTransportRejectsUnsupportedMetadata(t *testing.T) {
	base := "vless://" + legacyNodeID + "@127.0.0.1:443?type="
	for name, suffix := range map[string]string{
		"raw-http-host-without-header":"tcp&host=cdn.example.invalid",
		"wrong-tcp-header":"tcp&headerType=srtp",
		"tcp-invalid-http-path":"tcp&headerType=http&path=not-absolute",
		"http-header-on-websocket":"ws&headerType=http",
		"bad-kcp-header":"mkcp&headerType=unknown",
		"bad-kcp-tti":"mkcp&tti=9",
		"kcp-tti-overflow":"mkcp&tti=4294967296",
		"kcp-negative-mtu":"mkcp&mtu=-1",
		"kcp-seed-conflict":"mkcp&seed=one&path=two",
		"kcp-domain-requires-dns":"mkcp&headerType=srtp&headerdomain=cdn.example.invalid",
		"kcp-host-requires-dns":"mkcp&headerType=dtls&host=cdn.example.invalid",
		"unrelated-seed":"tcp&seed=secret",
		"kcp-empty-mtu": "mkcp&mtu=",
		"kcp-empty-tti": "mkcp&tti=",
		"kcp-empty-seed": "mkcp&seed=",
		"kcp-empty-domain": "mkcp&headerType=dns&headerdomain=",
	} {
		t.Run(name,func(t *testing.T){if _,err:=conf.ParseNodeURI(base+suffix);err==nil {t.Fatal("invalid metadata accepted")}})
	}
}
