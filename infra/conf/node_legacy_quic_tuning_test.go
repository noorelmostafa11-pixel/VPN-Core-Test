package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

const quicTuningNodeID = "11111111-1111-4111-8111-111111111111"
const quicTuningJSON = `{"maxIdleTimeout":80,"keepAlivePeriod":20,"maxIncomingStreams":64,"initStreamReceiveWindow":65536,"maxStreamReceiveWindow":131072,"initConnectionReceiveWindow":262144,"maxConnectionReceiveWindow":524288}`

func TestNodeLegacyQUICTuningFourProtocolParity(t *testing.T) {
	profiles := []string{
		"vless://" + quicTuningNodeID + "@127.0.0.1:443",
		"vmess://" + quicTuningNodeID + "@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	}
	network := conf.TransportProtocol("quic")
	for _, base := range profiles {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			uri := base + "?type=quic&security=tls&sni=example.invalid&quicsecurity=aes-128-gcm&quickey=synthetic&headerType=srtp&quicParams=" + url.QueryEscape(quicTuningJSON)
			got, err := conf.ParseNodeURI(uri)
			if err != nil { t.Fatal(err) }
			if got.StreamSetting.FinalMask == nil || got.StreamSetting.FinalMask.QuicParams == nil { t.Fatal("tuning not selected") }
			observed, err := got.StreamSetting.Build()
			if err != nil { t.Fatal(err) }
			var mask conf.FinalMask
			if err := json.Unmarshal([]byte(`{"quicParams":`+quicTuningJSON+`}`), &mask); err != nil { t.Fatal(err) }
			want := &conf.StreamConfig{
				Network: &network, Security: "tls",
				TLSSettings: &conf.TLSConfig{ServerName: "example.invalid"},
				QUICSettings: &conf.QUICConfig{Security: "aes-128-gcm", Key: "synthetic", Header: json.RawMessage(`{"type":"srtp","domain":""}`)},
				FinalMask: &mask,
			}
			expected, err := want.Build()
			if err != nil { t.Fatal(err) }
			if !proto.Equal(observed, expected) { t.Fatal("QUIC tuning differs from explicit full JSON") }
		})
	}
}

func TestNodeLegacyQUICTuningSharedInputs(t *testing.T) {
	base := "vless://" + quicTuningNodeID + "@127.0.0.1:443?type=quic&security=tls&sni=example.invalid&quicParams=" + url.QueryEscape(quicTuningJSON)
	uri, err := conf.ParseNodeURI(base)
	if err != nil { t.Fatal(err) }
	node := conf.NodeDescription{
		Version:1, Protocol:"vless", Address:"127.0.0.1",Port:443,
		Credentials:conf.NodeCredentials{ID:quicTuningNodeID},
		Parameters:map[string]string{"type":"quic","security":"tls","sni":"example.invalid","quicparams":quicTuningJSON},
	}
	b, err := json.Marshal(node)
	if err != nil { t.Fatal(err) }
	parsed, err := conf.ParseNodeJSON(b)
	if err != nil { t.Fatal(err) }
	one, err := uri.Build()
	if err != nil { t.Fatal(err) }
	two, err := parsed.Build()
	if err != nil { t.Fatal(err) }
	if !proto.Equal(one,two){t.Fatal("URI and JSON node selection differ")}

	legacy := map[string]any{
		"v":"2","add":"127.0.0.1","port":"443","id":quicTuningNodeID,
		"aid":0,"scy":"auto","net":"quic","type":"srtp",
		"host":"aes-128-gcm","path":"synthetic","tls":"tls",
		"sni":"example.invalid","quicParams":json.RawMessage(quicTuningJSON),
	}
	raw, err := json.Marshal(legacy)
	if err != nil { t.Fatal(err) }
	vmess, err := conf.ParseNodeURI("vmess://"+base64.RawStdEncoding.EncodeToString(raw))
	if err != nil { t.Fatal(err) }
	if vmess.StreamSetting.FinalMask == nil || vmess.StreamSetting.FinalMask.QuicParams == nil {
		t.Fatal("VMess JSON envelope lost nested QUIC settings")
	}
	if _,err=vmess.Build(); err!=nil {t.Fatal(err)}
}

func TestNodeLegacyQUICDefaultUnchanged(t *testing.T) {
	for _, scheme := range []string{"vless","vmess","trojan","ss"} {
		base := scheme + "://"
		switch scheme {
		case "vless","vmess": base+=quicTuningNodeID
		case "trojan": base+="synthetic"
		case "ss": base+="aes-128-gcm:synthetic"
		}
		got,err:=conf.ParseNodeURI(base+"@127.0.0.1:443?type=quic&security=tls&sni=example.invalid")
		if err!=nil {t.Fatal(scheme,err)}
		if got.StreamSetting.FinalMask!=nil {t.Fatal(scheme,"changed default")}
		if _,err=got.Build();err!=nil{t.Fatal(scheme,err)}
	}
}

func TestNodeLegacyQUICTuningRejectsUnsafe(t *testing.T) {
	base := "vless://" + quicTuningNodeID + "@127.0.0.1:443?type=quic&security=tls&sni=example.invalid"
	invalid := map[string]string{
		"empty":"","null":"null","array":"[]","malformed":"{",
		"unknown":`{"disableChromeParrot":true}`,
		"congestion-invalid":`{"congestion":"cubic"}`,
		"brutal":`{"brutalUp":"1mbps"}`,
		"key-file":`{"certificates":[{"keyFile":"private.key"}]}`,
		"socket":`{"sockopt":{"dialerProxy":"direct"}}`,
		"too-small-idle":`{"maxIdleTimeout":3}`,
		"too-large-idle":`{"maxIdleTimeout":121}`,
		"keepalive-after-idle":`{"maxIdleTimeout":30,"keepAlivePeriod":30}`,
		"invalid-streams":`{"maxIncomingStreams":10000}`,
		"unpaired-window":`{"initStreamReceiveWindow":65536}`,
		"window-too-large":`{"initConnectionReceiveWindow":65536,"maxConnectionReceiveWindow":999999999999}`,
		"window-inverted":`{"initStreamReceiveWindow":524288,"maxStreamReceiveWindow":262144}`,
		"negative":`{"maxIdleTimeout":-1}`,
		"float":`{"maxIncomingStreams":8.5}`,
		"duplicate":`{"maxIdleTimeout":30,"MaxIdleTimeout":40}`,
		"oversized":`{"maxIdleTimeout":80,"padding":"`+strings.Repeat("A",4100)+`"}`,
	}
	for name, raw := range invalid {
		t.Run(name,func(t *testing.T){
			if _,err:=conf.ParseNodeURI(base+"&quicParams="+url.QueryEscape(raw));err==nil{t.Fatal("invalid tuning accepted")}
		})
	}
	for name, suffix := range map[string]string{
		"wrong-carrier":"?type=tcp&quicParams="+url.QueryEscape(quicTuningJSON),
		"browser-fingerprint":"?type=quic&security=tls&fp=chrome&quicParams="+url.QueryEscape(quicTuningJSON),
	} {
		t.Run(name,func(t *testing.T){
			if _,err:=conf.ParseNodeURI("vless://"+quicTuningNodeID+"@127.0.0.1:443"+suffix);err==nil{t.Fatal("invalid carrier/profile accepted")}
		})
	}
}

func TestNodeLegacyQUICNewCongestionFourFamilies(t *testing.T) {
	modes := map[string]string{
		"bbr": `{"congestion":"bbr","bbrProfile":"aggressive"}`,
		"force-brutal": `{"congestion":"force-brutal","brutalUp":"8mbps","brutalDown":"16mbps","brutalDisableLossCompensation":true}`,
	}
	for _, base := range []string{
		"vless://"+quicTuningNodeID+"@127.0.0.1:443",
		"vmess://"+quicTuningNodeID+"@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	} {
		for mode, option := range modes {
			t.Run(strings.SplitN(base,"://",2)[0]+"/"+mode,func(t *testing.T){
				got,err:=conf.ParseNodeURI(base+"?type=quic&quicParams="+url.QueryEscape(option))
				if err!=nil{t.Fatal(err)}
				cfg,err:=got.StreamSetting.Build()
				if err!=nil{t.Fatal(err)}
				if cfg.QuicParams==nil || cfg.QuicParams.Congestion!=mode {
					t.Fatal("QUIC congestion selection absent or changed")
				}
				if mode=="force-brutal" && (cfg.QuicParams.BrutalUp!=1048576 || cfg.QuicParams.BrutalDown!=2097152) {
					t.Fatal("QUIC rates differed from original bandwidth conversion")
				}
			})
		}
	}
}

func TestNodeLegacyQUICCongestionRejectsUnsafeRates(t *testing.T) {
	base:="vless://"+quicTuningNodeID+"@127.0.0.1:443?type=quic&quicParams="
	for label, raw := range map[string]string{
		"brutal-missing-down":`{"congestion":"force-brutal","brutalUp":"8mbps"}`,
		"brutal-undersized":`{"congestion":"force-brutal","brutalUp":"100kbps","brutalDown":"8mbps"}`,
		"brutal-overflow":`{"congestion":"force-brutal","brutalUp":"100000000000gbps","brutalDown":"8mbps"}`,
		"brutal-with-bbr":`{"congestion":"bbr","brutalUp":"8mbps"}`,
		"unknown-profile":`{"congestion":"bbr","bbrProfile":"invalid"}`,
		"unselected-controller":`{"brutalUp":"8mbps","brutalDown":"8mbps"}`,
		"non-string-rate":`{"congestion":"force-brutal","brutalUp":102400,"brutalDown":"8mbps"}`,
	} {
		t.Run(label,func(t *testing.T){
			if _,err:=conf.ParseNodeURI(base+url.QueryEscape(raw));err==nil{t.Fatal("invalid QUIC control metadata accepted")}
		})
	}
}
