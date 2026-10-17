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

const xhttpNodeTestID = "11111111-1111-4111-8111-111111111111"
const xhttpDownloadTLS = `{"address":"download.example.invalid","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.example.invalid","alpn":["h2"]},"xhttpSettings":{"host":"download.example.invalid","path":"/down"}}`

func xhttpNodeProfiles() []string {
	return []string{
		"vless://" + xhttpNodeTestID + "@127.0.0.1:443",
		"vmess://" + xhttpNodeTestID + "@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	}
}

func TestNodeXHTTPDownloadAdditiveFourProtocolParity(t *testing.T) {
	extra := `{"xPaddingBytes":"100-200","downloadSettings":` + xhttpDownloadTLS + `}`
	for _, base := range xhttpNodeProfiles() {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			u := base + "?type=xhttp&mode=stream-up&host=upload.example.invalid&path=%2Fup&extra=" + url.QueryEscape(extra)
			got, err := conf.ParseNodeURI(u)
			if err != nil {
				t.Fatal("node import:", err)
			}
			gotStream, err := got.StreamSetting.Build()
			if err != nil {
				t.Fatal("node stream:", err)
			}
			var down conf.StreamConfig
			if err := json.Unmarshal([]byte(xhttpDownloadTLS), &down); err != nil {
				t.Fatal(err)
			}
			want := *got.StreamSetting
			want.XHTTPSettings = &conf.SplitHTTPConfig{Host: "upload.example.invalid", Path: "/up", Mode: "stream-up", DownloadSettings: &down}
			want.XHTTPSettings.XPaddingBytes.From = 100
			want.XHTTPSettings.XPaddingBytes.To = 200
			wantedStream, err := want.Build()
			if err != nil {
				t.Fatal("explicit stream:", err)
			}
			if !proto.Equal(gotStream, wantedStream) {
				t.Fatal("XHTTP download connection differs from explicit full-JSON settings")
			}
			if got.StreamSetting.XHTTPSettings == nil || got.StreamSetting.XHTTPSettings.Extra == nil {
				t.Fatal("XHTTP metadata was not preserved")
			}
		})
	}
}

func TestNodeXHTTPDownloadURIAndNodeJSONParity(t *testing.T) {
	extra := `{"downloadSettings":` + xhttpDownloadTLS + `}`
	u := "vless://" + xhttpNodeTestID + "@127.0.0.1:443?type=xhttp&mode=stream-up&extra=" + url.QueryEscape(extra)
	uriNode, err := conf.ParseNodeURI(u)
	if err != nil {
		t.Fatal(err)
	}
	node := conf.NodeDescription{Version: 1, Protocol: "vless", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{ID: xhttpNodeTestID}, Parameters: map[string]string{"type": "xhttp", "mode": "stream-up", "extra": extra}}
	encoded, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	jsonNode, err := conf.ParseNodeJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	a, err := uriNode.Build()
	if err != nil {
		t.Fatal(err)
	}
	b, err := jsonNode.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(a, b) {
		t.Fatal("URI and JSON-node diverged")
	}
}

func TestNodeXHTTPDownloadVMessJSONShare(t *testing.T) {
	extra := json.RawMessage(`{"downloadSettings":` + xhttpDownloadTLS + `}`)
	profile, err := json.Marshal(map[string]any{
		"v": "2", "ps": "synthetic", "add": "127.0.0.1", "port": "443",
		"id": xhttpNodeTestID, "aid": 0, "scy": "auto", "net": "xhttp", "type": "none",
		"mode": "stream-up", "extra": extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := conf.ParseNodeURI("vmess://" + base64.RawStdEncoding.EncodeToString(profile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Build(); err != nil {
		t.Fatal(err)
	}
}

func TestNodeXHTTPDownloadOriginalExtraDefaultsUnchanged(t *testing.T) {
	for _, base := range xhttpNodeProfiles() {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			u := base + "?type=xhttp&extra=" + url.QueryEscape(`{"headers":{"X-Test":"synthetic"}}`)
			got, err := conf.ParseNodeURI(u)
			if err != nil {
				t.Fatal(err)
			}
			if got.StreamSetting.XHTTPSettings == nil || got.StreamSetting.XHTTPSettings.DownloadSettings != nil {
				t.Fatal("default XHTTP transport changed")
			}
			if _, err := got.Build(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeXHTTPDownloadRejectsUntrustedNestedConfig(t *testing.T) {
	prefix := "vless://" + xhttpNodeTestID + "@127.0.0.1:443?type=xhttp&mode=stream-up&extra="
	base := `"address":"download.example.invalid","port":443,"network":"xhttp","security":"tls"`
	cases := map[string]string{
		"bad-port": `{"address":"download.example.invalid","port":0,"network":"xhttp","security":"tls"}`,
		"missing-address": `{"port":443,"network":"xhttp","security":"tls"}`,
		"env-address": `{"address":"env:PRIVATE_ADDRESS","port":443,"network":"xhttp","security":"tls"}`,
		"remote-sockopt": `{` + base + `,"sockopt":{"dialerProxy":"private"}}`,
		"remote-finalmask": `{` + base + `,"finalmask":{"udp":[]}}`,
		"non-xhttp-transport": `{"address":"download.example.invalid","port":443,"network":"tcp","security":"tls"}`,
		"missing-security": `{"address":"download.example.invalid","port":443,"network":"xhttp"}`,
		"unknown-security": `{"address":"download.example.invalid","port":443,"network":"xhttp","security":"xtls"}`,
		"insecure-certificate": `{` + base + `,"tlsSettings":{"allowInsecure":true}}`,
		"local-key-file": `{` + base + `,"tlsSettings":{"certificates":[{"keyFile":"private.key"}]}}`,
		"local-certificate": `{` + base + `,"tlsSettings":{"certificateFile":"secret.pem"}}`,
		"unsafe-download-transport": `{` + base + `,"xhttpSettings":{"headers":{"X-Injected":"value"}}}`,
		"nested-download": `{` + base + `,"xhttpSettings":{"downloadSettings":{}}}`,
		"invalid-download-host": `{` + base + `,"xhttpSettings":{"host":"bad\r\nInjected: yes"}}`,
		"invalid-download-path": `{` + base + `,"xhttpSettings":{"path":"not/absolute"}}`,
		"duplicate-case": `{` + base + `,"Address":"other.example.invalid"}`,
		"TLS-and-REALITY": `{` + base + `,"realitySettings":{}}`,
		"null": `null`,
		"array": `[]`,
		"oversized": `{` + base + `,"xhttpSettings":{"path":"/` + strings.Repeat("x", 8500) + `"}}`,
	}
	for label, down := range cases {
		t.Run(label, func(t *testing.T) {
			extra := `{"downloadSettings":` + down + `}`
			if _, err := conf.ParseNodeURI(prefix + url.QueryEscape(extra)); err == nil {
				t.Fatal("untrusted XHTTP download stream was accepted")
			}
		})
	}
	for label, extra := range map[string]string{
		"download-in-stream-one": `{"downloadSettings":` + xhttpDownloadTLS + `}`,
		"duplicate-outer-field": `{"downloadSettings":` + xhttpDownloadTLS + `,"DownloadSettings":` + xhttpDownloadTLS + `}`,
		"non-xhttp-extra": `{"downloadSettings":` + xhttpDownloadTLS + `}`,
	} {
		t.Run(label, func(t *testing.T) {
			u := prefix + url.QueryEscape(extra)
			if label == "download-in-stream-one" {
				u = "vless://" + xhttpNodeTestID + "@127.0.0.1:443?type=xhttp&mode=stream-one&extra=" + url.QueryEscape(extra)
			} else if label == "non-xhttp-extra" {
				u = "vless://" + xhttpNodeTestID + "@127.0.0.1:443?type=tcp&extra=" + url.QueryEscape(extra)
			}
			if _, err := conf.ParseNodeURI(u); err == nil {
				t.Fatal("invalid XHTTP download mode or input type was accepted")
			}
		})
	}
}

func TestNodeXHTTPDownloadSafeAdvancedPaddingAndXMux(t *testing.T) {
	inner := `{"address":"download.example.invalid","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.example.invalid"},"xhttpSettings":{"host":"download.example.invalid","path":"/down","xPaddingBytes":"64-128","xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingMethod":"tokenish","xmux":{"maxConnections":3,"hMaxRequestTimes":10}}}`
	for _, base := range xhttpNodeProfiles() {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			extra := `{"downloadSettings":` + inner + `}`
			got, err := conf.ParseNodeURI(base + "?type=xhttp&mode=stream-up&extra=" + url.QueryEscape(extra))
			if err != nil { t.Fatal(err) }
			a, err := got.StreamSetting.Build()
			if err != nil { t.Fatal(err) }
			var down conf.StreamConfig
			if err := json.Unmarshal([]byte(inner), &down); err != nil { t.Fatal(err) }
			want := *got.StreamSetting
			want.XHTTPSettings = &conf.SplitHTTPConfig{Mode:"stream-up",DownloadSettings:&down}
			b, err := want.Build()
			if err != nil { t.Fatal(err) }
			if !proto.Equal(a,b) { t.Fatal("nested XHTTP padding/XMux differs from full JSON") }
		})
	}
}

func TestNodeXHTTPDownloadAdvancedRejectsUnboundedInputs(t *testing.T) {
	for label, inner := range map[string]string{
		"too-large-padding":`{"xPaddingBytes":999999}`,
		"invalid-padding-header":`{"xPaddingHeader":"Bad Header"}`,
		"oversized-xmux":`{"xmux":{"maxConnections":999999}}`,
		"bad-placement":`{"xPaddingPlacement":"unknown"}`,
		"nested-extra":`{"extra":{"downloadSettings":{}}}`,
		"header-injection":`{"headers":{"Host":"override.example"}}`,
	} {
		t.Run(label,func(t *testing.T){
			profile := `{"downloadSettings":{"address":"download.example.invalid","port":443,"network":"xhttp","security":"tls","xhttpSettings":` + inner + `}}`
			u := "vless://" + xhttpNodeTestID + "@127.0.0.1:443?type=xhttp&mode=stream-up&extra=" + url.QueryEscape(profile)
			if _,err:=conf.ParseNodeURI(u);err==nil{t.Fatal("unbounded XHTTP metadata accepted")}
		})
	}
}
