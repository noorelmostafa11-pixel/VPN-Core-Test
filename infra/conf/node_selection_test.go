package conf_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

func TestNodeUnifiedSelection(t *testing.T) {
	password := "synthetic"
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		name, uri   string
		credentials conf.NodeCredentials
		parameters  map[string]string
		addons      []conf.NodeAddon
	}{
		{"base-vless", "vless://" + nodeID + "@127.0.0.1:443", conf.NodeCredentials{ID: nodeID}, nil, nil},
		{"base-vmess", "vmess://" + nodeID + "@127.0.0.1:443?encryption=aes-128-gcm", conf.NodeCredentials{ID: nodeID}, map[string]string{"encryption": "aes-128-gcm"}, nil},
		{"base-socks", "socks5://synthetic@127.0.0.1:443", conf.NodeCredentials{Username: password}, nil, nil},
		{"vmess-body", "vmess://" + nodeID + "@127.0.0.1:443?encryption=aes-128-cfb", conf.NodeCredentials{ID: nodeID}, map[string]string{"encryption": "aes-128-cfb"}, []conf.NodeAddon{conf.NodeVMessBody}},
		{"vmess-header", "vmess://" + nodeID + "@127.0.0.1:443?aid=16", conf.NodeCredentials{ID: nodeID}, map[string]string{"aid": "16"}, []conf.NodeAddon{conf.NodeVMessHeader}},
		{"vmess-both", "vmess://" + nodeID + "@127.0.0.1:443?aid=64&encryption=none", conf.NodeCredentials{ID: nodeID}, map[string]string{"aid": "64", "encryption": "none"}, []conf.NodeAddon{conf.NodeVMessBody, conf.NodeVMessHeader}},
		{"added-ss", "ss://aes-192-gcm:synthetic@127.0.0.1:443", conf.NodeCredentials{Method: "aes-192-gcm", Password: &password}, nil, []conf.NodeAddon{conf.NodeSSCipher, conf.NodeSSServerFirst}},
		{"original-ss-node-contract", "ss://aes-128-gcm:synthetic@127.0.0.1:443", conf.NodeCredentials{Method: "aes-128-gcm", Password: &password}, nil, []conf.NodeAddon{conf.NodeSSServerFirst}},
		{"socks4a", "socks4a://synthetic@127.0.0.1:443", conf.NodeCredentials{Username: password}, nil, []conf.NodeAddon{conf.NodeSOCKS4}},
		{"http2", "vless://" + nodeID + "@127.0.0.1:443?type=h2c", conf.NodeCredentials{ID: nodeID}, map[string]string{"type": "h2c"}, []conf.NodeAddon{conf.NodeHTTP2}},
		{"http2-reality", "vless://" + nodeID + "@127.0.0.1:443?type=h2&security=reality&sni=example.invalid&pbk=" + key + "&sid=ab", conf.NodeCredentials{ID: nodeID}, map[string]string{"type": "h2", "security": "reality", "sni": "example.invalid", "pbk": key, "sid": "ab"}, []conf.NodeAddon{conf.NodeHTTP2}},
		{"quic", "vless://" + nodeID + "@127.0.0.1:443?type=quic&quicsecurity=aes-128-gcm&headerType=dtls", conf.NodeCredentials{ID: nodeID}, map[string]string{"type": "quic", "quicsecurity": "aes-128-gcm", "headertype": "dtls"}, []conf.NodeAddon{conf.NodeQUIC}},
		{"base-tls", "trojan://synthetic@127.0.0.1:443", conf.NodeCredentials{Password: &password}, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			scheme, _, _ := strings.Cut(test.uri, "://")
			node := &conf.NodeDescription{Version: 1, Protocol: scheme, Address: "127.0.0.1", Port: 443, Credentials: test.credentials, Parameters: test.parameters}
			before, _ := json.Marshal(node)
			direct, err := conf.ResolveNode(node)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(direct.Addons, test.addons) {
				t.Fatalf("wrong capabilities: %v, want %v", direct.Addons, test.addons)
			}
			uri, err := conf.ParseNodeURI(test.uri)
			if err != nil {
				t.Fatal(err)
			}
			structured, err := conf.ParseNodeJSON(before)
			if err != nil {
				t.Fatal(err)
			}
			want, err := direct.Outbound.Build()
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []*conf.OutboundDetourConfig{uri, structured} {
				got, err := candidate.Build()
				if err != nil || !proto.Equal(want, got) {
					t.Fatal("equivalent node descriptions selected different core configurations", err)
				}
			}
			after, _ := json.Marshal(node)
			if !bytes.Equal(before, after) {
				t.Fatal("selection rewrote caller data")
			}
		})
	}
}

func TestNodeDescriptionCipherMatrix(t *testing.T) {
	for _, cipher := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb", "none", "zero"} {
		for _, count := range []int{0, 16, 64} {
			node := &conf.NodeDescription{Version: 1, Protocol: "vmess", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{ID: nodeID}, Parameters: map[string]string{"cipher": cipher, "aid": fmt.Sprint(count)}}
			data, _ := json.Marshal(node)
			got, err := conf.ParseNodeJSON(data)
			if err != nil {
				t.Fatal(err)
			}
			want, err := conf.ParseNodeURI(fmt.Sprintf("vmess://%s@127.0.0.1:443?cipher=%s&aid=%d", nodeID, cipher, count))
			if err != nil {
				t.Fatal(err)
			}
			gotPB, err := got.Build()
			if err != nil {
				t.Fatal(err)
			}
			wantPB, err := want.Build()
			if err != nil || !proto.Equal(gotPB, wantPB) {
				t.Fatal("cipher/header semantics differ across formats", err)
			}
		}
	}
}

func TestNodeBaseDescriptionMatchesOriginal(t *testing.T) {
	for _, test := range []struct{ uri, settings, protocol string }{
		{"vless://" + nodeID + "@127.0.0.1:443", `{"address":"127.0.0.1","port":443,"id":"` + nodeID + `","encryption":"none"}`, "vless"},
		{"vmess://" + nodeID + "@127.0.0.1:443?cipher=aes-128-gcm", `{"address":"127.0.0.1","port":443,"id":"` + nodeID + `","security":"aes-128-gcm"}`, "vmess"},
		{"socks5://127.0.0.1:1080", `{"address":"127.0.0.1","port":1080}`, "socks"},
	} {
		description, err := conf.DescribeNodeURI(test.uri)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := conf.ResolveNode(description)
		if err != nil || len(selection.Addons) != 0 {
			t.Fatal("base node selected an addition", err)
		}
		got, err := selection.Outbound.Build()
		if err != nil {
			t.Fatal(err)
		}
		raw := json.RawMessage(test.settings)
		// The description explicitly represents ordinary TCP/none; compare
		// that stream to the original config with the same declared data.
		network := conf.TransportProtocol("tcp")
		original := &conf.OutboundDetourConfig{Protocol: test.protocol, Settings: &raw, StreamSetting: &conf.StreamConfig{Network: &network, Security: "none"}}
		want, err := original.Build()
		if err != nil || !proto.Equal(got, want) {
			t.Fatal("base handler settings changed", err)
		}
	}
}

func TestNodeDescriptionRejectsAmbiguity(t *testing.T) {
	const prefix = `{"version":1,"protocol":"socks4a","address":"127.0.0.1","port":1080`
	for _, input := range []string{
		`null`, `[]`, `{}`, prefix + `,"version":1}`, prefix + `,"PORT":1080}`, prefix + `,"version":2}`,
		prefix + `,"credentials":{"username":"synthetic","Username":"other"}}`,
		prefix + `,"parameters":{"security":"tls","SECURITY":"none"}}`,
		prefix + `,"legacySettings":{}}`, prefix + `,"outbounds":[]}`, prefix + `,"parameters":{"enableLegacy":"true"}}`,
		prefix + `,"credentials":{"password":"do-not-echo-secret"}}`,
		prefix + `,"parameters":{"type":"h2c","security":"tls"}}`,
		prefix + `,"parameters":{"type":"quic","security":"tls","fp":"chrome"}}`,
		prefix + `,"parameters":{"security":"none","sni":"secret"}}`,
		prefix + `,"parameters":{"type":"ws","unknown":"secret"}}`,
		prefix + `,"credentials":{"id":"secret"}}`, prefix + `} {}`,
		prefix + `,"parameters":{"nested":{}}}`, strings.Repeat("x", conf.MaxNodeURIBytes+1),
	} {
		if _, err := conf.ParseNodeJSON([]byte(input)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("ambiguous/invalid node accepted or input exposed", err)
		}
	}
	for _, node := range []*conf.NodeDescription{
		nil,
		{Version: 2},
		{Version: 1, Protocol: "tuic", Address: "127.0.0.1", Port: 443},
		{Version: 1, Protocol: "vmess", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{ID: nodeID}, Parameters: map[string]string{"aid": "65"}},
		{Version: 1, Protocol: "socks", Address: "127.0.0.1", Port: 443, Parameters: map[string]string{"Type": "tcp", "type": "tcp"}},
		{Version: 1, Protocol: "socks", Address: "127.0.0.1", Port: 443, Name: strings.Repeat("x", conf.MaxNodeURIBytes+1)},
	} {
		if _, err := conf.ResolveNode(node); err == nil {
			t.Fatal("invalid Go description accepted")
		}
	}
}

func TestNodeDescriptionConcurrentReadOnly(t *testing.T) {
	node := &conf.NodeDescription{Version: 1, Protocol: "vmess", Address: "127.0.0.1", Port: 443, Credentials: conf.NodeCredentials{ID: nodeID}, Parameters: map[string]string{"aid": "16", "encryption": "aes-128-cfb"}}
	before, _ := json.Marshal(node)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 8 {
				selection, err := conf.ResolveNode(node)
				if err != nil {
					t.Error(err)
					return
				}
				// The resolver owns its output; mutating it cannot affect another
				// call or the shared source description.
				selection.Addons[0] = "caller-only"
			}
		})
	}
	workers.Wait()
	after, _ := json.Marshal(node)
	if !bytes.Equal(before, after) {
		t.Fatal("shared node description was mutated")
	}
}

func FuzzNodeDescription(f *testing.F) {
	for _, input := range []string{`{}`, `null`, `{"version":1,"protocol":"socks4a","address":"127.0.0.1","port":1080}`, `{"version":1,"protocol":"vmess","address":"127.0.0.1","port":443,"credentials":{"id":"` + nodeID + `"},"parameters":{"aid":"16","cipher":"aes-128-cfb"}}`} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		outbound, err := conf.ParseNodeJSON(input)
		if err == nil {
			if outbound == nil {
				t.Fatal("accepted node missing outbound")
			}
			if _, err := outbound.Build(); err != nil {
				t.Fatal("accepted node cannot build", err)
			}
		}
	})
}
