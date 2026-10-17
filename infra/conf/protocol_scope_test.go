package conf

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestFourProtocolRegistrations(t *testing.T) {
	for _, test := range []struct {
		loader *JSONConfigLoader
		want   []string
	}{
		{inboundConfigLoader, []string{"dokodemo-door", "http", "mixed", "shadowsocks", "socks", "trojan", "tun", "tunnel", "vless", "vmess"}},
		{outboundConfigLoader, []string{"blackhole", "block", "direct", "dns", "freedom", "loopback", "shadowsocks", "trojan", "vless", "vmess"}},
	} {
		var got []string
		for name := range test.loader.cache {
			got = append(got, name)
		}
		slices.Sort(got)
		slices.Sort(test.want)
		if !slices.Equal(got, test.want) {
			t.Fatal("unexpected proxy registration", got)
		}
	}
}

func TestFourProtocolScopeRejectsOtherNodes(t *testing.T) {
	password := "do-not-echo-secret"
	for _, protocol := range []string{"ssh", "hysteria", "hysteria1", "hy2", "hysteria2", "tuic", "anytls", "shadowtls", "wireguard", "masque", "socks", "socks4", "socks4a", "socks5", "http", "https", "freedom", "direct", "dns", "blackhole"} {
		for _, name := range []string{protocol, strings.ToUpper(protocol)} {
			if _, err := DescribeNodeURI(name + "://" + password + "@127.0.0.1:443"); err == nil || strings.Contains(err.Error(), password) {
				t.Fatal("excluded URI accepted or leaked credentials", name, err)
			}
			node := &NodeDescription{Version: 1, Protocol: name, Address: "127.0.0.1", Port: 443, Credentials: NodeCredentials{Password: &password}}
			if _, err := ResolveNode(node); err == nil || strings.Contains(err.Error(), password) {
				t.Fatal("excluded Go node accepted or leaked credentials", name, err)
			}
			body, err := json.Marshal(node)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseNodeJSON(body); err == nil || strings.Contains(err.Error(), password) {
				t.Fatal("excluded JSON node accepted or leaked credentials", name, err)
			}
		}
	}
	for _, protocol := range []string{"ssh", "hysteria", "hysteria1", "hy2", "hysteria2", "tuic", "anytls", "shadowtls", "wireguard", "masque"} {
		if _, err := (&InboundDetourConfig{Protocol: protocol}).Build(); err == nil {
			t.Fatal("excluded full JSON inbound accepted", protocol)
		}
	}
	for _, protocol := range []string{"ssh", "hysteria", "hysteria1", "hy2", "hysteria2", "tuic", "anytls", "shadowtls", "wireguard", "masque", "socks", "socks4", "socks4a", "http"} {
		if _, err := (&OutboundDetourConfig{Protocol: protocol}).Build(); err == nil {
			t.Fatal("excluded full JSON outbound accepted", protocol)
		}
	}
	for _, protocol := range []TransportProtocol{"hysteria", "masque"} {
		if _, err := protocol.Build(); err == nil {
			t.Fatal("excluded transport accepted", protocol)
		}
	}
}

func TestFourProtocolNodeTLSTrustMetadata(t *testing.T) {
	const id = "11111111-2222-4333-8444-555555555555"
	pin := strings.Repeat("47", 32)
	for _, base := range []string{"trojan://synthetic@127.0.0.1:443?security=tls", "vless://" + id + "@127.0.0.1:443?security=tls", "vmess://" + id + "@127.0.0.1:443?security=tls", "ss://aes-128-gcm:synthetic@127.0.0.1:443?security=tls"} {
		node, err := ParseNodeURI(base + "&pcs=" + pin + "&vcn=scope.example")
		if err != nil || node.StreamSetting.TLSSettings.PinnedPeerCertSha256 != pin || node.StreamSetting.TLSSettings.VerifyPeerCertByName != "scope.example" || node.StreamSetting.TLSSettings.AllowInsecure {
			t.Fatal("explicit TLS trust metadata changed", err)
		}
		for _, extra := range []string{"&pcs=invalid", "&pcs=" + pin + "&pinsha256=" + strings.Repeat("48", 32), "&insecure=true"} {
			if _, err := ParseNodeURI(base + extra); err == nil {
				t.Fatal("invalid trust accepted", extra)
			}
		}
	}
	if _, err := ParseNodeURI("vless://" + id + "@127.0.0.1:443?pcs=" + pin); err == nil {
		t.Fatal("TLS trust silently ignored on an unencrypted stream")
	}
}
