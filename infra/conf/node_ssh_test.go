package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

var nodeSSHPin = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))

func TestNodeSSHEquivalentInputs(t *testing.T) {
	password := "synthetic:@+/password"
	uri := "ssh://" + url.UserPassword("user", password).String() + "@127.0.0.1/?hostkey=" + url.QueryEscape(nodeSSHPin) + "&security=ssh&type=raw"
	node, err := conf.DescribeNodeURI(uri)
	if err != nil || node.Port != 22 {
		t.Fatal("SSH default endpoint unavailable", err)
	}
	selection, err := conf.ResolveNode(node)
	if err != nil || len(selection.Addons) != 1 || selection.Addons[0] != conf.NodeSSH {
		t.Fatal("SSH not automatically selected", err)
	}
	want, err := selection.Outbound.Build()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(node)
	fromJSON, err := conf.ParseNodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	fromURI, err := conf.ParseNodeURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*conf.OutboundDetourConfig{fromJSON, fromURI} {
		got, err := candidate.Build()
		if err != nil || !proto.Equal(got, want) {
			t.Fatal("URI/node/Go SSH selection differs", err)
		}
		proxy, err := got.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		client := proxy.(*ssh.ClientConfig)
		if client.Username != "user" || client.Password != password || client.HostKey != nodeSSHPin || client.Port != 22 || candidate.StreamSetting.Security != "none" || candidate.StreamSetting.TLSSettings != nil {
			t.Fatal("SSH credentials, host verification or outer socket was changed")
		}
	}
}

func TestNodeSSHRejectsUnverifiedOrAmbiguousMetadata(t *testing.T) {
	base := "ssh://user:secret@127.0.0.1:22?"
	pin := "hostkey=" + url.QueryEscape(nodeSSHPin)
	for _, query := range []string{
		"", "hostkey=secret", "hostkey=SHA256:abc", "hostkey=" + url.QueryEscape(nodeSSHPin+"="),
		pin + "&host-key=SHA256:other", pin + "&security=tls", pin + "&security=none", pin + "&type=ws", pin + "&type=kcp",
		pin + "&fp=chrome", pin + "&sni=ignored", pin + "&insecure=true", pin + "&path=ignored", pin + "&host=ignored",
		pin + "&private-key=C:/secret", pin + "&private-key-passphrase=secret", pin + "&known-hosts=C:/secret", pin + "&unknown=secret",
	} {
		if _, err := conf.ParseNodeURI(base + query); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid SSH import accepted or exposed credentials", err)
		}
	}
	for _, credentials := range []string{"", "user", "user:", ":secret", "u%0Aser:secret"} {
		if _, err := conf.ParseNodeURI("ssh://" + credentials + "@127.0.0.1:22?" + pin); err == nil {
			t.Fatal("missing SSH credentials accepted")
		}
	}
}

func TestSSHSettingsRejectUnsupportedOrDuplicateOptions(t *testing.T) {
	for _, data := range []string{`null`, `{"username":"user","Username":"other"}`, `{"hostKey":"pin","knownHostsFile":"secret"}`, `{"username":"user"} {}`, `{"algorithms":["unknown"]}`} {
		var client conf.SSHClientConfig
		var server conf.SSHServerConfig
		if err := json.Unmarshal([]byte(data), &client); err == nil {
			t.Fatal("unsupported SSH client settings accepted")
		}
		if err := json.Unmarshal([]byte(data), &server); err == nil {
			t.Fatal("unsupported SSH server settings accepted")
		}
	}
}
