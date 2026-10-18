package conf_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

func TestTrustedXDriveExplicitFourProtocolSelection(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	profiles := []string{
		"vless://"+id+"@127.0.0.1:443?type=xdrive",
		"vmess://"+id+"@127.0.0.1:443?type=xdrive",
		"trojan://synthetic@127.0.0.1:443?type=xdrive",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443?type=xdrive",
	}
	for _, uri := range profiles {
		t.Run(strings.SplitN(uri,"://",2)[0],func(t *testing.T){
			if _,err:=conf.ParseNodeURI(uri);err==nil {
				t.Fatal("ordinary untrusted node import must keep rejecting XDrive")
			}
			approved := &conf.XDriveConfig{Service:"local",RemoteFolder:"application-approved-local-folder"}
			got,err:=conf.ParseNodeURIWithTrustedXDrive(uri,approved)
			if err!=nil{t.Fatal(err)}
			if got.StreamSetting.XDRIVESettings == nil ||
				got.StreamSetting.XDRIVESettings.RemoteFolder!="application-approved-local-folder" ||
				got.StreamSetting.Security!="none" {
				t.Fatal("approved XDrive settings missing or changed")
			}
			expectedNetwork:=conf.TransportProtocol("xdrive")
			original:=*got.StreamSetting
			original.Network=&expectedNetwork
			original.XDRIVESettings=&conf.XDriveConfig{Service:"local",RemoteFolder:"application-approved-local-folder"}
			a,err:=got.StreamSetting.Build()
			if err!=nil{t.Fatal(err)}
			b,err:=original.Build()
			if err!=nil{t.Fatal(err)}
			if !proto.Equal(a,b){t.Fatal("trusted XDrive differs from native full JSON")}
			approved.RemoteFolder="mutated"
			if got.StreamSetting.XDRIVESettings.RemoteFolder!="application-approved-local-folder" {
				t.Fatal("approved profile was not cloned")
			}
		})
	}
}

func TestTrustedXDriveVersionedNodeImport(t *testing.T) {
	secret:="synthetic"
	node:=conf.NodeDescription{
		Version:1,Protocol:"trojan",Address:"127.0.0.1",Port:443,
		Credentials:conf.NodeCredentials{Password:&secret},
		Parameters:map[string]string{"type":"xdrive"},
	}
	raw,err:=json.Marshal(node)
	if err!=nil{t.Fatal(err)}
	if _,err:=conf.ParseNodeJSON(raw);err==nil {t.Fatal("untrusted JSON import enabled XDrive")}
	got,err:=conf.ResolveNodeWithTrustedXDrive(&node,&conf.XDriveConfig{
		Service:"local",RemoteFolder:"owner-approved-folder",
	})
	if err!=nil{t.Fatal(err)}
	if got.Outbound.StreamSetting.XDRIVESettings.RemoteFolder!="owner-approved-folder"{
		t.Fatal("trusted profile missing")
	}
	if node.Parameters["type"]!="xdrive"{t.Fatal("original node mutated")}
}

func TestTrustedXDriveRejectsResourceInjection(t *testing.T) {
	const id="11111111-1111-4111-8111-111111111111"
	base:="vless://"+id+"@127.0.0.1:443"
	approved:=&conf.XDriveConfig{Service:"local",RemoteFolder:"owner-approved-folder"}
	for label,query:=range map[string]string{
		"missing-transport":"?type=tcp",
		"unapproved-path":"?type=xdrive&path="+url.QueryEscape("/private/resources"),
		"unapproved-profile":"?type=xdrive&xdriveProfile=internal",
		"unapproved-folder":"?type=xdrive&remoteFolder="+url.QueryEscape("/secrets"),
		"unapproved-service":"?type=xdrive&service=Google%20Drive",
		"extra-security":"?type=xdrive&security=tls",
		"plugin-execution":"?type=xdrive&plugin=obfs-local",
		"uncertain-network":"?type=xdrive&net=tcp",
		"unapproved-template":"?type=xdrive&template=download",
	}{
		t.Run(label,func(t *testing.T){
			if _,err:=conf.ParseNodeURIWithTrustedXDrive(base+query,approved);err==nil{
				t.Fatal("XDrive accepted untrusted local resource metadata")
			}
		})
	}
	if _,err:=conf.ParseNodeURIWithTrustedXDrive(base+"?type=xdrive",nil);err==nil{t.Fatal("unapproved nil profile accepted")}
	if _,err:=conf.ParseNodeURIWithTrustedXDrive(base+"?type=xdrive",&conf.XDriveConfig{Service:"template",RemoteFolder:"any"});err==nil {
		t.Fatal("unreviewed template backend accepted")
	}
	if _,err:=conf.ParseNodeURIWithTrustedXDrive(base+"?type=xdrive",&conf.XDriveConfig{Service:"local"});err==nil{
		t.Fatal("empty local folder accepted")
	}
}

func TestTrustedXDriveSecretIsolation(t *testing.T) {
	profile:=&conf.XDriveConfig{
		Service:"Google Drive",RemoteFolder:"owner-approved-drive",
		Secrets:[]string{"synthetic-client-id","synthetic-client-secret","synthetic-refresh-token"},
	}
	uri:="trojan://synthetic@127.0.0.1:443?type=xdrive"
	out,err:=conf.ParseNodeURIWithTrustedXDrive(uri,profile)
	if err!=nil{t.Fatal(err)}
	profile.Secrets[1]="changed"
	if out.StreamSetting.XDRIVESettings.Secrets[1]!="synthetic-client-secret"{
		t.Fatal("trusted secrets not isolated from caller mutations")
	}
	uri+="&secrets="+url.QueryEscape("private-key")
	_,err=conf.ParseNodeURIWithTrustedXDrive(uri,profile)
	if err==nil||strings.Contains(err.Error(),"private-key"){t.Fatal("untrusted secret accepted or leaked")}
}
