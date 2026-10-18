package conf

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/sip003"
)

func TestTrustedSIP003ObfsHTTPAndTLS(t *testing.T) {
	trusted:=sip003.Approved{Name:"obfs-local"}
	for _,mode:=range []string{"http","tls"}{
		options,err:=trustedSIP003Options("obfs-local;obfs="+mode+";obfs-host=front.example.invalid",trusted)
		if err!=nil||options!="obfs="+mode+";obfs-host=front.example.invalid"{t.Fatal(mode,err)}
		alias,err:=trustedSIP003Options("simple-obfs;obfs="+mode,trusted)
		if err!=nil||alias!="obfs="+mode{t.Fatal("alias",err)}
	}
	for _,bad:=range []string{"obfs-local","obfs-local;obfs=invalid","obfs-local;obfs=http;obfs=http",
		"obfs-local;obfs=tls;obfs-host=/private/key","obfs-local;obfs=tls;cert=secret"}{
		if _,err:=trustedSIP003Options(bad,trusted);err==nil{t.Fatal("unsafe obfs accepted")}
	}
}

func TestTrustedSIP003V2RayExternalMuxAndQUIC(t *testing.T) {
	trusted:=sip003.Approved{Name:"v2ray-plugin"}
	for _,option:=range []string{"v2ray-plugin;mode=websocket;mux=1;tls;path=/edge",
		"v2ray-plugin;mode=quic;host=front.example.invalid;mux=4"}{
		if _,err:=trustedSIP003Options(option,trusted);err!=nil{t.Fatal(err)}
	}
	for _,bad:=range []string{"v2ray-plugin;cert=/secret.pem","v2ray-plugin;mux=999",
		"v2ray-plugin;mode=invalid","v2ray-plugin;host=env:PRIVATE_ADDRESS",
		"v2ray-plugin;path=//other.example","v2ray-plugin;tls;tls"}{
		if _,err:=trustedSIP003Options(bad,trusted);err==nil{t.Fatal("unsupported option accepted")}
	}
}

func TestTrustedSIP003UntrustedImportRemainsClosed(t *testing.T){
	url1:="ss://aes-128-gcm:synthetic@127.0.0.1:443?plugin="+url.QueryEscape("obfs-local;obfs=http")
	if _,err:=ParseNodeURI(url1);err==nil{t.Fatal("ordinary URI unexpectedly launches SIP003")}
	if _,closer,err:=ParseNodeURIWithTrustedSIP003(context.Background(),url1,sip003.Approved{Name:"obfs-local"});err==nil||closer!=nil{
		t.Fatal("approved executable pin was not required")
	}
	for _,base:=range []string{
		"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"vmess://11111111-1111-4111-8111-111111111111@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
	}{
		u:=base+"?plugin="+url.QueryEscape("obfs-local;obfs=tls")
		if node,err:=DescribeNodeURI(u);err==nil{
			_,_,err=ResolveNodeWithTrustedSIP003(context.Background(),node,sip003.Approved{Name:"obfs-local"})
			if err==nil||strings.Contains(err.Error(),"synthetic"){t.Fatal("unsupported protocol or credential leaked")}
		}
	}
}
