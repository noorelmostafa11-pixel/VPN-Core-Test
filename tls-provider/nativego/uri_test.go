package nativego

import (
 "context"
 "encoding/base64"
 "errors"
 "net"
 "testing"
)

func TestGoNativeURIParseTLSAndReality(t *testing.T){
 pub:=base64.RawURLEncoding.EncodeToString(make([]byte,32))
 cases:=[]struct{uri string;protocol,security,address,sni string}{
  {"vless://00112233-4455-6677-8899-aabbccddeeff@198.51.100.8:443?type=tcp&security=tls&sni=example.com","vless","tls","198.51.100.8","example.com"},
  {"vless://00112233-4455-6677-8899-aabbccddeeff@[2001:db8::3]:443?type=tcp&security=reality&sni=example.com&fp=chrome&pbk="+pub+"&sid=01020304","vless","reality","2001:db8::3","example.com"},
  {"trojan://test-password@203.0.113.9:443?type=tcp&security=tls&sni=example.com","trojan","tls","203.0.113.9","example.com"},
 }
 for _,tc:=range cases{
  n,err:=ParseURI(tc.uri)
  if err!=nil{t.Fatalf("parse URI: %v",err)}
  if n.Protocol!=tc.protocol||n.Security!=tc.security||n.Address!=tc.address||n.ServerName!=tc.sni{
   t.Fatalf("wrong config: %+v",n)
  }
  protected:=func(context.Context,string,string)(net.Conn,error){return nil,errors.New("offline test")}
  if _,err=NewDialer(n,protected);err!=nil{t.Fatalf("valid supported node: %v",err)}
 }
}

func TestGoNativeURIRejectsDowngradeAndUnknownOptions(t *testing.T){
 base:="vless://00112233-4455-6677-8899-aabbccddeeff@1.2.3.4:443?"
 bad:=[]string{
  "type=websocket&security=tls&sni=example.com",
  "security=none&sni=example.com",
  "security=tls&sni=example.com&allowInsecure=1",
  "security=tls&sni=example.com&unknown=1",
  "security=tls&sni=example.com&fp=chrome&fp=firefox",
  "security=tls&sni=example.com&fp=%ZZ",
 }
 for _,query:=range bad{
  if _,err:=ParseURI(base+query);err==nil{t.Fatalf("accepted dangerous query %s",query)}
 }
}
func TestGoNativeURIVisionMustNotDowngrade(t *testing.T){
 n,err:=ParseURI("vless://00112233-4455-6677-8899-aabbccddeeff@1.2.3.4:443?security=tls&sni=example.com&flow=xtls-rprx-vision")
 if err!=nil{t.Fatal(err)}
 protect:=func(context.Context,string,string)(net.Conn,error){t.Fatal("called protected socket");return nil,nil}
 if _,err=NewDialer(n,protect);!errors.Is(err,ErrUnsupported){t.Fatalf("silent Vision downgrade: %v",err)}
}
func TestGoNativeEndpointIPRejectsUnsafe(t *testing.T){
 for _,ip:=range []string{"","0.0.0.0","::","224.0.0.1","ff02::1","not an IP"}{
  if _,err:=EndpointIP(ip);err==nil{t.Fatalf("accepted unsafe bootstrap: %q",ip)}
 }
 if _,err:=EndpointIP("198.51.100.8");err!=nil{t.Fatal(err)}
}
