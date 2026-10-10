package nativego

import (
 "context"
 "encoding/base64"
 "errors"
 "net"
 "testing"
)

func TestGoRealityFailClosedPreflight(t *testing.T){
 var called bool
 protect:=func(context.Context,string,string)(net.Conn,error){called=true;return nil,errors.New("unexpected socket")}
 base:=Node{
  Protocol:"vless",Address:"203.0.113.9",Port:443,ServerName:"example.com",
  Security:"reality",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff",
 }
 cases:=[]struct{name string;pub,short string}{
  {"missing","", ""},
  {"malformed","invalid-key", "0123"},
  {"wrong-key-size",base64.RawURLEncoding.EncodeToString(make([]byte,31)),"0123"},
  {"bad-short-id",base64.RawURLEncoding.EncodeToString(make([]byte,32)),"zz"},
  {"overlong-short-id",base64.RawURLEncoding.EncodeToString(make([]byte,32)),"0123456789abcdef00"},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   n:=base;n.PublicKey=tc.pub;n.ShortID=tc.short
   if _,err:=NewDialer(n,protect);!errors.Is(err,ErrUnsupported){t.Fatalf("expected fail closed: %v",err)}
  })
 }
 if called{t.Fatal("invalid REALITY config contacted a network")}
}

func TestGoRealitySupportsPinnedConfiguration(t *testing.T){
 n:=Node{
  Protocol:"vless",Address:"203.0.113.9",Port:443,ServerName:"example.com",
  Security:"reality",Transport:"raw",Fingerprint:"chrome",
  UUID:"00112233-4455-6677-8899-aabbccddeeff",
  PublicKey:base64.RawURLEncoding.EncodeToString(make([]byte,32)),
  ShortID:"01234567",
 }
 protect:=func(context.Context,string,string)(net.Conn,error){return nil,errors.New("test only")}
 d,err:=NewDialer(n,protect)
 if err!=nil||d==nil{t.Fatalf("REALITY configuration rejected before TLS proof: %v",err)}
 n.Flow="xtls-rprx-vision"
 if _,err=NewDialer(n,protect);!errors.Is(err,ErrUnsupported){t.Fatalf("Vision cannot be silently downgraded: %v",err)}
}
