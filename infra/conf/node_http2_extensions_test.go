package conf_test

import (
 "encoding/base64"
 "net/url"
 "strconv"
 "strings"
 "testing"
 "github.com/xtls/xray-core/infra/conf"
 "google.golang.org/protobuf/proto"
)

func TestNodeAdvancedHTTP2FourProtocolParity(t *testing.T) {
 for _,base:=range advancedProfiles() {
  t.Run(strings.SplitN(base,"://",2)[0],func(t *testing.T){
   headers:=`{"X-Route":"synthetic","X-Edge":"test"}`
   got,err:=conf.ParseNodeURI(base+"?type=h2&security=tls&host=front.example.invalid&path=%2Fedge&httpMethod=POST&httpReadIdleTimeout=120&httpHealthCheckTimeout=30&httpHeaders="+url.QueryEscape(headers))
   if err!=nil{t.Fatal(err)}
   fromURI,err:=got.StreamSetting.Build()
   if err!=nil{t.Fatal(err)}
   want:=*got.StreamSetting
   hosts:=conf.StringList{"front.example.invalid"}
   route:=conf.StringList{"synthetic"}
   edge:=conf.StringList{"test"}
   want.HTTPSettings=&conf.HTTPConfig{Host:&hosts,Path:"/edge",Method:"POST",ReadIdleTimeout:120,HealthCheckTimeout:30,Headers:map[string]*conf.StringList{"X-Route":&route,"X-Edge":&edge}}
   expected,err:=want.Build()
   if err!=nil{t.Fatal(err)}
   if !proto.Equal(fromURI,expected){t.Fatal("HTTP2 settings differ from original full JSON builder")}
   if _,err:=got.Build();err!=nil{t.Fatal(err)}
  })
 }
}

func TestNodeAdvancedHTTP2VMessObjectAndString(t *testing.T) {
 headers:=`{"X-Route":"synthetic"}`
 for _,value:=range []string{headers,strconv.Quote(headers)} {
  body:=`{"v":"2","add":"127.0.0.1","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":0,"net":"h2","tls":"tls","httpMethod":"POST","httpHeaders":`+value+`}`
  got,err:=conf.ParseNodeURI("vmess://"+base64.RawStdEncoding.EncodeToString([]byte(body)))
  if err!=nil{t.Fatal(err)}
  if got.StreamSetting.HTTPSettings.Headers["X-Route"]==nil{t.Fatal("VMess HTTP2 header lost")}
  if _,err:=got.Build();err!=nil{t.Fatal(err)}
 }
}

func TestNodeAdvancedHTTP2RejectsUnsafe(t *testing.T) {
 base:="vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type="
 for name,q:=range map[string]string{
  "reserved":"h2&httpHeaders="+url.QueryEscape(`{"Content-Length":"12"}`),
  "host":"h2&httpHeaders="+url.QueryEscape(`{"Host":"override.invalid"}`),
  "duplicate":"h2&httpHeaders="+url.QueryEscape(`{"X-Test":"one","x-test":"two"}`),
  "control":"h2&httpHeaders="+url.QueryEscape(`{"X-Test":"one\r\nEvil:two"}`),
  "method-get":"h2&httpMethod=GET",
  "method-head":"h2&httpMethod=HEAD",
  "bad-timeouts":"h2&httpHealthCheckTimeout=20",
  "bad-idle":"h2&httpReadIdleTimeout=601",
  "unrelated-ws":"ws&httpMethod=POST",
  "unrelated-tcp":"tcp&httpHeaders="+url.QueryEscape(`{"X-Test":"safe"}`),
 } {
  t.Run(name,func(t *testing.T){if _,err:=conf.ParseNodeURI(base+q);err==nil{t.Fatal("unsafe HTTP2 node metadata accepted")}})
 }
}
