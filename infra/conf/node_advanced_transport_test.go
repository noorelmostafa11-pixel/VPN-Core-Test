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

const advancedNodeID = "11111111-1111-4111-8111-111111111111"

func advancedProfiles() []string {
	return []string{
		"vless://" + advancedNodeID + "@127.0.0.1:443",
		"vmess://" + advancedNodeID + "@127.0.0.1:443",
		"trojan://synthetic@127.0.0.1:443",
		"ss://aes-128-gcm:synthetic@127.0.0.1:443",
	}
}

func TestAddedWebSocketAndHTTPUpgradeHeadersFourProtocolParity(t *testing.T) {
	for _, item := range []struct{
		network string
		key string
	}{
		{"ws","wsHeaders"}, {"httpupgrade","httpUpgradeHeaders"},
	} {
		for _, base := range advancedProfiles() {
			t.Run(strings.SplitN(base,"://",2)[0]+"/"+item.network,func(t *testing.T){
				uri := base+"?type="+item.network+"&host=front.example.invalid&path=%2Fedge&"+item.key+"="+url.QueryEscape(`{"X-Route":"synthetic","X-Session":"staged"}`)
				got,err:=conf.ParseNodeURI(uri)
				if err!=nil {t.Fatal(err)}
				observed,err:=got.StreamSetting.Build()
				if err!=nil {t.Fatal(err)}
				want:=*got.StreamSetting
				headers:=map[string]string{"X-Route":"synthetic","X-Session":"staged"}
				if item.network=="ws" {
					want.WSSettings=&conf.WebSocketConfig{Host:"front.example.invalid",Path:"/edge",Headers:headers}
				} else {
					want.HTTPUPGRADESettings=&conf.HttpUpgradeConfig{Host:"front.example.invalid",Path:"/edge",Headers:headers}
				}
				expected,err:=want.Build()
				if err!=nil {t.Fatal(err)}
				if !proto.Equal(observed,expected) {t.Fatal("node headers differ from existing JSON transport")}
			})
		}
	}
}

func TestAddedWebSocketHeartbeatAndGRPCParameters(t *testing.T) {
	for _, base := range advancedProfiles() {
		t.Run(strings.SplitN(base,"://",2)[0],func(t *testing.T){
			ws,err:=conf.ParseNodeURI(base+"?type=ws&wsHeartbeatPeriod=25")
			if err!=nil || ws.StreamSetting.WSSettings.HeartbeatPeriod!=25 {t.Fatal("WS heartbeat",err)}
			if _,err:=ws.Build();err!=nil{t.Fatal(err)}
			gr,err:=conf.ParseNodeURI(base+"?type=grpc&serviceName=synthetic&grpcIdleTimeout=120&grpcHealthCheckTimeout=20&grpcInitialWindowSize=65535&grpcPermitWithoutStream=true&grpcUserAgent=TestAgent")
			if err!=nil {t.Fatal(err)}
			g:=gr.StreamSetting.GRPCSettings
			if g.IdleTimeout!=120 || g.HealthCheckTimeout!=20 || g.InitialWindowsSize!=65535 || !g.PermitWithoutStream || g.UserAgent!="TestAgent" {t.Fatal("gRPC configuration dropped")}
			if _,err:=gr.Build();err!=nil{t.Fatal(err)}
		})
	}
}

func TestAddedHTTPHeaderShareVMessJSONAndVersionedNode(t *testing.T) {
	headers:=`{"X-Route":"synthetic"}`
	encoded,err:=json.Marshal(map[string]any{"v":"2","add":"127.0.0.1","port":"443","id":advancedNodeID,"aid":0,"scy":"auto","net":"ws","type":"none","wsHeaders":json.RawMessage(headers)})
	if err!=nil{t.Fatal(err)}
	vmess,err:=conf.ParseNodeURI("vmess://"+base64.RawStdEncoding.EncodeToString(encoded))
	if err!=nil{t.Fatal(err)}
	if vmess.StreamSetting.WSSettings.Headers["X-Route"]!="synthetic"{t.Fatal("VMess JSON headers lost")}
	pass:="synthetic"
	node:=conf.NodeDescription{Version:1,Protocol:"trojan",Address:"127.0.0.1",Port:443,Credentials:conf.NodeCredentials{Password:&pass},Parameters:map[string]string{"type":"ws","wsheaders":headers}}
	raw,err:=json.Marshal(node)
	if err!=nil{t.Fatal(err)}
	structured,err:=conf.ParseNodeJSON(raw)
	if err!=nil{t.Fatal(err)}
	if structured.StreamSetting.WSSettings.Headers["X-Route"]!="synthetic"{t.Fatal("node JSON headers lost")}
}

func TestAddedAdvancedTransportRejectsUnsafeMetadata(t *testing.T) {
	base:="vless://"+advancedNodeID+"@127.0.0.1:443?type="
	cases:=map[string]string{
		"ws-empty-headers":"ws&wsHeaders=",
		"ws-invalid-headers":"ws&wsHeaders="+url.QueryEscape(`{"Host":"override.example"}`),
		"ws-control-header":"ws&wsHeaders="+url.QueryEscape(`{"X-Test":"evil\r\nHost: bad"}`),
		"ws-duplicate-header":"ws&wsHeaders="+url.QueryEscape(`{"X-Test":"a","x-test":"b"}`),
		"ws-bad-header-name":"ws&wsHeaders="+url.QueryEscape(`{"Bad Key":"x"}`),
		"upgrade-host-header":"httpupgrade&httpUpgradeHeaders="+url.QueryEscape(`{"host":"override"}`),
		"ws-out-of-range-heartbeat":"ws&wsHeartbeatPeriod=99999",
		"grpc-invalid-window":"grpc&grpcInitialWindowSize=16",
		"grpc-negative-idle":"grpc&grpcIdleTimeout=-1",
		"grpc-bad-bool":"grpc&grpcPermitWithoutStream=maybe",
		"grpc-bad-agent":"grpc&grpcUserAgent="+url.QueryEscape("agent\r\nHost: bad"),
		"unrelated-ws-headers":"tcp&wsHeaders="+url.QueryEscape(`{"X-Test":"synthetic"}`),
		"unrelated-grpc-knobs":"ws&grpcIdleTimeout=5",
	}
	for label,query:=range cases {
		t.Run(label,func(t *testing.T){if _,err:=conf.ParseNodeURI(base+query);err==nil{t.Fatal("unsafe transport metadata accepted")}})
	}
}
