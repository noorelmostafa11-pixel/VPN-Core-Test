package conf_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

func TestXHTTPDownloadSessionControlsFourProtocolParity(t *testing.T) {
	downJSON := `{"address":"download.example.invalid","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.example.invalid"},"xhttpSettings":{"path":"/down","mode":"packet-up","uplinkHTTPMethod":"GET","sessionIDPlacement":"header","sessionIDKey":"X-Session-Id","seqPlacement":"query","seqKey":"x_seq","uplinkDataPlacement":"cookie","uplinkDataKey":"x_data","uplinkChunkSize":"1024-2048"}}`
	for _, base := range xhttpNodeProfiles() {
		t.Run(strings.SplitN(base, "://", 2)[0], func(t *testing.T) {
			extra := `{"downloadSettings":` + downJSON + `}`
			node, err := conf.ParseNodeURI(base+"?type=xhttp&mode=stream-up&extra="+url.QueryEscape(extra))
			if err != nil { t.Fatal(err) }
			actual, err := node.StreamSetting.Build()
			if err != nil { t.Fatal(err) }
			var down conf.StreamConfig
			if err := json.Unmarshal([]byte(downJSON), &down); err != nil { t.Fatal(err) }
			want := *node.StreamSetting
			want.XHTTPSettings = &conf.SplitHTTPConfig{Mode:"stream-up", DownloadSettings:&down}
			expected, err := want.Build()
			if err != nil { t.Fatal(err) }
			if !proto.Equal(actual, expected) { t.Fatal("download session controls differ from native config") }
		})
	}
}

func TestXHTTPDownloadSessionControlsRejectUnsafe(t *testing.T) {
	cases := map[string]string{
		"bad-method":`{"uplinkHTTPMethod":"TRACE"}`,
		"GET-not-packet":`{"mode":"stream-up","uplinkHTTPMethod":"GET"}`,
		"reserved-header":`{"sessionIDPlacement":"header","sessionIDKey":"Host"}`,
		"bad-header":`{"seqPlacement":"header","seqKey":"Bad Header"}`,
		"bad-cookie":`{"uplinkDataPlacement":"cookie","uplinkDataKey":"invalid;x"}`,
		"bad-query":`{"seqPlacement":"query","seqKey":"unsafe/path"}`,
		"orphaned-key":`{"sessionIDKey":"X-Session"}`,
		"bad-placement":`{"sessionIDPlacement":"filesystem"}`,
		"chunk-small":`{"uplinkChunkSize":"1-1024"}`,
		"chunk-large":`{"uplinkChunkSize":"1024-9999999"}`,
		"recursive":`{"downloadSettings":{"network":"xhttp"}}`,
	}
	for label, xhttp := range cases {
		t.Run(label, func(t *testing.T) {
			inner := `{"downloadSettings":{"address":"download.example.invalid","port":443,"network":"xhttp","security":"tls","xhttpSettings":`+xhttp+`}}`
			uri := "vless://"+xhttpNodeTestID+"@127.0.0.1:443?type=xhttp&mode=stream-up&extra="+url.QueryEscape(inner)
			if _,err:=conf.ParseNodeURI(uri);err==nil { t.Fatal("unsafe download settings accepted") }
		})
	}
}
