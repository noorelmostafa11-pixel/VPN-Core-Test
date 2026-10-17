package conf_test

import (
    "bytes"
    "encoding/base64"
    "net/url"
    "testing"

    "github.com/xtls/xray-core/infra/conf"
    ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
    "google.golang.org/protobuf/proto"
)

// Keep SS2022 in the four-family transport-import matrix. A working share
// link must select the SS2022 outbound, not a classic Shadowsocks fallback.
func TestAddedSS2022TransportHeadersAliasParity(t *testing.T) {
    for _, item := range []struct { method string; keySize int }{
        {ss2022.MethodAES128GCM, 16},
        {ss2022.MethodAES256GCM, 32},
        {ss2022.MethodChaCha20Poly1305, 32},
    } {
        t.Run(item.method, func(t *testing.T) {
            key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, item.keySize))
            base := "ss://" + url.UserPassword(item.method, key).String() + "@127.0.0.1:443"
            for _, network := range []string{"ws", "httpupgrade"} {
                t.Run(network, func(t *testing.T) {
                    raw := `{"X-Route":"synthetic"}`
                    uri := base + "?type=" + network + "&headers=" + url.QueryEscape(raw)
                    got, err := conf.ParseNodeURI(uri)
                    if err != nil { t.Fatal(err) }
                    legacyName := "wsHeaders"
                    if network == "httpupgrade" { legacyName = "httpupgradeHeaders" }
                    old, err := conf.ParseNodeURI(base + "?type=" + network + "&" + legacyName + "=" + url.QueryEscape(raw))
                    if err != nil { t.Fatal(err) }
                    gotStream, err := got.StreamSetting.Build()
                    if err != nil { t.Fatal(err) }
                    oldStream, err := old.StreamSetting.Build()
                    if err != nil { t.Fatal(err) }
                    if !proto.Equal(gotStream, oldStream) { t.Fatal("SS2022 transport settings changed under headers alias") }
                    built, err := got.Build()
                    if err != nil { t.Fatal(err) }
                    proxy, err := built.ProxySettings.GetInstance()
                    if err != nil { t.Fatal(err) }
                    selected, ok := proxy.(*ss2022.ClientConfig)
                    if !ok || selected.Method != item.method || selected.Key != key {
                        t.Fatal("SS2022 method/key changed or fell back to classic Shadowsocks")
                    }
                })
            }
        })
    }
}

func TestAddedSS2022TransportHeadersAliasRejectsUnsafe(t *testing.T) {
    key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))
    base := "ss://" + url.UserPassword(ss2022.MethodAES128GCM, key).String() + "@127.0.0.1:443?type="
    for _, item := range []struct{ network, raw string }{
        {"ws", `{"Host":"override.invalid"}`},
        {"httpupgrade", `{"Connection":"close"}`},
        {"ws", `{"X-Route":"one","x-route":"two"}`},
        {"ws", `{"X-Route":"line\r\nInjected: yes"}`},
        {"grpc", `{"X-Route":"synthetic"}`},
        {"tcp", `{"X-Route":"synthetic"}`},
    } {
        if _, err := conf.ParseNodeURI(base + item.network + "&headers=" + url.QueryEscape(item.raw)); err == nil {
            t.Fatal("unsafe SS2022 transport header accepted", item.network, item.raw)
        }
    }
}
