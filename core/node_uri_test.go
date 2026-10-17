package core_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/socks"
)

func TestNodeURIFormatAutomaticSelection(t *testing.T) {
	config, err := core.LoadConfig("uri", strings.NewReader("socks4a://synthetic@127.0.0.1:1080#node"))
	if err != nil {
		t.Fatal("node input is not available without a feature switch", err)
	}
	if core.GetFormat("node.uri") != "uri" || len(config.Outbound) != 1 {
		t.Fatal("node input was not recognized automatically")
	}
	value, err := config.Outbound[0].ProxySettings.GetInstance()
	if err != nil || value.(*socks.ClientConfig).Version != socks.ClientVersion_SOCKS4A {
		t.Fatal("node did not select its matching protocol", err)
	}
}
