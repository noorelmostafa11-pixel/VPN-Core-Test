package core_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/trojan"
)

func TestNodeURIFormatAutomaticSelection(t *testing.T) {
	config, err := core.LoadConfig("uri", strings.NewReader("trojan://synthetic@127.0.0.1:443#node"))
	if err != nil {
		t.Fatal("node input is not available without a feature switch", err)
	}
	if core.GetFormat("node.uri") != "uri" || len(config.Outbound) != 1 {
		t.Fatal("node input was not recognized automatically")
	}
	value, err := config.Outbound[0].ProxySettings.GetInstance()
	if err != nil || value.(*trojan.ClientConfig).Server.User == nil {
		t.Fatal("node did not select its matching protocol", err)
	}
}
