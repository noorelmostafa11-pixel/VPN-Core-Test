package core_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/socks"
)

func TestNodeDescriptionFormatAutomaticSelection(t *testing.T) {
	input := `{"version":1,"protocol":"socks4a","address":"127.0.0.1","port":1080,"credentials":{"username":"synthetic"}}`
	config, err := core.LoadConfig("node", strings.NewReader(input))
	if err != nil {
		t.Fatal("node description must enter the normal distribution", err)
	}
	if core.GetFormat("synthetic.node") != "node" || len(config.Outbound) != 1 {
		t.Fatal("node description did not select its input format")
	}
	value, err := config.Outbound[0].ProxySettings.GetInstance()
	if err != nil || value.(*socks.ClientConfig).Version != socks.ClientVersion_SOCKS4A {
		t.Fatal("node description did not select the added handler", err)
	}
}
