package serial_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestNodeDescriptionReaderBounds(t *testing.T) {
	for _, input := range []string{strings.Repeat("x", conf.MaxNodeURIBytes+1), `{} {}`, `{"outbounds":[]}`} {
		if _, err := serial.DecodeNodeConfig(strings.NewReader(input)); err == nil {
			t.Fatal("invalid node reader accepted")
		}
	}
	if _, err := serial.DecodeNodeConfig(failedNodeReader{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("node reader exposed context", err)
	}
}
