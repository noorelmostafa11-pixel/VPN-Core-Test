package serial_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

type failedNodeReader struct{}

func (failedNodeReader) Read([]byte) (int, error) { return 0, errors.New("private-reader-secret") }

func TestNodeReaderBoundsAndErrors(t *testing.T) {
	for _, input := range []string{"trojan://127.0.0.1:1080\nsocks5://127.0.0.1:1080", strings.Repeat("x", conf.MaxNodeURIBytes+1)} {
		if _, err := serial.DecodeURIConfig(strings.NewReader(input)); err == nil {
			t.Fatal("multiple/oversized nodes accepted as one profile")
		}
	}
	if _, err := serial.DecodeURIConfig(failedNodeReader{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("reader failure missing or leaked input context")
	}
	config, err := serial.DecodeURIConfig(strings.NewReader(" \n trojan://synthetic@127.0.0.1:1080 \n"))
	if err != nil || len(config.OutboundConfigs) != 1 {
		t.Fatal("normal file whitespace changed node selection", err)
	}
}
