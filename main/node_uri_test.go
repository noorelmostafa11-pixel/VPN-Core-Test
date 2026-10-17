package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func TestNodeURIFileAutoAndMergedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic.uri")
	if err := os.WriteFile(path, []byte("socks4a://synthetic@127.0.0.1:1080"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := core.LoadConfig("auto", cmdarg.Arg{path})
	if err != nil || len(config.Outbound) != 1 {
		t.Fatal("node file needed a feature switch", err)
	}
	merged, err := core.GetMergedConfig(cmdarg.Arg{path})
	if err != nil || !strings.Contains(merged, "socks4a") {
		t.Fatal("node file omitted from explicit merged configuration", err)
	}
	previous := *format
	t.Cleanup(func() { *format = previous })
	*format = "uri"
	if getConfigFormat() != "uri" || getRegepxByFormat() != `^.+\.uri$` {
		t.Fatal("URI input format not registered")
	}
	*format = "auto"
	if strings.Contains(getRegepxByFormat(), "uri") {
		t.Fatal("original automatic directory selection changed")
	}
}
