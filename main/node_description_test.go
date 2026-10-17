package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/core"
)

func TestNodeDescriptionFileAndMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic.node")
	input := `{"version":1,"protocol":"socks4a","address":"127.0.0.1","port":1080}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := core.LoadConfig("auto", cmdarg.Arg{path})
	if err != nil || len(config.Outbound) != 1 {
		t.Fatal("normal file loading failed", err)
	}
	base := filepath.Join(t.TempDir(), "base.json")
	if err := os.WriteFile(base, []byte(`{"log":{"loglevel":"warning"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	merged, err := core.GetMergedConfig(cmdarg.Arg{base, path})
	if err != nil || !strings.Contains(merged, "socks4a") || !strings.Contains(merged, "warning") {
		t.Fatal("node input bypassed ordinary config merging", err)
	}
	previous := *format
	t.Cleanup(func() { *format = previous })
	*format = "node"
	if getRegepxByFormat() != `^.+\.node$` {
		t.Fatal("explicit node directory format missing")
	}
	*format = "auto"
	if strings.Contains(getRegepxByFormat(), "node") {
		t.Fatal("original automatic directory selection changed")
	}
}
