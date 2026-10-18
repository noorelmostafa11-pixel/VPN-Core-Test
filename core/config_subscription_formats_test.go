package core_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/core"
)

func TestFourProtocolSubscriptionFormatExtensions(t *testing.T) {
	for ext, want := range map[string]string{
		"sub": "subscription", "subscription": "subscription",
		"subjson": "subjson", "node-list": "subjson",
		"uri": "uri", "node": "node", "json": "json", "yaml": "yaml",
	} {
		t.Run(ext, func(t *testing.T) {
			if got := core.GetFormatByExtension(ext); got != want {
				t.Fatalf("got %q, expected %q", got, want)
			}
		})
	}
	for name, want := range map[string]string{
		"nodes.sub": "subscription", "nodes.subscription": "subscription",
		"nodes.subjson": "subjson", "nodes.node-list": "subjson",
		"single.uri": "uri", "single.node": "node",
	} {
		if got := core.GetFormat(name); got != want {
			t.Fatalf("file %q detected as %q; expected %q", name, got, want)
		}
	}
}

func TestAddedSubscriptionReadersAndFileMerge(t *testing.T) {
	const uri = "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type=ws"
	const node = `[{"version":1,"protocol":"vless","address":"127.0.0.1","port":443,"credentials":{"id":"11111111-1111-4111-8111-111111111111"},"parameters":{"type":"ws"}}]`
	for _, item := range []struct{ format, extension, payload string }{
		{"subscription", "sub", uri}, {"sub", "subscription", uri}, {"subjson", "subjson", node}, {"node-list", "node-list", node},
	} {
		t.Run(item.format, func(t *testing.T) {
			config, err := core.LoadConfig(item.format, strings.NewReader(item.payload))
			if err != nil || len(config.GetOutbound()) != 1 {
				t.Fatal("reader loader unavailable", err)
			}
			path := filepath.Join(t.TempDir(), "nodes."+item.extension)
			if err := os.WriteFile(path, []byte(item.payload), 0o600); err != nil {
				t.Fatal(err)
			}
			merged, err := core.GetMergedConfig(cmdarg.Arg{path})
			if err != nil || !strings.Contains(merged, "vless") {
				t.Fatal("merge omitted subscription nodes", err)
			}
		})
	}
}

func TestAddedMultipleSubscriptionFilesPreserveEveryNode(t *testing.T) {
	dir := t.TempDir()
	files := cmdarg.Arg{}
	for _, item := range []struct{ name, body string }{
		{"one.sub", "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443"},
		{"two.sub", "trojan://synthetic@127.0.0.1:443"},
		{"three.subjson", `[{"version":1,"protocol":"vless","address":"127.0.0.1","port":444,"credentials":{"id":"11111111-1111-4111-8111-111111111111"}}]`},
		{"four.subjson", `[{"version":1,"protocol":"trojan","address":"127.0.0.1","port":445,"credentials":{"password":"synthetic"}}]`},
	} {
		path := filepath.Join(dir, item.name)
		if err := os.WriteFile(path, []byte(item.body), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
	}
	config, err := core.LoadConfig("auto", files)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Outbound) != len(files) {
		t.Fatalf("subscription file merge discarded nodes: got %d, want %d", len(config.Outbound), len(files))
	}
	seen := map[string]bool{}
	for _, out := range config.Outbound {
		if out.Tag == "" || seen[out.Tag] {
			t.Fatal("generated tags collide")
		}
		seen[out.Tag] = true
	}
	single, err := core.LoadConfig("auto", files[:1])
	if err != nil || single.Outbound[0].Tag != "subscription-001" {
		t.Fatal("single-file generated tags changed", err)
	}
}
