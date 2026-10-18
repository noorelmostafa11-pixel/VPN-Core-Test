package core_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// An optional, explicit independent test endpoint. Never used by production
// dialing, automatically downloaded, or treated as a fallback proxy engine.
func TestAddedShadowsocksPluginReference(t *testing.T) {
	path := os.Getenv("XRAY_V2RAY_PLUGIN_REFERENCE")
	if path == "" {
		t.Skip("set XRAY_V2RAY_PLUGIN_REFERENCE to a pinned upstream test executable")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	tcp, _ := scopeEchoTargets(t)
	for _, variant := range []string{"ss", "ss2022"} {
		t.Run(variant, func(t *testing.T) {
			backend, public := additivePort(t), additivePort(t)
			node, settings, protocol := additiveNode(t, variant, backend, map[string]string{"plugin": "v2ray-plugin;mux=0;host=front.example.invalid;path=/plugin"})
			settings["network"] = "tcp"
			additiveServer(t, backend, protocol, settings, map[string]any{"network": "tcp"})
			node.Port = uint16(public)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "-server", "-mux", "0", "-localAddr", "127.0.0.1", "-localPort", strconv.Itoa(public), "-remoteAddr", "127.0.0.1", "-remotePort", strconv.Itoa(backend), "-host", "front.example.invalid", "-path", "/plugin", "-loglevel", "error")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-exited:
				case <-time.After(3 * time.Second):
					t.Error("reference plugin did not exit")
				}
			})
			ready := time.NewTicker(10 * time.Millisecond)
			defer ready.Stop()
			for {
				conn, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", public), 50*time.Millisecond)
				if e == nil {
					conn.Close()
					break
				}
				select {
				case <-ready.C:
				case err := <-exited:
					exited <- err
					t.Fatal("reference plugin exited", err)
				case <-ctx.Done():
					t.Fatal("reference listener did not start")
				}
			}
			for _, format := range []string{"uri", "node", "go"} {
				t.Run(format, func(t *testing.T) { additiveTCPExchange(t, additiveClient(t, node, format), tcp) })
			}
		})
	}
}
