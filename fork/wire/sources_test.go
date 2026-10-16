package wire_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// An optional local test builds the one and only Xray peer from this checkout.
func sourcePeer(t *testing.T, source string) string {
	t.Helper()
	if !filepath.IsAbs(source) {
		t.Fatal("Xray source checkout path must be absolute")
	}
	if _, err := os.Stat(filepath.Join(source, "go.mod")); err != nil {
		t.Fatal("Xray source checkout has no go.mod:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "xray-selftest")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./main")
	command.Dir, command.Env = source, fixtureEnv(os.Environ())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Xray self-test binary build failed: %v\n%s", err, output)
	}
	return binary
}

func fixtureEnv(base []string) []string {
	result := make([]string, 0, len(base)+1)
	for _, value := range base {
		name, _, _ := strings.Cut(value, "=")
		if !strings.EqualFold(name, "CGO_ENABLED") {
			result = append(result, value)
		}
	}
	return append(result, "CGO_ENABLED=0")
}

func TestFixtureInputGuards(t *testing.T) {
	env := fixtureEnv([]string{"PATH=keep", "cgo_enabled=1", "CGO_ENABLED=1", "OTHER=keep"})
	if fmt.Sprint(env) != "[PATH=keep OTHER=keep CGO_ENABLED=0]" {
		t.Fatal("fixture environment changed unrelated settings", env)
	}
}
