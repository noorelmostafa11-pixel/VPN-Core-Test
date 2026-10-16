package wire_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validCommit(value string) bool { return regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(value) }

// Peers exist only inside the test's temporary directory, are never packaged
// or uploaded and are removed by testing after all child processes have joined.
func sourcePeers(t *testing.T, fork, main, commit string) []string {
	t.Helper()
	for _, source := range []string{fork, main} {
		if !filepath.IsAbs(source) {
			t.Fatal("source checkout paths must be absolute")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "-C", main, "rev-parse", "HEAD")
	actual, err := command.Output()
	if err != nil || strings.TrimSpace(string(actual)) != commit {
		t.Fatal("comparison checkout is not the pinned main commit", err)
	}
	if _, err := os.Stat(filepath.Join(main, "vendor", "modules.txt")); err != nil {
		t.Fatal("pinned main vendor tree is required", err)
	}
	temp := t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	paths := []string{filepath.Join(temp, "fork-peer"+suffix), filepath.Join(temp, "main-peer"+suffix)}
	for i, source := range []string{fork, main} {
		mode := "readonly"
		if i == 1 {
			mode = "vendor"
		}
		command := exec.CommandContext(ctx, "go", "build", "-mod="+mode, "-trimpath", "-o", paths[i], "./main")
		command.Dir, command.Env = source, fixtureEnv(os.Environ())
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("temporary test peer preparation failed: %v\n%s", err, output)
		}
	}
	return paths
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
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"b066df12e6e9030a937a3c1313e85cdf62d7bb8f", true},
		{"main", false},
		{"", false},
		{strings.Repeat("a", 39), false},
		{strings.Repeat("a", 41), false},
		{strings.Repeat("Z", 40), false},
	} {
		if validCommit(test.value) != test.valid {
			t.Fatal("invalid commit validation", test.value)
		}
	}
	env := fixtureEnv([]string{"PATH=keep", "cgo_enabled=1", "CGO_ENABLED=1", "OTHER=keep"})
	if fmt.Sprint(env) != "[PATH=keep OTHER=keep CGO_ENABLED=0]" {
		t.Fatal("fixture environment changed unrelated settings", env)
	}
}
