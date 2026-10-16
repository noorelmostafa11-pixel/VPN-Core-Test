package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPhaseArguments(t *testing.T) {
	root, folder := t.TempDir(), t.TempDir()
	for _, phase := range []string{"suite", "vet", "build", "wire"} {
		args, timeout, err := phaseArgs(phase, root, folder)
		if err != nil || timeout < time.Minute {
			t.Fatal("missing bounded test phase", phase, err)
		}
		joined := strings.Join(args, " ")
		for _, forbidden := range []string{"upload", "release", "portable", "mobile", "comparison-main", "-main-source", "-main-commit"} {
			if strings.Contains(joined, forbidden) {
				t.Fatal("test phase contains packaging", joined)
			}
		}
		if phase == "suite" && (!strings.Contains(joined, "-race") || !strings.Contains(joined, "./...")) {
			t.Fatal("suite does not cover the entire repository")
		}
		if phase == "wire" && (!strings.Contains(joined, "^TestXraySelfCompatibility$") || !strings.Contains(joined, "-binary=")) {
			t.Fatal("wire does not use the fork's compiled binary")
		}
		if phase == "build" && (!strings.Contains(joined, "-o") || !strings.Contains(joined, "./main")) {
			t.Fatal("build does not compile Xray")
		}
	}
	if _, _, err := phaseArgs("mobile", root, folder); err == nil {
		t.Fatal("unsupported phase accepted")
	}
}

func TestEnvironmentReplacement(t *testing.T) {
	result := replaceEnv([]string{"Path=old", "CGO_ENABLED=0", "OTHER=keep"}, map[string]string{"PATH": "new", "CGO_ENABLED": "1"})
	joined := strings.Join(result, "\n")
	if strings.Contains(joined, "old") || !strings.Contains(joined, "PATH=new") || !strings.Contains(joined, "CGO_ENABLED=1") || !strings.Contains(joined, "OTHER=keep") {
		t.Fatal("duplicate or lost environment variables", result)
	}
}

func TestPinnedAssets(t *testing.T) {
	for _, test := range []struct {
		name         string
		status       int
		body, cached string
		pass         bool
	}{
		{"valid", 200, "correct", "", true},
		{"bad-digest", 200, "wrong", "", false},
		{"missing", 404, "correct", "", false},
		{"replace-bad-cache", 200, "correct", "old", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "asset.dat")
			if test.cached != "" {
				if err := os.WriteFile(path, []byte(test.cached), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := ensureAsset(context.Background(), server.Client(), server.URL, path, digest([]byte("correct")))
			if (err == nil) != test.pass || calls.Load() != 1 {
				t.Fatal("incorrect asset verification or retry", err, calls.Load())
			}
			if test.pass {
				if err := ensureAsset(context.Background(), server.Client(), server.URL, path, digest([]byte("correct"))); err != nil || calls.Load() != 1 {
					t.Fatal("verified cache unexpectedly downloaded", err, calls.Load())
				}
			} else if test.cached == "" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("unverified asset persisted")
				}
			}
		})
	}
}

func TestIncompleteWireCannotPass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.json")
	methods := make([]string, 32)
	for _, test := range []struct {
		passed                     bool
		pairs, tcp, udp, greetings int
		valid                      bool
	}{
		{true, 32, 64, 288, 64, true},
		{false, 32, 64, 288, 64, false},
		{true, 31, 64, 288, 64, false},
		{true, 32, 63, 288, 64, false},
		{true, 32, 64, 287, 64, false},
		{true, 32, 64, 288, 63, false},
	} {
		data := map[string]any{"passed": test.passed, "methods": methods, "completed": map[string]int{"completed_pairs": test.pairs, "completed_tcp_echoes": test.tcp, "completed_udp_echoes": test.udp, "completed_server_first_greetings": test.greetings}}
		if err := writeJSON(path, data); err != nil {
			t.Fatal(err)
		}
		if err := verifyWire(path); (err == nil) != test.valid {
			t.Fatal("partial evidence reported as success", test, err)
		}
	}
	if err := verifyWire(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing evidence accepted")
	}
}

func TestSummaryDoesNotInventResults(t *testing.T) {
	folder := t.TempDir()
	summary := filepath.Join(t.TempDir(), "github-summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	if err := os.WriteFile(filepath.Join(folder, "suite.log"), []byte("{\"Action\":\"pass\",\"Package\":\"one\"}\n{\"Action\":\"fail\",\"Package\":\"two\"}\n{\"Action\":\"skip\",\"Package\":\"one\",\"Test\":\"NeedsExternalPeer\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(folder, "prepare.json"), result{Phase: "prepare", Passed: true}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(folder, "suite.json"), result{Phase: "suite", Passed: false}); err != nil {
		t.Fatal(err)
	}
	if err := summarize(folder); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"| prepare | PASS", "| suite | FAIL", "| wire | NOT RUN / incomplete", "no Internet", "SS2022", "1 passed packages, 1 failed packages, 1 skipped tests", "NeedsExternalPeer"} {
		if !strings.Contains(string(data), expected) {
			t.Fatal("missing result/boundary", expected)
		}
	}
}
