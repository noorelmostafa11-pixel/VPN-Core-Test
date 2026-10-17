package main

import (
	"context"
	"fmt"
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
		if phase == "suite" && (!strings.Contains(joined, "-race") || !strings.Contains(joined, "./...") || !strings.Contains(joined, "-timeout=25m")) {
			t.Fatal("suite must test every package with the race detector and a bounded timeout")
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
	// The test fixture deliberately fixes literal counts independently of the
	// validator constants, so changing acceptance thresholds needs a test update.
	methods := []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "chacha20-poly1305"}
	for len(methods) < 32 {
		methods = append(methods, fmt.Sprintf("other-cipher-%02d", len(methods)))
	}
	validReport := func() map[string]any {
		return map[string]any{
			"passed": true,
			"methods": append([]string(nil), methods...),
			"expected_pairs": 37,
			"expected_tcp_echoes": 74,
			"expected_udp_echoes": 333,
			"expected_server_first_greetings": 64,
			"original_default_client_first_cases": 5,
			"original_server_first_opt_in_cases": 5,
			"completed": map[string]int{
				"completed_pairs": 37,
				"completed_tcp_echoes": 74,
				"completed_udp_echoes": 333,
				"completed_server_first_greetings": 64,
			},
		}
	}
	setCompleted := func(data map[string]any, field string, value int) {
		data["completed"].(map[string]int)[field] = value
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"complete", nil},
		{"reported-failure", func(d map[string]any) { d["passed"] = false }},
		{"missing-method", func(d map[string]any) { d["methods"] = d["methods"].([]string)[:31] }},
		{"duplicate-method", func(d map[string]any) { d["methods"].([]string)[0] = d["methods"].([]string)[1] }},
		{"missing-original-cipher", func(d map[string]any) { d["methods"].([]string)[0] = "unverified-cipher" }},
		{"missing-pair", func(d map[string]any) { setCompleted(d, "completed_pairs", 36) }},
		{"missing-TCP", func(d map[string]any) { setCompleted(d, "completed_tcp_echoes", 73) }},
		{"missing-UDP", func(d map[string]any) { setCompleted(d, "completed_udp_echoes", 332) }},
		{"missing-greeting", func(d map[string]any) { setCompleted(d, "completed_server_first_greetings", 63) }},
		{"extra-pair", func(d map[string]any) { setCompleted(d, "completed_pairs", 38) }},
		{"old-pair-expectation", func(d map[string]any) { d["expected_pairs"] = 32 }},
		{"old-TCP-expectation", func(d map[string]any) { d["expected_tcp_echoes"] = 64 }},
		{"old-UDP-expectation", func(d map[string]any) { d["expected_udp_echoes"] = 288 }},
		{"wrong-greeting-expectation", func(d map[string]any) { d["expected_server_first_greetings"] = 74 }},
		{"missing-default-coverage", func(d map[string]any) { d["original_default_client_first_cases"] = 0 }},
		{"missing-opt-in-coverage", func(d map[string]any) { d["original_server_first_opt_in_cases"] = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := validReport()
			if tc.mutate != nil {
				tc.mutate(data)
			}
			if err := writeJSON(path, data); err != nil {
				t.Fatal(err)
			}
			if err := verifyWire(path); (err == nil) != (tc.mutate == nil) {
				t.Fatal("incorrect wire evidence acceptance", tc.name, err)
			}
		})
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
	for _, expected := range []string{"| prepare | PASS", "| suite | FAIL", "| wire | NOT RUN / incomplete", "not external interoperability", "SS2022", "1 passed packages, 1 failed packages, 1 skipped tests", "NeedsExternalPeer", "37 same-fork client/server cases", "74 TCP echoes / 333 UDP echoes / 64 pre-payload server-first greetings"} {
		if !strings.Contains(string(data), expected) {
			t.Fatal("missing result/boundary", expected)
		}
	}
}
