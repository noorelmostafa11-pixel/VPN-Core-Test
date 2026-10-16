// Command check orchestrates manually requested compatibility tests. It neither
// packages programs nor dispatches workflows; evidence contains test reports only.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const assetsCommit = "a2d310e1de9ba35757f1633dda231192d114a306"

var assets = map[string]string{
	"geoip.dat":   "1931cec183daad70aa84c1ff7559d316c94cd3e67ddba4b8fddde125f10068bc",
	"geosite.dat": "9d951dbf2fcbabd04cd18051a6679eaa1da12566ddf5aa613e53eaee88ae7dc7",
}

type manifest struct {
	Branch string `json:"branch"`
}

type result struct {
	Phase    string  `json:"phase"`
	Passed   bool    `json:"passed"`
	Error    string  `json:"error,omitempty"`
	Seconds  float64 `json:"seconds"`
	Revision string  `json:"revision"`
	Platform string  `json:"platform"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./fork/check prepare|suite|vet|build|wire|summary")
		os.Exit(2)
	}
	if err := execute(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(phase string) error {
	allowed := map[string]bool{"prepare": true, "suite": true, "vet": true, "build": true, "wire": true, "summary": true}
	if !allowed[phase] {
		return fmt.Errorf("unknown phase %q", phase)
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	var pin manifest
	if err := readJSON(filepath.Join(root, "fork", "manifest.json"), &pin); err != nil {
		return err
	}
	if pin.Branch != "feature/xray-custom-core" {
		return errors.New("validation is restricted to feature/xray-custom-core")
	}
	temp := os.Getenv("RUNNER_TEMP")
	if temp == "" {
		return errors.New("RUNNER_TEMP is required; this command is for the manual workflow")
	}
	folder := filepath.Join(temp, "xray-compatibility")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return err
	}
	if phase == "summary" {
		return summarize(folder)
	}
	started := time.Now()
	revision, _ := exec.Command("git", "rev-parse", "HEAD").Output()
	entry := result{Phase: phase, Revision: strings.TrimSpace(string(revision)), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	err = runPhase(phase, root, folder, pin)
	entry.Passed, entry.Seconds = err == nil, time.Since(started).Seconds()
	if err != nil {
		entry.Error = err.Error()
	}
	if saveErr := writeJSON(filepath.Join(folder, phase+".json"), entry); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	return err
}

func runPhase(phase, root, folder string, pin manifest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	if phase == "prepare" {
		if os.Getenv("GITHUB_EVENT_NAME") != "workflow_dispatch" || os.Getenv("GITHUB_REF") != "refs/heads/"+pin.Branch {
			return errors.New("manual dispatch on the custom branch is required")
		}
		if runtime.Version() != "go1.27.1" {
			return fmt.Errorf("expected Go1.27.1, got %s", runtime.Version())
		}
		if _, err := testEnv(); err != nil {
			return err
		}
		for name, digest := range assets {
			url := "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/" + assetsCommit + "/" + name
			if err := ensureAsset(ctx, http.DefaultClient, url, filepath.Join(root, "resources", name), digest); err != nil {
				return err
			}
		}
		return nil
	}
	env, err := testEnv()
	if err != nil {
		return err
	}
	args, timeout, err := phaseArgs(phase, root, folder)
	if err != nil {
		return err
	}
	ctx, cancelPhase := context.WithTimeout(ctx, timeout)
	defer cancelPhase()
	log, err := os.Create(filepath.Join(folder, phase+".log"))
	if err != nil {
		return err
	}
	defer log.Close()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir, command.Env = root, env
	command.Stdout, command.Stderr = io.MultiWriter(os.Stdout, log), io.MultiWriter(os.Stderr, log)
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s failed (no retry): %w", phase, err)
	}
	if phase == "wire" {
		return verifyWire(filepath.Join(folder, "wire", "summary.json"))
	}
	return nil
}

func testBinaryPath() string {
	name := "xray-selftest"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(os.Getenv("RUNNER_TEMP"), name)
}

func phaseArgs(phase, root, folder string) ([]string, time.Duration, error) {
	switch phase {
	case "suite":
		return []string{"test", "-race", "-count=1", "-timeout=15m", "-json", "./..."}, 30 * time.Minute, nil
	case "vet":
		return []string{"vet", "./..."}, 5 * time.Minute, nil
	case "build":
		return []string{"build", "-mod=readonly", "-trimpath", "-o", testBinaryPath(), "./main"}, 10 * time.Minute, nil
	case "wire":
		return []string{"test", "-race", "./fork/wire", "-run", "^TestXraySelfCompatibility$", "-count=1", "-timeout=12m", "-v", "-args", "-binary=" + testBinaryPath(), "-evidence=" + filepath.Join(folder, "wire")}, 14 * time.Minute, nil
	}
	return nil, 0, fmt.Errorf("unknown test phase %q", phase)
}

func testEnv() ([]string, error) {
	compiler := "gcc"
	if runtime.GOOS == "darwin" {
		compiler = "clang"
	}
	path, err := exec.LookPath(compiler)
	if err != nil {
		return nil, fmt.Errorf("race detector compiler %s is missing: %w", compiler, err)
	}
	values := map[string]string{"CGO_ENABLED": "1", "CC": path, "PATH": filepath.Dir(path) + string(os.PathListSeparator) + os.Getenv("PATH"), "GOTOOLCHAIN": "local"}
	return replaceEnv(os.Environ(), values), nil
}

func replaceEnv(base []string, values map[string]string) []string {
	result := make([]string, 0, len(base)+len(values))
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		replaced := false
		for name := range values {
			if strings.EqualFold(name, key) {
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, item)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}

func ensureAsset(ctx context.Context, client *http.Client, url, path, want string) error {
	if data, err := os.ReadFile(path); err == nil && digest(data) == want {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("test asset HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return err
	}
	if digest(data) != want {
		return fmt.Errorf("test asset SHA256 mismatch: %s", filepath.Base(path))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

func verifyWire(path string) error {
	var report struct {
		Passed    bool     `json:"passed"`
		Methods   []string `json:"methods"`
		Completed struct {
			Pairs     int `json:"completed_pairs"`
			TCP       int `json:"completed_tcp_echoes"`
			UDP       int `json:"completed_udp_echoes"`
			Greetings int `json:"completed_server_first_greetings"`
		} `json:"completed"`
	}
	if err := readJSON(path, &report); err != nil {
		return err
	}
	if !report.Passed || len(report.Methods) != 32 || report.Completed.Pairs != 32 || report.Completed.TCP != 64 || report.Completed.UDP != 288 || report.Completed.Greetings != 64 {
		return errors.New("wire report failed or incomplete; skipped exchanges are not a pass")
	}
	return nil
}

func summarize(folder string) error {
	var output bytes.Buffer
	fmt.Fprintf(&output, "## Xray self-validation (%s/%s)\n\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintln(&output, "| Check | Result |\n| --- | --- |")
	for _, phase := range []string{"prepare", "suite", "vet", "build", "wire"} {
		var entry result
		status := "NOT RUN / incomplete"
		if err := readJSON(filepath.Join(folder, phase+".json"), &entry); err == nil {
			status = "FAIL"
			if entry.Passed {
				status = "PASS"
			}
			status += fmt.Sprintf(" (%.1fs)", entry.Seconds)
		}
		fmt.Fprintf(&output, "| %s | %s |\n", phase, status)
	}
	if file, err := os.Open(filepath.Join(folder, "suite.log")); err == nil {
		defer file.Close()
		var passed, failed int
		var skipped []string
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 4<<20)
		for scanner.Scan() {
			var event struct{ Action, Package, Test string }
			if json.Unmarshal(scanner.Bytes(), &event) != nil {
				continue
			}
			if event.Test == "" {
				if event.Action == "pass" {
					passed++
				}
				if event.Action == "fail" {
					failed++
				}
			} else if event.Action == "skip" {
				skipped = append(skipped, event.Package+" / "+event.Test)
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		fmt.Fprintf(&output, "\nRepository suite: %d passed packages, %d failed packages, %d skipped tests.\n", passed, failed, len(skipped))
		if len(skipped) > 0 {
			fmt.Fprint(&output, "\n<details><summary>Skipped tests (not counted as compatibility passes)</summary>\n\n")
			for _, name := range skipped {
				fmt.Fprintf(&output, "- `%s`\n", name)
			}
			fmt.Fprintln(&output, "\n</details>")
		}
	}
	fmt.Fprintln(&output, "\nSuite: all repository Go tests with race detection; skipped tests remain visible in suite.log. Wire: 32 classic Shadowsocks names, same-fork client/server, 32 pairs / 64 TCP / 288 UDP / 64 server-first greetings. Missing or partial evidence is not a pass.")
	fmt.Fprintln(&output, "\nLimits: loopback self-compatibility is not external interoperability or Internet/private-node, mobile SDK, Android, packaging or release acceptance. SS2022 has package tests but no dedicated self-wire fixture. Race and vet failures remain visible.")
	if err := os.WriteFile(filepath.Join(folder, "RESULTS.md"), output.Bytes(), 0o600); err != nil {
		return err
	}
	fmt.Print(output.String())
	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		return appendFile(summary, output.String())
	}
	return nil
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func appendFile(path, text string) error {
	if path == "" {
		return errors.New("required GitHub output path is missing")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, text)
	return err
}
