package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFile(t *testing.T, path string, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

func fixture(t *testing.T) (string, manifest) {
	t.Helper()
	root := t.TempDir()
	m := manifest{SHA256: map[string]string{}}
	for name, data := range map[string]string{
		"shared/geoip.dat": "geo ip fixture", "shared/geosite.dat": "geo site fixture",
		"windows/amd64/wintun.dll": "test dll only", "windows/LICENSE-Wintun": "test license",
	} {
		m.SHA256[name] = testFile(t, filepath.Join(root, "assets", filepath.FromSlash(name)), data)
	}
	testFile(t, filepath.Join(root, "LICENSE"), "Xray license")
	for _, ext := range []string{"cmd", "ps1", "vbs"} {
		testFile(t, filepath.Join(root, ".github", "build", "windows", "xray_no_window."+ext), ext)
	}
	return root, m
}

func TestMatrix(t *testing.T) {
	seen := map[target]bool{}
	for _, target := range supported {
		if seen[target] || !validTarget(target) {
			t.Fatalf("bad target %v", target)
		}
		seen[target] = true
	}
	if validTarget(target{"windows", "mips"}) || validTarget(target{"freebsd", "amd64"}) {
		t.Fatal("unsupported targets accepted")
	}
}

func TestTargetResources(t *testing.T) {
	root, m := fixture(t)
	win, err := resourceFiles(root, m, target{"windows", "amd64"})
	if err != nil || len(win) != 8 {
		t.Fatalf("windows resources %d: %v", len(win), err)
	}
	linux, err := resourceFiles(root, m, target{"linux", "amd64"})
	if err != nil || len(linux) != 3 {
		t.Fatalf("linux resources %d: %v", len(linux), err)
	}
	if _, err := resourceFiles(root, m, target{"windows", "arm64"}); err == nil || !strings.Contains(err.Error(), "SHA256 pin") {
		t.Fatalf("missing Windows arm64 pin must fail: %v", err)
	}
	m.SHA256["shared/geoip.dat"] = strings.Repeat("0", 64)
	if _, err := resourceFiles(root, m, target{"linux", "amd64"}); err == nil || !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("modified geodata must fail: %v", err)
	}
}

func TestOfflineEnvironment(t *testing.T) {
	env := cleanEnv([]string{"PATH=/usr/bin", "GOFLAGS=-mod=mod", "GOPROXY=https://bad.example", "GOTOOLCHAIN=auto", "CGO_ENABLED=1"}, target{"linux", "arm"})
	got := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		got[parts[0]] = parts[1]
	}
	for key, want := range map[string]string{
		"GOOS": "linux", "GOARCH": "arm", "GOARM": "7", "CGO_ENABLED": "0",
		"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=vendor", "GOWORK": "off",
	} {
		if got[key] != want {
			t.Errorf("%s=%s, want %s", key, got[key], want)
		}
	}
}

func TestVendorRequired(t *testing.T) {
	root := t.TempDir()
	if err := validateVendor(root); err == nil {
		t.Fatal("missing vendor accepted")
	}
	testFile(t, filepath.Join(root, "vendor", "modules.txt"), "test vendor")
	if err := validateVendor(root); err != nil {
		t.Fatal(err)
	}
}

func TestZipFiles(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "xray.exe")
	testFile(t, first, "binary")
	dst := filepath.Join(root, "out.zip")
	if err := zipFiles(dst, []packagedFile{{first, "xray.exe"}}); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 1 || z.File[0].Name != "xray.exe" {
		t.Fatalf("unexpected zip: %v", z.File)
	}
	r, err := z.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil || string(data) != "binary" {
		t.Fatalf("archive payload %q: %v", data, err)
	}
	if err = zipFiles(dst, []packagedFile{{first, "../escape"}}); err == nil {
		t.Fatal("unsafe archive entry accepted")
	}
}

func TestNoAssetsIsNotSuccess(t *testing.T) {
	root := t.TempDir()
	testFile(t, filepath.Join(root, "go.mod"), "module example.com/a\n")
	testFile(t, filepath.Join(root, "vendor", "modules.txt"), "vendor")
	m := manifest{SHA256: map[string]string{}}
	if _, err := resourceFiles(root, m, target{"windows", "amd64"}); err == nil {
		t.Fatal("must not silently produce incomplete package")
	}
}
