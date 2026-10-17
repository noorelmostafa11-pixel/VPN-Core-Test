package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFile(t *testing.T, path string, content []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	return digest(content)
}

func digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func testWintunArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, content := range map[string]string{
		"wintun/bin/amd64/wintun.dll": "test-amd64-dll",
		"wintun/bin/arm64/wintun.dll": "test-arm64-dll",
		"wintun/bin/x86/wintun.dll":   "test-x86-dll",
		"wintun/LICENSE.txt":          "test-Wintun-license",
	} {
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func testAssets(t *testing.T) (string, runtimeAssets, manifest, []byte) {
	t.Helper()
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0755); err != nil {
		t.Fatal(err)
	}
	data := testWintunArchive(t)
	a := runtimeAssets{
		GeoIP:     filepath.Join(stage, "geoip.dat"),
		GeoSite:   filepath.Join(stage, "geosite.dat"),
		WintunZip: filepath.Join(stage, "wintun.zip"),
	}
	m := manifest{SHA256: map[string]string{
		"shared/geoip.dat":                          testFile(t, a.GeoIP, []byte("test-geoip")),
		"shared/geosite.dat":                        testFile(t, a.GeoSite, []byte("test-geosite")),
		"upstream/wintun-" + wintunVersion + ".zip": testFile(t, a.WintunZip, data),
	}}
	testFile(t, filepath.Join(root, "LICENSE"), []byte("Xray license"))
	for _, ext := range []string{"cmd", "ps1", "vbs"} {
		testFile(t, filepath.Join(root, ".github", "build", "windows", "xray_no_window."+ext), []byte(ext))
	}
	return root, a, m, data
}

func TestTargets(t *testing.T) {
	seen := map[target]bool{}
	for _, item := range supported {
		if seen[item] || !validTarget(item) {
			t.Fatalf("invalid target matrix: %v", item)
		}
		seen[item] = true
	}
	if validTarget(target{"windows", "mips"}) {
		t.Fatal("unsupported target accepted")
	}
	for _, selection := range []struct {
		os, arch, all string
		wantCount     int
	}{
		{"windows", "amd64", "", 1},
		{"", "", "all", len(supported)},
		{"windows", "amd64", "all", 0},
		{"windows", "mips", "", 0},
		{"", "", "", 0},
	} {
		got, err := chooseTargets(selection.os, selection.arch, selection.all)
		if selection.wantCount == 0 && err == nil {
			t.Fatalf("invalid target selection accepted: %+v", selection)
		}
		if selection.wantCount > 0 && (err != nil || len(got) != selection.wantCount) {
			t.Fatalf("target selection %+v: got %d: %v", selection, len(got), err)
		}
	}
}

func TestPackageResources(t *testing.T) {
	root, a, _, _ := testAssets(t)
	stage := filepath.Dir(a.GeoIP)
	for _, arch := range []string{"amd64", "arm64", "386"} {
		got, err := resourceFiles(root, stage, a, target{"windows", arch})
		if err != nil || len(got) != 8 {
			t.Fatalf("Windows %s has %d resources: %v", arch, len(got), err)
		}
		dll, err := os.ReadFile(filepath.Join(stage, "wintun-"+arch+".dll"))
		if err != nil || string(dll) != "test-"+map[string]string{"386": "x86", "amd64": "amd64", "arm64": "arm64"}[arch]+"-dll" {
			t.Fatalf("wrong Wintun DLL for %s: %q: %v", arch, dll, err)
		}
	}
	got, err := resourceFiles(root, stage, a, target{"linux", "amd64"})
	if err != nil || len(got) != 3 {
		t.Fatalf("Linux resources %d: %v", len(got), err)
	}
	if _, err := resourceFiles(root, stage, runtimeAssets{GeoIP: a.GeoIP, GeoSite: a.GeoSite}, target{"windows", "amd64"}); err == nil {
		t.Fatal("missing Wintun archive was accepted")
	}
}

func TestAcquireAssetsVerified(t *testing.T) {
	_, _, m, wintun := testAssets(t)
	geoIP, geoSite := []byte("test-geoip"), []byte("test-geosite")
	m.SHA256["shared/geoip.dat"] = digest(geoIP)
	m.SHA256["shared/geosite.dat"] = digest(geoSite)
	m.SHA256["upstream/wintun-"+wintunVersion+".zip"] = digest(wintun)
	counts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counts[r.URL.Path]++
		switch r.URL.Path {
		case "/geoip.dat":
			w.Write(geoIP)
		case "/geosite.dat":
			w.Write(geoSite)
		case "/wintun.zip":
			w.Write(wintun)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	stage := t.TempDir()
	sources := assetSources{GeoBaseURL: server.URL, WintunURL: server.URL + "/wintun.zip"}
	got, err := acquireAssets(context.Background(), server.Client(), sources, stage, m, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{got.GeoIP, got.GeoSite, got.WintunZip} {
		if err := checkRegularFile(file); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/geoip.dat", "/geosite.dat", "/wintun.zip"} {
		if counts[path] != 1 {
			t.Fatalf("unexpected download count for %s: %d", path, counts[path])
		}
	}
	// Non-Windows platforms never request Wintun.
	counts["/wintun.zip"] = 0
	if _, err := acquireAssets(context.Background(), server.Client(), sources, t.TempDir(), m, false); err != nil {
		t.Fatal(err)
	}
	if counts["/wintun.zip"] != 0 {
		t.Fatal("Wintun downloaded for a non-Windows target")
	}
}

func TestDownloadRejectsCorruptionAndHTTPFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "unsafe payload")
	}))
	defer server.Close()
	for _, tc := range []struct {
		path  string
		hash  string
		limit int64
	}{
		{"/file", strings.Repeat("0", 64), 100},
		{"/file", digest([]byte("unsafe payload")), 4},
		{"/missing", digest([]byte("unsafe payload")), 100},
	} {
		output := filepath.Join(t.TempDir(), "download.dat")
		if err := downloadVerified(context.Background(), server.Client(), server.URL+tc.path, output, tc.hash, tc.limit); err == nil {
			t.Fatalf("invalid download accepted: %+v", tc)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("failed download left a published output: %v", err)
		}
	}
}

func TestBuildEnvironment(t *testing.T) {
	env := buildEnv([]string{"PATH=/usr/bin", "GOOS=old", "GOARCH=old", "GOFLAGS=-mod=vendor", "GOPROXY=https://proxy.golang.org", "GOWORK=on", "CGO_ENABLED=1"}, target{"linux", "arm"})
	got := map[string]string{}
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		got[parts[0]] = parts[1]
	}
	for key, want := range map[string]string{
		"GOOS": "linux", "GOARCH": "arm", "GOARM": "7", "CGO_ENABLED": "0",
		"GOPROXY": "https://proxy.golang.org", "GOFLAGS": "", "GOWORK": "off",
	} {
		if got[key] != want {
			t.Errorf("%s=%s, want %s", key, got[key], want)
		}
	}
}

func TestZipFailsClosed(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "xray.exe")
	testFile(t, first, []byte("binary"))
	dst := filepath.Join(root, "out.zip")
	if err := zipFiles(dst, []packagedFile{{first, "xray.exe"}}); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 1 || z.File[0].Name != "xray.exe" {
		t.Fatalf("unexpected zip contents: %v", z.File)
	}
	r, err := z.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	z.Close()
	if err != nil || string(data) != "binary" {
		t.Fatalf("archive contents %q: %v", data, err)
	}
	if err := zipFiles(dst, []packagedFile{{first, "../escape"}}); err == nil {
		t.Fatal("zip traversal accepted")
	}
	if err := zipFiles(dst, []packagedFile{{first, "dup"}, {first, "dup"}}); err == nil {
		t.Fatal("duplicate filenames accepted")
	}
}

func TestChecksumPins(t *testing.T) {
	if _, err := checksum(manifest{SHA256: map[string]string{}}, "missing"); err == nil {
		t.Fatal("missing pin accepted")
	}
	if _, err := checksum(manifest{SHA256: map[string]string{"bad": strings.Repeat("x", 64)}}, "bad"); err == nil {
		t.Fatal("invalid pin accepted")
	}
}
