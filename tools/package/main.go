// Command package builds and bundles one Xray target (or an explicit matrix).
// Like upstream Xray's release packaging, it downloads verified distribution
// assets at package time; no runtime binaries or vendored modules are required
// to be checked into the source repository.
package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
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

type target struct {
	OS   string
	Arch string
}

var supported = []target{
	{"windows", "amd64"}, {"windows", "arm64"}, {"windows", "386"},
	{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "arm"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"android", "arm64"},
}

const (
	geoRevision   = "a2d310e1de9ba35757f1633dda231192d114a306"
	wintunVersion = "0.14.1"
	maxGeoBytes   = 64 << 20
	maxWintunZip  = 64 << 20
	maxWintunDLL  = 32 << 20
)

type assetSources struct {
	GeoBaseURL string
	WintunURL  string
}

func upstreamSources() assetSources {
	return assetSources{
		GeoBaseURL: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/" + geoRevision,
		WintunURL:  "https://www.wintun.net/builds/wintun-" + wintunVersion + ".zip",
	}
}

type manifest struct {
	SHA256 map[string]string `json:"sha256"`
}

type packagedFile struct {
	Source string
	Name   string
}

type runtimeAssets struct {
	GeoIP     string
	GeoSite   string
	WintunZip string
}

func main() {
	osName := flag.String("os", "", "target GOOS: windows, linux, darwin or android")
	arch := flag.String("arch", "", "target GOARCH (see -list)")
	all := flag.String("target", "", "set to all to build every supported target")
	list := flag.Bool("list", false, "list supported targets")
	flag.Parse()
	if err := run(*osName, *arch, *all, *list); err != nil {
		fmt.Fprintln(os.Stderr, "packaging:", err)
		os.Exit(1)
	}
}

func run(osName, arch, all string, list bool) error {
	if list {
		for _, t := range supported {
			fmt.Printf("%s/%s\n", t.OS, t.Arch)
		}
		return nil
	}
	requested, err := chooseTargets(osName, arch, all)
	if err != nil {
		return err
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	m, err := readManifest(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Join(root, "dist"), ".xray-assets-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	needWintun := false
	for _, t := range requested {
		if t.OS == "windows" {
			needWintun = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Minute}
	assets, err := acquireAssets(ctx, client, upstreamSources(), stage, m, needWintun)
	if err != nil {
		return err
	}
	for _, t := range requested {
		if err := buildAndPack(root, stage, assets, t); err != nil {
			return fmt.Errorf("%s/%s: %w", t.OS, t.Arch, err)
		}
	}
	return nil
}

func chooseTargets(osName, arch, all string) ([]target, error) {
	switch {
	case all == "all" && osName == "" && arch == "":
		return supported, nil
	case all == "" && osName != "" && arch != "":
		t := target{osName, arch}
		if !validTarget(t) {
			return nil, fmt.Errorf("unsupported target %s/%s; use -list", osName, arch)
		}
		return []target{t}, nil
	default:
		return nil, errors.New("select -os NAME -arch NAME, or -target all (not both); use -list")
	}
}

func validTarget(t target) bool {
	for _, candidate := range supported {
		if t == candidate {
			return true
		}
	}
	return false
}

func readManifest(root string) (manifest, error) {
	var m manifest
	f, err := os.Open(filepath.Join(root, "assets", "manifest.json"))
	if err != nil {
		return m, fmt.Errorf("missing asset checksum manifest: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("invalid asset manifest: %w", err)
	}
	if m.SHA256 == nil {
		return m, errors.New("asset manifest has no sha256 entries")
	}
	return m, nil
}

func checksum(m manifest, key string) (string, error) {
	want := m.SHA256[key]
	if len(want) != 64 {
		return "", fmt.Errorf("missing 64-character SHA256 pin for %s", key)
	}
	if _, err := hex.DecodeString(want); err != nil {
		return "", fmt.Errorf("invalid SHA256 pin for %s: %w", key, err)
	}
	return strings.ToLower(want), nil
}

// downloadVerified streams a bounded response to a temporary file, checks the
// exact pinned SHA256, and never publishes a partial or unverified download.
func downloadVerified(ctx context.Context, client *http.Client, url, path, want string, limit int64) error {
	if len(want) != 64 {
		return errors.New("invalid expected SHA256")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: unexpected HTTP %d", url, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("download %s exceeds limit", url)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".xray-download-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit+1))
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if n == 0 || n > limit {
		return fmt.Errorf("download %s is empty or oversized", url)
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("download %s failed SHA256 verification", url)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

func acquireAssets(ctx context.Context, client *http.Client, sources assetSources, stage string, m manifest, wintun bool) (runtimeAssets, error) {
	var out runtimeAssets
	for _, resource := range []struct {
		name, key string
	}{
		{"geoip.dat", "shared/geoip.dat"},
		{"geosite.dat", "shared/geosite.dat"},
	} {
		want, err := checksum(m, resource.key)
		if err != nil {
			return out, err
		}
		destination := filepath.Join(stage, resource.name)
		fmt.Println("Downloading verified", resource.name)
		if err := downloadVerified(ctx, client, sources.GeoBaseURL+"/"+resource.name, destination, want, maxGeoBytes); err != nil {
			return out, err
		}
		if resource.name == "geoip.dat" {
			out.GeoIP = destination
		} else {
			out.GeoSite = destination
		}
	}
	if wintun {
		want, err := checksum(m, "upstream/wintun-"+wintunVersion+".zip")
		if err != nil {
			return out, err
		}
		out.WintunZip = filepath.Join(stage, "wintun.zip")
		fmt.Println("Downloading verified Wintun", wintunVersion)
		if err := downloadVerified(ctx, client, sources.WintunURL, out.WintunZip, want, maxWintunZip); err != nil {
			return out, err
		}
	}
	return out, nil
}

func resourceFiles(root, stage string, a runtimeAssets, t target) ([]packagedFile, error) {
	items := []packagedFile{
		{a.GeoIP, "geoip.dat"},
		{a.GeoSite, "geosite.dat"},
		{filepath.Join(root, "LICENSE"), "LICENSE"},
	}
	if t.OS == "windows" {
		if a.WintunZip == "" {
			return nil, errors.New("missing verified Wintun archive")
		}
		archiveArch := t.Arch
		if archiveArch == "386" {
			archiveArch = "x86"
		}
		dll := filepath.Join(stage, "wintun-"+t.Arch+".dll")
		license := filepath.Join(stage, "LICENSE-Wintun")
		if err := extractWintun(a.WintunZip, "wintun/bin/"+archiveArch+"/wintun.dll", dll, maxWintunDLL); err != nil {
			return nil, err
		}
		if err := extractWintun(a.WintunZip, "wintun/LICENSE.txt", license, 1<<20); err != nil {
			return nil, err
		}
		items = append(items, packagedFile{dll, "wintun.dll"}, packagedFile{license, "LICENSE-Wintun"})
		for _, suffix := range []string{"cmd", "ps1", "vbs"} {
			name := "xray_no_window." + suffix
			items = append(items, packagedFile{filepath.Join(root, ".github", "build", "windows", name), name})
		}
	}
	for _, item := range items {
		if err := checkRegularFile(item.Source); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func extractWintun(archivePath, name, outputPath string, limit int64) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("invalid Wintun archive: %w", err)
	}
	defer archive.Close()
	for _, item := range archive.File {
		if item.Name != name {
			continue
		}
		if item.FileInfo().IsDir() || item.UncompressedSize64 == 0 || item.UncompressedSize64 > uint64(limit) {
			return fmt.Errorf("invalid Wintun archive member %q", name)
		}
		r, err := item.Open()
		if err != nil {
			return err
		}
		f, err := os.Create(outputPath)
		if err != nil {
			r.Close()
			return err
		}
		n, copyErr := io.Copy(f, io.LimitReader(r, limit+1))
		closeErr := errors.Join(r.Close(), f.Close())
		if err := errors.Join(copyErr, closeErr); err != nil {
			os.Remove(outputPath)
			return err
		}
		if n == 0 || n > limit {
			os.Remove(outputPath)
			return fmt.Errorf("Wintun archive member %q is empty or oversized", name)
		}
		return nil
	}
	return fmt.Errorf("Wintun archive is missing %q", name)
}

func checkRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("required file %s: %w", filepath.ToSlash(path), err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("required file %s is empty or not a regular file", filepath.ToSlash(path))
	}
	return nil
}

func buildAndPack(root, stage string, a runtimeAssets, t target) error {
	files, err := resourceFiles(root, stage, a, t)
	if err != nil {
		return err
	}
	build, err := os.MkdirTemp(filepath.Join(root, "dist"), ".xray-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(build)
	executable := "xray"
	if t.OS == "windows" {
		executable += ".exe"
	}
	binary := filepath.Join(build, executable)
	args := []string{"build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", binary, "./main"}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = buildEnv(os.Environ(), t)
	fmt.Printf("Building %s/%s...\n", t.OS, t.Arch)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build failed: %w", err)
	}
	if err := checkRegularFile(binary); err != nil {
		return fmt.Errorf("compiled binary missing: %w", err)
	}
	files = append([]packagedFile{{binary, executable}}, files...)
	archiveName := fmt.Sprintf("Xray-%s-%s.zip", t.OS, t.Arch)
	destination := filepath.Join(root, "dist", archiveName)
	if err := zipFiles(destination, files); err != nil {
		return err
	}
	fmt.Println("Created", destination)
	return nil
}

func buildEnv(environ []string, t target) []string {
	blocked := map[string]bool{
		"GOOS": true, "GOARCH": true, "GOARM": true, "CGO_ENABLED": true,
		"GOFLAGS": true, "GOWORK": true,
	}
	env := make([]string, 0, len(environ)+7)
	for _, entry := range environ {
		parts := strings.SplitN(entry, "=", 2)
		if !blocked[strings.ToUpper(parts[0])] {
			env = append(env, entry)
		}
	}
	env = append(env, "GOOS="+t.OS, "GOARCH="+t.Arch, "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off")
	if t.OS == "linux" && t.Arch == "arm" {
		env = append(env, "GOARM=7")
	}
	return env
}

func zipFiles(destination string, files []packagedFile) error {
	dir := filepath.Dir(destination)
	f, err := os.CreateTemp(dir, ".xray-package-*.zip")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	w := zip.NewWriter(f)
	seen := make(map[string]bool, len(files))
	var writeErr error
	for _, item := range files {
		if item.Name == "" || strings.ContainsAny(item.Name, `/\\`) || seen[item.Name] {
			writeErr = fmt.Errorf("unsafe or duplicate archive name %q", item.Name)
			break
		}
		seen[item.Name] = true
		if writeErr = writeZipEntry(w, item); writeErr != nil {
			break
		}
	}
	writeErr = errors.Join(writeErr, w.Close(), f.Close())
	if writeErr != nil {
		return writeErr
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(tmp, destination)
}

func writeZipEntry(w *zip.Writer, item packagedFile) error {
	f, err := os.Open(item.Source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = item.Name
	header.Method = zip.Deflate
	header.SetMode(info.Mode())
	out, err := w.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, f)
	return err
}
