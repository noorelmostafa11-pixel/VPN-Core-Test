// Command package builds and packages one Xray target, or an explicitly requested
// target matrix. It never downloads dependencies or distribution assets.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

type manifest struct {
	SHA256 map[string]string `json:"sha256"`
}

type packagedFile struct {
	Source string
	Name   string
}

func main() {
	osName := flag.String("os", "", "target GOOS: windows, linux, darwin or android")
	arch := flag.String("arch", "", "target GOARCH (see -list)")
	all := flag.String("target", "", "set to all to build every supported target")
	offline := flag.Bool("offline", true, "offline-only packaging (false is not supported)")
	list := flag.Bool("list", false, "list supported targets")
	flag.Parse()
	if err := run(*osName, *arch, *all, *offline, *list); err != nil {
		fmt.Fprintln(os.Stderr, "packaging:", err)
		os.Exit(1)
	}
}

func run(osName, arch, all string, offline, list bool) error {
	if !offline {
		return errors.New("online packaging is not supported; -offline must remain true")
	}
	if list {
		for _, t := range supported {
			fmt.Printf("%s/%s\n", t.OS, t.Arch)
		}
		return nil
	}
	var requested []target
	switch {
	case all == "all" && osName == "" && arch == "":
		requested = supported
	case all == "" && osName != "" && arch != "":
		t := target{osName, arch}
		if !validTarget(t) {
			return fmt.Errorf("unsupported target %s/%s; use -list", osName, arch)
		}
		requested = []target{t}
	default:
		return errors.New("select -os NAME -arch NAME, or -target all (not both); use -list")
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	if err = validateVendor(root); err != nil {
		return err
	}
	m, err := readManifest(root)
	if err != nil {
		return err
	}
	// Validate all requested targets up front. No compilation/output when an
	// asset is absent, unpinned or corrupted.
	for _, t := range requested {
		if _, err = resourceFiles(root, m, t); err != nil {
			return fmt.Errorf("%s/%s: %w", t.OS, t.Arch, err)
		}
	}
	if err = os.MkdirAll(filepath.Join(root, "dist"), 0755); err != nil {
		return err
	}
	for _, t := range requested {
		if err = buildAndPack(root, m, t); err != nil {
			return fmt.Errorf("%s/%s: %w", t.OS, t.Arch, err)
		}
	}
	return nil
}

func validTarget(t target) bool {
	for _, candidate := range supported {
		if t == candidate {
			return true
		}
	}
	return false
}

func validateVendor(root string) error {
	info, err := os.Stat(filepath.Join(root, "vendor", "modules.txt"))
	if err != nil || info.IsDir() {
		return errors.New("offline Go modules are missing: vendor/modules.txt must be committed with all go.mod dependencies")
	}
	return nil
}

func readManifest(root string) (manifest, error) {
	var m manifest
	f, err := os.Open(filepath.Join(root, "assets", "manifest.json"))
	if err != nil {
		return m, fmt.Errorf("missing repository asset manifest: %w", err)
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

func resourceFiles(root string, m manifest, t target) ([]packagedFile, error) {
	items := []packagedFile{
		{filepath.Join(root, "assets", "shared", "geoip.dat"), "geoip.dat"},
		{filepath.Join(root, "assets", "shared", "geosite.dat"), "geosite.dat"},
		{filepath.Join(root, "LICENSE"), "LICENSE"},
	}
	if t.OS == "windows" {
		items = append(items,
			packagedFile{filepath.Join(root, "assets", "windows", t.Arch, "wintun.dll"), "wintun.dll"},
			packagedFile{filepath.Join(root, "assets", "windows", "LICENSE-Wintun"), "LICENSE-Wintun"},
		)
		for _, suffix := range []string{"cmd", "ps1", "vbs"} {
			name := "xray_no_window." + suffix
			items = append(items, packagedFile{filepath.Join(root, ".github", "build", "windows", name), name})
		}
	}
	// Non-generated external assets must be locked. Repo-authored helper scripts
	// and the inherited Xray LICENSE are already versioned source files.
	for _, item := range items {
		rel, err := filepath.Rel(filepath.Join(root, "assets"), item.Source)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			if err := verifyAsset(item.Source, filepath.ToSlash(rel), m); err != nil {
				return nil, err
			}
		} else if err = checkRegularFile(item.Source); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func checkRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("required repository file %s: %w", filepath.ToSlash(path), err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("required file %s is empty or not a regular file", filepath.ToSlash(path))
	}
	return nil
}

func verifyAsset(path, key string, m manifest) error {
	want := m.SHA256[key]
	if len(want) != 64 {
		return fmt.Errorf("missing 64-character SHA256 pin for assets/%s in assets/manifest.json", key)
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("invalid SHA256 pin for assets/%s: %w", key, err)
	}
	if err := checkRegularFile(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
		return fmt.Errorf("SHA256 mismatch for assets/%s", key)
	}
	return nil
}

func buildAndPack(root string, m manifest, t target) error {
	files, err := resourceFiles(root, m, t)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Join(root, "dist"), ".xray-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	executable := "xray"
	if t.OS == "windows" {
		executable += ".exe"
	}
	binary := filepath.Join(stage, executable)
	args := []string{"build", "-mod=vendor", "-trimpath", "-ldflags=-s -w", "-o", binary, "./main"}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// No network or Go toolchain downloads are allowed, even if the user has
	// GOFLAGS/GOPROXY/GOTOOLCHAIN overridden in the parent environment.
	cmd.Env = cleanEnv(os.Environ(), t)
	fmt.Printf("Building %s/%s offline...\n", t.OS, t.Arch)
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

func cleanEnv(environ []string, t target) []string {
	blocked := map[string]bool{
		"GOOS": true, "GOARCH": true, "GOARM": true, "CGO_ENABLED": true,
		"GOPROXY": true, "GOSUMDB": true, "GOTOOLCHAIN": true, "GOFLAGS": true,
		"GOWORK": true,
	}
	env := make([]string, 0, len(environ)+9)
	for _, entry := range environ {
		parts := strings.SplitN(entry, "=", 2)
		if !blocked[strings.ToUpper(parts[0])] {
			env = append(env, entry)
		}
	}
	env = append(env, "GOOS="+t.OS, "GOARCH="+t.Arch, "CGO_ENABLED=0",
		"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=vendor", "GOWORK=off")
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
	// Windows cannot rename over an existing file; remove only the previous
	// completed archive after creating the new archive successfully.
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
