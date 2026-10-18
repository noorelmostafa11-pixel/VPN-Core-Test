// Package sip003 implements an explicit, locally approved SIP003 executable
// supervisor. It never interprets downloaded links as executable paths.
package sip003

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxPluginBinaryBytes = 64 << 20

// Approved is supplied by the local application; untrusted node links MUST
// NOT populate Executable, SHA256 or Args. A user-approved executable is
// required even for the obfs-local/simple-obfs protocol.
type Approved struct {
	Name string
	Executable string
	SHA256 string
	Args []string
	LocalOptions string // locally trusted configuration, never remote URL
	StartupTimeout time.Duration
}

type Running struct {
	LocalPort uint16
	cmd *exec.Cmd
	done chan error
	once sync.Once
}

func (p *Running) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
	return nil
}

func verifyExecutable(approved Approved) error {
	if approved.Name == "" || len(approved.Name) > 64 || !validName(approved.Name) {
		return errors.New("SIP003: invalid locally approved plugin identity")
	}
	if !filepath.IsAbs(approved.Executable) || len(approved.Executable) > 4096 {
		return errors.New("SIP003: executable requires a trusted absolute path")
	}
	pinned, err := hex.DecodeString(approved.SHA256)
	if err != nil || len(pinned) != sha256.Size {
		return errors.New("SIP003: executable requires a valid SHA256 pin")
	}
	f, err := os.Open(approved.Executable)
	if err != nil {
		return errors.New("SIP003: pinned executable is unavailable")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() <= 0 ||
		stat.Size() > maxPluginBinaryBytes || (runtime.GOOS != "windows" && stat.Mode()&0111 == 0) {
		return errors.New("SIP003: executable is not an approved regular binary")
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil ||
		subtle.ConstantTimeCompare(sum.Sum(nil), pinned) != 1 {
		return errors.New("SIP003: executable hash differs from locally approved pin")
	}
	for _, arg := range approved.Args {
		if len(arg) > 1024 || strings.ContainsAny(arg, "\x00\r\n") {
			return errors.New("SIP003: invalid locally approved executable argument")
		}
	}
	return nil
}

func validName(name string) bool {
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// Start executes only a hash-pinned app-owned plugin with the normal SIP003
// environment, not a binary named by a remote node or subscription.
// It picks a local ephemeral port for the original Shadowsocks client to dial.
// The plugin talks to the original remote server and must implement the
// remote peer's exact wire protocol (v2ray-plugin, simple-obfs etc.).
func Start(ctx context.Context, approved Approved, remoteHost string, remotePort uint16, options string) (*Running, error) {
	if err := verifyExecutable(approved); err != nil {
		return nil, err
	}
	if remoteHost == "" || len(remoteHost) > 253 || remotePort == 0 ||
		strings.ContainsAny(remoteHost, "\x00\r\n\t /\\") {
		return nil, errors.New("SIP003: invalid remote endpoint")
	}
	if len(options) > 2048 || strings.ContainsAny(options, "\x00\r\n") {
		return nil, errors.New("SIP003: invalid plugin options")
	}
	if ctx == nil {
		return nil, errors.New("SIP003: missing lifecycle context")
	}
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("SIP003: cannot allocate loopback port")
	}
	port := socket.Addr().(*net.TCPAddr).Port
	_ = socket.Close()

	cmd := exec.CommandContext(ctx, approved.Executable, approved.Args...)
	// No inherited secrets, no shell, no user-controlled command arguments.
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"SS_LOCAL_HOST=127.0.0.1",
		"SS_LOCAL_PORT="+strconv.Itoa(port),
		"SS_REMOTE_HOST="+remoteHost,
		"SS_REMOTE_PORT="+strconv.Itoa(int(remotePort)),
		"SS_PLUGIN_OPTIONS="+options,
	}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.New("SIP003: could not start locally approved plugin")
	}
	running := &Running{LocalPort:uint16(port),cmd:cmd,done:make(chan error,1)}
	go func(){running.done <- cmd.Wait(); close(running.done)}()

	timeout := approved.StartupTimeout
	if timeout == 0 {
		timeout = 5*time.Second
	}
	if timeout < 200*time.Millisecond || timeout > 30*time.Second {
		_ = running.Close()
		return nil, errors.New("SIP003: unsupported startup timeout")
	}
	checkCtx, cancel := context.WithTimeout(ctx,timeout)
	defer cancel()
	target := net.JoinHostPort("127.0.0.1",strconv.Itoa(port))
	ticker := time.NewTicker(25*time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-running.done:
			_ = running.Close()
			return nil, errors.New("SIP003: approved plugin exited before local listener became ready")
		default:
		}
		connection, err := (&net.Dialer{Timeout:75*time.Millisecond}).DialContext(checkCtx,"tcp4",target)
		if err == nil {
			_ = connection.Close()
			return running,nil
		}
		select {
		case <-checkCtx.Done():
			_ = running.Close()
			return nil, fmt.Errorf("SIP003: approved plugin listener did not become ready")
		case <-ticker.C:
		}
	}
}
