package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshServerSpec struct {
	config ServerConfig
	ssh    *ssh.ServerConfig
}

func compileSSHServer(c ServerConfig) (sshServerSpec, error) {
	s := sshServerSpec{config: c}
	if c.CertFile != "" || c.Cipher != "" || len(c.UUIDs) != 0 || c.WireGuard != nil || len(c.Password) > 4096 || c.KeyFile == "" {
		return s, errors.New("SSH_SERVER_CONFIGURATION")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil {
		return s, errors.New("SERVER_LISTEN_INVALID")
	}
	if _, err = number(port, 0, 65535); err != nil {
		return s, err
	}
	for k := range c.Options {
		if !contains([]string{"username", "authorized-keys", "host-key-passphrase"}, k) {
			return s, errors.New("SSH_SERVER_OPTION_UNSUPPORTED")
		}
	}
	username := c.Options["username"]
	if username == "" || len(username) > 255 || strings.ContainsAny(username, "\r\n\x00") {
		return s, errors.New("SSH_SERVER_USERNAME_INVALID")
	}
	key, err := boundedPrivateFile(c.KeyFile, 65536)
	if err != nil {
		return s, err
	}
	var signer ssh.Signer
	if phrase := c.Options["host-key-passphrase"]; phrase != "" {
		if len(phrase) > 4096 {
			return s, errors.New("SSH_SERVER_CONFIGURATION")
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(phrase))
	} else {
		signer, err = ssh.ParsePrivateKey(key)
	}
	if err != nil {
		return s, errors.New("SSH_SERVER_HOST_KEY_INVALID")
	}
	s.ssh = &ssh.ServerConfig{MaxAuthTries: 3, ServerVersion: "SSH-2.0-VPNCore"}
	s.ssh.AddHostKey(signer)
	denied := errors.New("SSH_AUTHENTICATION_FAILED")
	if c.Password != "" {
		password := sha256.Sum256([]byte(c.Password))
		s.ssh.PasswordCallback = func(meta ssh.ConnMetadata, input []byte) (*ssh.Permissions, error) {
			h := sha256.Sum256(input)
			if meta.User() != username || subtle.ConstantTimeCompare(h[:], password[:]) != 1 {
				return nil, denied
			}
			return nil, nil
		}
	}
	if path := c.Options["authorized-keys"]; path != "" {
		data, err := boundedPrivateFile(path, 1048576)
		if err != nil {
			return s, err
		}
		keys := map[string]bool{}
		for len(bytes.TrimSpace(data)) > 0 {
			key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
			if err != nil || len(options) != 0 || len(keys) >= 128 {
				return s, errors.New("SSH_AUTHORIZED_KEYS_INVALID")
			}
			keys[string(key.Marshal())] = true
			data = rest
		}
		if len(keys) == 0 {
			return s, errors.New("SSH_AUTHORIZED_KEYS_INVALID")
		}
		s.ssh.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != username || !keys[string(key.Marshal())] {
				return nil, denied
			}
			return nil, nil
		}
	}
	if s.ssh.PasswordCallback == nil && s.ssh.PublicKeyCallback == nil {
		return s, errors.New("SSH_SERVER_AUTH_REQUIRED")
	}
	return s, nil
}

type sshActivityConn struct {
	net.Conn
	last atomic.Int64
}

func (c *sshActivityConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}
func (c *sshActivityConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

type sshForwardConn struct {
	ssh.Channel
	physical net.Conn
}

func (c *sshForwardConn) LocalAddr() net.Addr  { return c.physical.LocalAddr() }
func (c *sshForwardConn) RemoteAddr() net.Addr { return c.physical.RemoteAddr() }

// The private server adapter uses the relay's joined idle watcher. Applying
// a channel deadline to the shared TCP socket would disrupt unrelated flows.
func (c *sshForwardConn) SetDeadline(t time.Time) error {
	if !t.IsZero() {
		return errors.New("SSH_CHANNEL_DEADLINE_UNSUPPORTED")
	}
	return nil
}
func (c *sshForwardConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *sshForwardConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (e *Engine) startSSHServer(c ServerConfig) (net.Addr, error) {
	s, err := compileSSHServer(c)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return nil, err
	}
	if !e.track(l) {
		return nil, net.ErrClosed
	}
	slots := make(chan struct{}, 64)
	if !e.spawn(func() {
		defer l.Close()
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			if !e.track(raw) {
				<-slots
				return
			}
			if !e.spawn(func() { defer func() { <-slots }(); defer raw.Close(); defer e.untrack(raw); e.serveSSH(raw, s) }) {
				raw.Close()
				<-slots
				return
			}
		}
	}) {
		l.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return l.Addr(), nil
}
func (e *Engine) serveSSH(raw net.Conn, s sshServerSpec) {
	raw.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
	activity := &sshActivityConn{Conn: raw}
	activity.last.Store(time.Now().UnixNano())
	conn, channels, requests, err := ssh.NewServerConn(activity, s.ssh)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	raw.SetDeadline(time.Time{})
	var workers sync.WaitGroup
	workers.Add(2)
	defer func() { cancel(); raw.Close(); conn.Close(); conn.Wait(); workers.Wait() }()
	go func() {
		defer workers.Done()
		for r := range requests {
			r.Reply(r.Type == "keepalive@openssh.com" && len(r.Payload) == 0, nil)
		}
	}()
	go func() {
		defer workers.Done()
		timer := time.NewTimer(e.config.IdleTimeout)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				idle := time.Since(time.Unix(0, activity.last.Load()))
				if idle >= e.config.IdleTimeout {
					raw.Close()
					return
				}
				timer.Reset(e.config.IdleTimeout - idle)
			}
		}
	}()
	for request := range channels {
		if request.ChannelType() != "direct-tcpip" {
			request.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		var destination struct {
			Host       string
			Port       uint32
			OriginHost string
			OriginPort uint32
		}
		if len(request.ExtraData()) > 1024 || ssh.Unmarshal(request.ExtraData(), &destination) != nil || destination.Port == 0 || destination.Port > 65535 {
			request.Reject(ssh.Prohibited, "invalid destination")
			continue
		}
		if _, err := Address(destination.Host, int(destination.Port)); err != nil {
			request.Reject(ssh.Prohibited, "invalid destination")
			continue
		}
		if !e.acquire() {
			request.Reject(ssh.ResourceShortage, "connection limit")
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer e.release()
			// The claimed origin is not trusted source/process metadata.
			flow := e.flowContext(ctx, raw.RemoteAddr(), destination.Host)
			setup, cancel := context.WithTimeout(flow, e.config.ConnectTimeout)
			remote, err := e.dialTCP(setup, destination.Host, int(destination.Port))
			cancel()
			if err != nil {
				request.Reject(ssh.ConnectionFailed, "destination unavailable")
				return
			}
			if !e.track(remote) {
				request.Reject(ssh.ConnectionFailed, "owner closed")
				return
			}
			defer e.untrack(remote)
			defer remote.Close()
			closed := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { remote.Close(); close(closed) })
			defer func() {
				if !stop() {
					<-closed
				}
			}()
			channel, replies, err := request.Accept()
			if err != nil {
				return
			}
			defer channel.Close()
			done := make(chan struct{})
			go func() { defer close(done); ssh.DiscardRequests(replies) }()
			e.accepted.Add(1)
			e.relay(&sshForwardConn{Channel: channel, physical: raw}, remote)
			channel.Close()
			<-done
		}()
	}
}
