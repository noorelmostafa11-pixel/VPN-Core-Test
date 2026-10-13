package core

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func parseSSHURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "ssh", "raw", "ssh"
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return c, errors.New("SSH_CONFIGURATION")
	}
	c.Server, c.ServerName, c.Port = u.Hostname(), u.Hostname(), 22
	c.Username = u.User.Username()
	c.Password, _ = u.User.Password()
	if u.Port() != "" {
		c.Port, err = number(u.Port(), 1, 65535)
		if err != nil {
			return c, err
		}
	}
	if u.Path != "" && u.Path != "/" {
		return c, errors.New("SSH_CONFIGURATION")
	}
	c.Options = map[string]string{}
	for k, vs := range u.Query() {
		if len(vs) != 1 {
			return c, errors.New("SSH_CONFIGURATION")
		}
		c.Options[strings.ToLower(k)] = vs[0]
	}
	return c, c.Validate()
}
func validateSSH(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || c.Username == "" || len(c.Username) > 128 || len(c.Password) > 4096 || c.Security != "ssh" || c.Transport != "raw" {
		return errors.New("SSH_CONFIGURATION")
	}
	for k := range c.Options {
		if !contains([]string{"hostkey", "known-hosts", "private-key", "private-key-passphrase"}, k) {
			return errors.New("SSH_OPTION_UNSUPPORTED")
		}
	}
	if c.Password == "" && c.Options["private-key"] == "" {
		return errors.New("SSH_AUTH_REQUIRED")
	}
	pin := c.Options["hostkey"]
	if pin == "" && c.Options["known-hosts"] == "" {
		return errors.New("SSH_HOST_KEY_REQUIRED")
	}
	if pin != "" {
		b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(pin, "SHA256:"))
		if err != nil || len(b) != 32 || !strings.HasPrefix(pin, "SHA256:") {
			return errors.New("SSH_HOST_KEY_INVALID")
		}
	}
	if len(c.Options["private-key-passphrase"]) > 4096 {
		return errors.New("SSH_CONFIGURATION")
	}
	return nil
}
func boundedPrivateFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("SSH_KEY_FILE_INVALID")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("SSH_KEY_FILE_INVALID")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("SSH_KEY_FILE_INVALID")
	}
	return b, nil
}
func sshClientConfig(c Config) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{User: c.Username, Timeout: c.ConnectTimeout}
	if c.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(c.Password))
	}
	if path := c.Options["private-key"]; path != "" {
		b, err := boundedPrivateFile(path, 65536)
		if err != nil {
			return nil, err
		}
		var signer ssh.Signer
		if pass := c.Options["private-key-passphrase"]; pass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass))
		} else {
			signer, err = ssh.ParsePrivateKey(b)
		}
		if err != nil {
			return nil, errors.New("SSH_PRIVATE_KEY_INVALID")
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	pin := c.Options["hostkey"]
	var known ssh.HostKeyCallback
	if path := c.Options["known-hosts"]; path != "" {
		if _, err := boundedPrivateFile(path, 8388608); err != nil {
			return nil, err
		}
		var err error
		known, err = knownhosts.New(path)
		if err != nil {
			return nil, errors.New("SSH_KNOWN_HOSTS_INVALID")
		}
	}
	cfg.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if pin != "" && subtle.ConstantTimeCompare([]byte(pin), []byte(ssh.FingerprintSHA256(key))) != 1 {
			return errors.New("SSH_HOST_KEY_MISMATCH")
		}
		if known != nil {
			return known(hostname, remote, key)
		}
		return nil
	}
	return cfg, nil
}

// Each tunneled flow owns its SSH transport. Cancellation closes and joins
// that transport, so an unresponsive channel-open cannot strand a worker or
// cancel another active VPN flow. No shell or remote command is executed.
type sshProxyConn struct {
	ssh.Channel
	raw     net.Conn
	conn    ssh.Conn
	workers sync.WaitGroup
	once    sync.Once
}

func (s *sshProxyConn) Close() error {
	s.once.Do(func() { s.raw.Close(); s.conn.Close(); s.Channel.Close(); s.conn.Wait(); s.workers.Wait() })
	return nil
}
func (s *sshProxyConn) LocalAddr() net.Addr                { return s.raw.LocalAddr() }
func (s *sshProxyConn) RemoteAddr() net.Addr               { return s.raw.RemoteAddr() }
func (s *sshProxyConn) SetDeadline(t time.Time) error      { return s.raw.SetDeadline(t) }
func (s *sshProxyConn) SetReadDeadline(t time.Time) error  { return s.raw.SetReadDeadline(t) }
func (s *sshProxyConn) SetWriteDeadline(t time.Time) error { return s.raw.SetWriteDeadline(t) }

func dialSSH(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if _, err := Address(host, port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	config, err := sshClientConfig(c)
	if err != nil {
		return nil, err
	}
	raw, err := outboundDial(ctx, "tcp", net.JoinHostPort(c.Server, strconv.Itoa(c.Port)), c.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(canceled) })
	detached := false
	detach := func() {
		if !detached {
			if !stop() {
				<-canceled
			}
			detached = true
		}
	}
	defer detach()
	conn, channels, requests, err := ssh.NewClientConn(raw, net.JoinHostPort(c.Server, strconv.Itoa(c.Port)), config)
	if err != nil {
		raw.Close()
		return nil, errors.Join(errors.New("SSH_HANDSHAKE_FAILED"), err)
	}
	result := &sshProxyConn{raw: raw, conn: conn}
	result.workers.Add(2)
	go func() { defer result.workers.Done(); ssh.DiscardRequests(requests) }()
	go func() {
		defer result.workers.Done()
		for c := range channels {
			c.Reject(ssh.UnknownChannelType, "unsupported channel")
		}
	}()
	destination := struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}{host, uint32(port), "127.0.0.1", 0}
	channel, replies, err := conn.OpenChannel("direct-tcpip", ssh.Marshal(destination))
	if err != nil {
		raw.Close()
		conn.Close()
		conn.Wait()
		result.workers.Wait()
		return nil, errors.Join(errors.New("SSH_CHANNEL_FAILED"), err)
	}
	result.Channel = channel
	result.workers.Add(1)
	go func() { defer result.workers.Done(); ssh.DiscardRequests(replies) }()
	detach()
	if ctx.Err() != nil {
		result.Close()
		return nil, ctx.Err()
	}
	raw.SetDeadline(time.Time{})
	return result, nil
}
