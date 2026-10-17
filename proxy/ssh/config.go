// Package ssh adds authenticated TCP forwarding to the ordinary Xray lifecycle.
package ssh

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	xnet "github.com/xtls/xray-core/common/net"
	sshlib "golang.org/x/crypto/ssh"
)

func validUsername(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validSecret(value string) bool {
	return len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsFunc(host, unicode.IsControl) || strings.ContainsAny(host, " /?#@%[]") {
		return false
	}
	if xnet.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return false
			}
		}
	}
	return true
}

func hostPin(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "SHA256:") {
		return nil, errors.New("SSH requires a SHA256 host-key fingerprint")
	}
	pin, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(value, "SHA256:"))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("invalid SSH host-key fingerprint")
	}
	return pin, nil
}

// ValidateClient also guards callers supplying protobuf directly. It performs
// no file access; configured key files are read once when the handler starts.
func ValidateClient(c *ClientConfig) error {
	if c == nil || c.Address == nil || c.Port == 0 || c.Port > 65535 || !validUsername(c.Username) || !validSecret(c.Password) || !validSecret(c.PrivateKeyPassphrase) {
		return errors.New("invalid SSH client configuration")
	}
	switch address := c.Address.Address.(type) {
	case *xnet.IPOrDomain_Ip:
		if address == nil || len(address.Ip) != 4 && len(address.Ip) != 16 {
			return errors.New("invalid SSH server IP")
		}
	case *xnet.IPOrDomain_Domain:
		if address == nil || !validHost(address.Domain) || strings.Contains(address.Domain, ":") {
			return errors.New("invalid SSH server hostname")
		}
	default:
		return errors.New("invalid SSH server address")
	}
	address := c.Address.AsAddress()
	if address == nil || address == xnet.AnyIP || address == xnet.AnyIPv6 || len(address.String()) > 253 || strings.ContainsAny(address.String(), "\x00\r\n\t /?#@%") {
		return errors.New("invalid SSH server address")
	}
	if c.Password == "" && c.PrivateKeyFile == "" || c.PrivateKeyFile == "" && c.PrivateKeyPassphrase != "" || len(c.PrivateKeyFile) > 4096 {
		return errors.New("SSH authentication is required")
	}
	_, err := hostPin(c.HostKey)
	return err
}

func ValidateServer(c *ServerConfig) error {
	if c == nil || !validUsername(c.Username) || !validSecret(c.Password) || !validSecret(c.HostKeyPassphrase) || c.HostKeyFile == "" || len(c.HostKeyFile) > 4096 || len(c.AuthorizedKeysFile) > 4096 || c.Password == "" && c.AuthorizedKeysFile == "" {
		return errors.New("invalid SSH server authentication or host key")
	}
	return nil
}

func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("unable to read SSH key file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid SSH key file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("invalid SSH key file")
	}
	return data, nil
}

func fileSigner(path, passphrase string) (sshlib.Signer, error) {
	data, err := boundedFile(path, 65536)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var signer sshlib.Signer
	if passphrase == "" {
		signer, err = sshlib.ParsePrivateKey(data)
	} else {
		signer, err = sshlib.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	if err != nil {
		return nil, errors.New("invalid SSH private key or passphrase")
	}
	return signer, nil
}

func clientConfig(c *ClientConfig) (*sshlib.ClientConfig, error) {
	if err := ValidateClient(c); err != nil {
		return nil, err
	}
	pin, _ := hostPin(c.HostKey)
	config := &sshlib.ClientConfig{
		User: c.Username,
		HostKeyCallback: func(_ string, _ xnet.Addr, key sshlib.PublicKey) error {
			sum := sha256.Sum256(key.Marshal())
			if subtle.ConstantTimeCompare(pin, sum[:]) != 1 {
				return errors.New("SSH host-key mismatch")
			}
			return nil
		},
	}
	if c.PrivateKeyFile != "" {
		signer, err := fileSigner(c.PrivateKeyFile, c.PrivateKeyPassphrase)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, sshlib.PublicKeys(signer))
	}
	if c.Password != "" {
		config.Auth = append(config.Auth, sshlib.Password(c.Password))
	}
	return config, nil
}

func serverConfig(c *ServerConfig) (*sshlib.ServerConfig, error) {
	if err := ValidateServer(c); err != nil {
		return nil, err
	}
	signer, err := fileSigner(c.HostKeyFile, c.HostKeyPassphrase)
	if err != nil {
		return nil, err
	}
	config := &sshlib.ServerConfig{MaxAuthTries: 3}
	config.AddHostKey(signer)
	usernameHash := sha256.Sum256([]byte(c.Username))
	validUser := func(user string) bool {
		hash := sha256.Sum256([]byte(user))
		return subtle.ConstantTimeCompare(hash[:], usernameHash[:]) == 1
	}
	if c.Password != "" {
		passwordHash := sha256.Sum256([]byte(c.Password))
		config.PasswordCallback = func(metadata sshlib.ConnMetadata, password []byte) (*sshlib.Permissions, error) {
			hash := sha256.Sum256(password)
			passwordOK := subtle.ConstantTimeCompare(hash[:], passwordHash[:]) == 1
			if !validUser(metadata.User()) || !passwordOK {
				return nil, errors.New("SSH authentication failed")
			}
			return nil, nil
		}
	}
	if c.AuthorizedKeysFile != "" {
		data, err := boundedFile(c.AuthorizedKeysFile, 1048576)
		if err != nil {
			return nil, err
		}
		keys, err := authorizedKeys(data)
		if err != nil {
			return nil, err
		}
		config.PublicKeyCallback = func(metadata sshlib.ConnMetadata, key sshlib.PublicKey) (*sshlib.Permissions, error) {
			_, ok := keys[string(key.Marshal())]
			if !validUser(metadata.User()) || !ok {
				return nil, errors.New("SSH authentication failed")
			}
			return nil, nil
		}
	}
	return config, nil
}

func authorizedKeys(data []byte) (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, options, _, err := sshlib.ParseAuthorizedKey(line)
		if err != nil || len(options) != 0 {
			return nil, errors.New("invalid SSH authorized keys or unsupported key options")
		}
		keys[string(key.Marshal())] = struct{}{}
		if len(keys) > 128 {
			return nil, errors.New("too many SSH authorized keys")
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("empty SSH authorized keys")
	}
	return keys, nil
}
