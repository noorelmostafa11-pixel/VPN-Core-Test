package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

func decodeSSHSettings(data []byte, target any) error {
	if len(data) > MaxNodeURIBytes || !nodeJSONObject(json.NewDecoder(bytes.NewReader(data)), 0) {
		return errors.New("invalid or duplicate SSH settings")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errors.New("unsupported SSH settings")
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return errors.New("trailing SSH settings")
	}
	return nil
}

type SSHClientConfig struct {
	Address              *Address `json:"address"`
	Port                 uint16   `json:"port"`
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	HostKey              string   `json:"hostKey"`
	PrivateKeyFile       string   `json:"privateKeyFile"`
	PrivateKeyPassphrase string   `json:"privateKeyPassphrase"`
	UserLevel            uint32   `json:"userLevel"`
}

func (c *SSHClientConfig) UnmarshalJSON(data []byte) error {
	type plain SSHClientConfig
	return decodeSSHSettings(data, (*plain)(c))
}

func (c *SSHClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("SSH server address is required")
	}
	config := &ssh.ClientConfig{Address: c.Address.Build(), Port: uint32(c.Port), Username: c.Username, Password: c.Password, HostKey: c.HostKey, PrivateKeyFile: c.PrivateKeyFile, PrivateKeyPassphrase: c.PrivateKeyPassphrase, UserLevel: c.UserLevel}
	return config, ssh.ValidateClient(config)
}

type SSHServerConfig struct {
	HostKeyFile        string `json:"hostKeyFile"`
	HostKeyPassphrase  string `json:"hostKeyPassphrase"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	AuthorizedKeysFile string `json:"authorizedKeysFile"`
	UserLevel          uint32 `json:"userLevel"`
}

func (c *SSHServerConfig) UnmarshalJSON(data []byte) error {
	type plain SSHServerConfig
	return decodeSSHSettings(data, (*plain)(c))
}

func (c *SSHServerConfig) Build() (proto.Message, error) {
	config := &ssh.ServerConfig{HostKeyFile: c.HostKeyFile, HostKeyPassphrase: c.HostKeyPassphrase, Username: c.Username, Password: c.Password, AuthorizedKeysFile: c.AuthorizedKeysFile, UserLevel: c.UserLevel}
	return config, ssh.ValidateServer(config)
}

func nodeSSHStream(fields *nodeFields) (*StreamConfig, error) {
	network := strings.ToLower(fields.take("type", "network", "net"))
	security := strings.ToLower(fields.take("security", "tls"))
	if network != "" && network != "raw" && network != "tcp" || security != "" && security != "ssh" {
		return nil, errors.New("node: SSH requires raw TCP and SSH security")
	}
	// SSH itself authenticates/encrypts the proxy stream. This describes the
	// outer Xray socket, not an insecure SSH mode or TLS substitution.
	p := TransportProtocol("raw")
	return &StreamConfig{Network: &p, Security: "none"}, nil
}
