package conf

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// NodeDescription is versioned connection data, never an original Xray config.
// Parameters have the same connection meanings as URI query metadata. No
// handler, transport, certificate file or feature-enable flag can be injected.
type NodeDescription struct {
	Version     uint32            `json:"version"`
	Protocol    string            `json:"protocol"`
	Address     string            `json:"address"`
	Port        uint16            `json:"port"`
	Name        string            `json:"name,omitempty"`
	Credentials NodeCredentials   `json:"credentials"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

type NodeCredentials struct {
	ID       string  `json:"id,omitempty"`
	Method   string  `json:"method,omitempty"`
	Username string  `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
}

// NodeAddon names a selected, implemented responsibility. This is a report of
// decisions made before building, not a switch or a list of retry candidates.
type NodeAddon string

const (
	NodeVMessHeader   NodeAddon = "vmess-legacy-header"
	NodeVMessBody     NodeAddon = "vmess-legacy-body"
	NodeSSCipher      NodeAddon = "shadowsocks-added-cipher"
	NodeSSServerFirst NodeAddon = "shadowsocks-server-first"
	NodeHTTP2         NodeAddon = "standalone-http2"
	NodeQUIC          NodeAddon = "standalone-quic"
)

type NodeSelection struct {
	Outbound *OutboundDetourConfig
	Addons   []NodeAddon
}

// ResolveNode is the single connection-data integration point. Syntax readers
// supply descriptions; this function selects only declared capabilities and
// then delegates to the ordinary outbound/stream builders. Original full
// JSON/protobuf does not enter here and keeps its established interpretation.
// There is no network I/O, alternate engine, retry, or authentication fallback.
func ResolveNode(node *NodeDescription) (*NodeSelection, error) {
	if node == nil || node.Version != 1 || len(node.Parameters) > 64 {
		return nil, errors.New("node: missing or unsupported description")
	}
	// Bound direct Go callers before allocating a JSON snapshot as well.
	size := len(node.Protocol) + len(node.Address) + len(node.Name) + len(node.Credentials.ID) + len(node.Credentials.Method) + len(node.Credentials.Username)
	if node.Credentials.Password != nil {
		size += len(*node.Credentials.Password)
	}
	for key, value := range node.Parameters {
		size += len(key) + len(value)
		if size > MaxNodeURIBytes {
			return nil, errors.New("node: oversized description")
		}
	}
	if size > MaxNodeURIBytes {
		return nil, errors.New("node: oversized description")
	}
	encoded, err := json.Marshal(node)
	if err != nil || len(encoded) > MaxNodeURIBytes {
		return nil, errors.New("node: oversized description")
	}
	if _, err := nodeEndpoint(node.Address, strconv.Itoa(int(node.Port))); err != nil {
		return nil, err
	}
	if len(node.Name) > 256 || !utf8.ValidString(node.Name) || strings.ContainsFunc(node.Name, unicode.IsControl) {
		return nil, errors.New("node: invalid label")
	}
	credentials := node.Credentials
	for _, value := range []string{node.Protocol, credentials.ID, credentials.Method, credentials.Username} {
		if !utf8.ValidString(value) {
			return nil, errors.New("node: invalid UTF-8 metadata")
		}
	}
	password := ""
	if credentials.Password != nil {
		password = *credentials.Password
		if !utf8.ValidString(password) {
			return nil, errors.New("node: invalid UTF-8 credentials")
		}
	}
	fields := &nodeFields{values: make(map[string]string, len(node.Parameters))}
	for key, value := range node.Parameters {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return nil, errors.New("node: invalid UTF-8 parameter")
		}
		key = strings.ToLower(key)
		if _, exists := fields.values[key]; exists {
			return nil, errors.New("node: duplicate connection parameter")
		}
		fields.values[key] = value
	}
	scheme := strings.ToLower(node.Protocol)
	if !supportedNodeProtocol(scheme) {
		return nil, errors.New("node: protocol is outside this core's supported scope")
	}
	stream, err := nodeStream(fields, scheme)
	if err != nil {
		return nil, err
	}
	selection := &NodeSelection{}
	settings := map[string]any{"address": node.Address, "port": node.Port}
	protocol := scheme
	switch scheme {
	case "vmess", "vless":
		if credentials.ID == "" || credentials.Username != "" || credentials.Method != "" || credentials.Password != nil {
			return nil, errors.New("node: invalid identity credentials")
		}
		settings["id"] = credentials.ID
		if scheme == "vless" {
			encryption := fields.take("encryption")
			if encryption == "" {
				encryption = "none"
			}
			settings["encryption"], settings["flow"] = encryption, fields.take("flow")
			break
		}
		cipher := strings.ToLower(fields.take("scy", "cipher", "encryption"))
		if cipher == "" {
			cipher = "auto"
		}
		alter := fields.take("aid", "alterid")
		var count uint64
		if alter != "" {
			count, err = strconv.ParseUint(alter, 10, 32)
		}
		if err != nil || count > 64 {
			return nil, errors.New("node: unsupported VMess alterId")
		}
		switch cipher {
		case "auto", "aes-128-gcm", "chacha20-poly1305":
		case "aes-128-cfb", "none", "zero":
			selection.Addons = append(selection.Addons, NodeVMessBody)
		default:
			return nil, errors.New("node: unsupported VMess body security")
		}
		if count != 0 {
			selection.Addons = append(selection.Addons, NodeVMessHeader)
		}
		settings["security"] = cipher
		if len(selection.Addons) != 0 {
			settings["legacySettings"] = &VMessLegacySettings{AlterID: uint32(count), Security: cipher}
		}
	case "ss":
		if credentials.ID != "" || credentials.Username != "" || credentials.Method == "" || credentials.Password == nil {
			return nil, errors.New("node: invalid Shadowsocks credentials")
		}
		protocol = "shadowsocks"
		method := strings.ToLower(credentials.Method)
		settings["method"], settings["password"] = method, password
		cipher := cipherFromString(method)
		if cipher != shadowsocks.CipherType_UNKNOWN {
			if cipher >= shadowsocks.CipherType_AES_192_GCM {
				selection.Addons = append(selection.Addons, NodeSSCipher)
			}
			// Preserve the existing node-reader server-first contract, isolated
			// from original full JSON and from the unrelated SS2022 handler.
			settings["serverFirstCompatibility"] = true
			selection.Addons = append(selection.Addons, NodeSSServerFirst)
		} else if _, err := shadowsocks_2022.GetCipherMethod(method); err != nil {
			return nil, errors.New("node: unsupported Shadowsocks method")
		}
	case "trojan":
		if credentials.ID != "" || credentials.Method != "" || credentials.Username != "" || credentials.Password == nil {
			return nil, errors.New("node: invalid Trojan credentials")
		}
		settings["password"] = password
	default:
		return nil, errors.New("node: protocol import is not implemented")
	}
	switch string(*stream.Network) {
	case "http", "h2", "http2", "h2c":
		selection.Addons = append(selection.Addons, NodeHTTP2)
	case "quic":
		selection.Addons = append(selection.Addons, NodeQUIC)
	}
	fields.take("ps", "name", "remarks", "group")
	if err := fields.finish(); err != nil {
		return nil, err
	}
	encoded, err = json.Marshal(settings)
	if err != nil {
		return nil, errors.New("node: unable to build settings")
	}
	raw := json.RawMessage(encoded)
	selection.Outbound = &OutboundDetourConfig{Protocol: protocol, Tag: node.Name, Settings: &raw, StreamSetting: stream}
	if _, err := selection.Outbound.Build(); err != nil {
		// Original builders may echo credentials. Do not wrap their errors or
		// fall back to another transport, cipher or certificate policy.
		return nil, errors.New("node: unsupported or invalid connection settings")
	}
	return selection, nil
}

// Remote node input supports exactly the owner's four protocol families.
// Local ingress, DNS and direct/block routing are core services, not nodes.
func supportedNodeProtocol(protocol string) bool {
	switch protocol {
	case "ss", "trojan", "vless", "vmess":
		return true
	default:
		return false
	}
}

func ParseNodeURI(input string) (*OutboundDetourConfig, error) {
	node, err := DescribeNodeURI(input)
	if err != nil {
		return nil, err
	}
	selection, err := ResolveNode(node)
	if err != nil {
		return nil, err
	}
	return selection.Outbound, nil
}
