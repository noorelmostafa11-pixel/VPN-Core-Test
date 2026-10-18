package conf

import (
	"errors"
	"strings"
)

// ResolveNodeWithTrustedXDrive is an explicit application-only selection API:
// the node supplies the four-protocol remote identity and requests "xdrive",
// while the caller supplies a previously approved XDrive profile from local
// trusted configuration. No link can name a local file, folder, credential,
// template, backend or profile identifier.
//
// The ordinary ParseNodeURI / ParseNodeJSON APIs intentionally continue to
// reject xdrive links. No implicit plugin or filesystem permission is added.
func ResolveNodeWithTrustedXDrive(node *NodeDescription, approved *XDriveConfig) (*NodeSelection, error) {
	if node == nil || approved == nil {
		return nil, errors.New("trusted XDrive: missing node or approved profile")
	}
	if approved.RemoteFolder == "" || len(approved.RemoteFolder) > 1024 {
		return nil, errors.New("trusted XDrive: missing or oversized approved storage folder")
	}
	switch approved.Service {
	case "local", "Google Drive":
		// Both are existing backends. The approved profile, never the link,
		// provides the directory, service and any required credentials.
	default:
		return nil, errors.New("trusted XDrive: unapproved storage backend")
	}
	profile := *approved
	profile.Secrets = append([]string(nil), approved.Secrets...)
	profile.Template = append([]byte(nil), approved.Template...)
	if _, err := profile.Build(); err != nil {
		return nil, errors.New("trusted XDrive: invalid approved storage profile")
	}

	clone := *node
	clone.Parameters = make(map[string]string, len(node.Parameters)+2)
	found := false
	for key, value := range node.Parameters {
		switch strings.ToLower(key) {
		case "type", "network", "net":
			if found || !strings.EqualFold(value, "xdrive") {
				return nil, errors.New("trusted XDrive: conflicting or missing network selection")
			}
			found = true
		case "security", "tls", "xdrivesettings", "xdriveprofile", "profile", "secrets", "remotefolder", "service", "template":
			return nil, errors.New("trusted XDrive: local storage or security metadata is not allowed in a link")
		default:
			clone.Parameters[key] = value
		}
	}
	if !found {
		return nil, errors.New("trusted XDrive: node must explicitly request xdrive transport")
	}

	// Parse credentials through the existing four-protocol selection and
	// validation without ever accepting resource metadata from the URI.
	clone.Parameters["type"] = "tcp"
	clone.Parameters["security"] = "none"
	selection, err := ResolveNode(&clone)
	if err != nil {
		return nil, err
	}
	network := TransportProtocol("xdrive")
	selection.Outbound.StreamSetting.Network = &network
	selection.Outbound.StreamSetting.XDRIVESettings = &profile
	if _, err := selection.Outbound.Build(); err != nil {
		return nil, errors.New("trusted XDrive: selected node is incompatible with approved profile")
	}
	return selection, nil
}

// ParseNodeURIWithTrustedXDrive requires an explicit locally approved profile
// from its caller; it does not add any acceptance to the ordinary URI parser.
func ParseNodeURIWithTrustedXDrive(input string, approved *XDriveConfig) (*OutboundDetourConfig, error) {
	node, err := DescribeNodeURI(input)
	if err != nil {
		return nil, err
	}
	selected, err := ResolveNodeWithTrustedXDrive(node, approved)
	if err != nil {
		return nil, err
	}
	return selected.Outbound, nil
}
