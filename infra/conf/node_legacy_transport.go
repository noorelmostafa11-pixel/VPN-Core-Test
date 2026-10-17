package conf

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// nodeLegacyTCPHeader maps explicitly selected node headers onto the existing
// TCP HTTP request authenticator. No header means the original RAW path.
func nodeLegacyTCPHeader(header, host, path string) (*TCPConfig, error) {
	if header == "" || header == "none" {
		if host != "" || path != "" {
			return nil, errors.New("node URI: unsupported raw transport parameters")
		}
		return nil, nil
	}
	if header != "http" {
		return nil, errors.New("node URI: unsupported TCP header type")
	}
	if strings.ContainsAny(path, "\r\n\x00") || (path != "" && !strings.HasPrefix(path, "/")) {
		return nil, errors.New("node URI: invalid TCP HTTP header path")
	}
	raw := map[string]any{"type": "http"}
	request := map[string]any{}
	if host != "" {
		names := strings.Split(host, ",")
		for _, name := range names {
			if name == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\r\n\x00 \t") {
				return nil, errors.New("node URI: invalid TCP HTTP header host")
			}
		}
		request["headers"] = map[string][]string{"Host": names}
	}
	if path != "" {
		request["path"] = []string{path}
	}
	if len(request) != 0 {
		raw["request"] = request
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, errors.New("node URI: invalid TCP HTTP header")
	}
	return &TCPConfig{HeaderConfig: encoded}, nil
}

// nodeLegacyKCP keeps original mKCP defaults intact. Only explicit connection
// metadata creates advanced settings or the already registered mkcp-legacy mask.
func nodeLegacyKCP(fields *nodeFields, header, host, path string) (*KCPConfig, *FinalMask, error) {
	config := new(KCPConfig)
	selected := false
	for _, entry := range []struct {
		names  []string
		target **uint32
	}{
		{[]string{"mtu"}, &config.Mtu},
		{[]string{"tti"}, &config.Tti},
		{[]string{"uplinkcapacity", "uplink-capacity", "upcap"}, &config.UpCap},
		{[]string{"downlinkcapacity", "downlink-capacity", "downcap"}, &config.DownCap},
		{[]string{"cwndmultiplier", "cwnd-multiplier"}, &config.CwndMultiplier},
		{[]string{"maxsendingwindow", "max-sending-window"}, &config.MaxSendingWindow},
	} {
		present := false
		for _, name := range entry.names {
			if _, ok := fields.values[name]; ok {
				present = true
			}
		}
		value := fields.take(entry.names...)
		if value == "" {
			if present {
				return nil, nil, errors.New("node URI: empty mKCP numeric parameter")
			}
			continue
		}
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, nil, errors.New("node URI: invalid mKCP numeric parameter")
		}
		num := uint32(number)
		*entry.target = &num
		selected = true
	}
	_, seedPresent := fields.values["seed"]
	seed := fields.take("seed")
	if seedPresent && seed == "" {
		return nil, nil, errors.New("node URI: empty mKCP seed")
	}
	if path != "" {
		if seed != "" && seed != path {
			return nil, nil, errors.New("node URI: conflicting mKCP seed")
		}
		seed = path // Historical VMess share links put mKCP seed in path.
	}
	domainPresent := false
	for _, name := range []string{"headerdomain", "header-domain", "header_domain"} {
		if _, ok := fields.values[name]; ok {
			domainPresent = true
		}
	}
	domain := fields.take("headerdomain", "header-domain", "header_domain")
	if domainPresent && domain == "" {
		return nil, nil, errors.New("node URI: empty mKCP DNS domain")
	}
	if host != "" {
		if header != "dns" || (domain != "" && domain != host) {
			return nil, nil, errors.New("node URI: unsupported mKCP host")
		}
		domain = host
	}
	if len(seed) > 1024 || len(domain) > 253 {
		return nil, nil, errors.New("node URI: oversized mKCP metadata")
	}
	if domain != "" && header != "dns" {
		return nil, nil, errors.New("node URI: mKCP domain requires DNS header")
	}
	var masks []Mask
	if seed != "" {
		settings, _ := json.Marshal(MkcpLegacy{Value: seed})
		raw := json.RawMessage(settings)
		masks = append(masks, Mask{Type: "mkcp-legacy", Settings: &raw})
	}
	if header != "" && header != "none" {
		if header == "wechat-video" {
			header = "wechat"
		}
		switch header {
		case "dns", "dtls", "srtp", "utp", "wechat", "wireguard":
		default:
			return nil, nil, errors.New("node URI: unsupported mKCP header")
		}
		settings, _ := json.Marshal(MkcpLegacy{Header: header, Value: domain})
		raw := json.RawMessage(settings)
		masks = append(masks, Mask{Type: "mkcp-legacy", Settings: &raw})
	}
	if !selected {
		config = nil
	}
	if len(masks) != 0 {
		return config, &FinalMask{Udp: masks}, nil
	}
	return config, nil, nil
}
