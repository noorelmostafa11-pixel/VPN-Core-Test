package conf

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Additive connection-only HTTP header support. The HTTP Host authority stays
// exclusively in the existing node "host" field; never make a share-link
// header object silently override it.
func nodeHTTPTransportHeaders(fields *nodeFields, keys ...string) (map[string]string, error) {
	present := false
	for _, key := range keys {
		if _, found := fields.values[key]; found {
			present = true
		}
	}
	raw := fields.take(keys...)
	if !present {
		return nil, nil
	}
	if raw == "" || len(raw) > 4096 {
		return nil, errors.New("node URI: invalid HTTP transport headers")
	}
	var headers map[string]string
	if err := nodeXHTTPDecodeObject([]byte(raw), &headers); err != nil || len(headers) == 0 || len(headers) > 32 {
		return nil, errors.New("node URI: invalid HTTP transport headers")
	}
	for key, value := range headers {
		if !nodeHTTPHeaderToken(key) || nodeHTTPTransportReservedHeader(key) || len(value) > 2048 ||
			strings.ContainsAny(value, "\x00\r\n") || !nodeHTTPHeaderValue(value) {
			return nil, errors.New("node URI: unsafe HTTP transport header")
		}
	}
	return headers, nil
}

// RFC 9110 token, without accepting obs-text, spaces, separators or controls.
func nodeHTTPHeaderToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch)):
		default:
			return false
		}
	}
	return true
}

func nodeTransportUint32(fields *nodeFields, minimum, maximum uint32, aliases ...string) (uint32, error) {
	found := false
	for _, key := range aliases {
		if _, exists := fields.values[key]; exists {
			found = true
		}
	}
	value := fields.take(aliases...)
	if !found {
		return 0, nil
	}
	if value == "" {
		return 0, errors.New("node URI: empty numeric transport parameter")
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || uint32(parsed) < minimum || uint32(parsed) > maximum {
		return 0, errors.New("node URI: invalid numeric transport parameter")
	}
	return uint32(parsed), nil
}

func nodeGRPCExtensions(fields *nodeFields, config *GRPCConfig) error {
	idle, err := nodeTransportUint32(fields, 0, 3600, "grpcidletimeout", "grpc-idle-timeout")
	if err != nil {
		return err
	}
	health, err := nodeTransportUint32(fields, 0, 300, "grpchealthchecktimeout", "grpc-health-check-timeout")
	if err != nil {
		return err
	}
	window, err := nodeTransportUint32(fields, 0, 16777216, "grpcinitialwindowsize", "grpc-initial-window-size")
	if err != nil {
		return err
	}
	if window != 0 && window < 65535 {
		return errors.New("node URI: invalid gRPC initial window")
	}
	config.IdleTimeout, config.HealthCheckTimeout, config.InitialWindowsSize = int32(idle), int32(health), int32(window)
	without := fields.take("grpcpermitwithoutstream", "grpc-permit-without-stream")
	switch without {
	case "", "false", "0":
	case "true", "1":
		config.PermitWithoutStream = true
	default:
		return errors.New("node URI: invalid gRPC permit-without-stream")
	}
	config.UserAgent = fields.take("grpcuseragent", "grpc-user-agent")
	if len(config.UserAgent) > 256 || !nodeHTTPHeaderValue(config.UserAgent) {
		return errors.New("node URI: invalid gRPC User-Agent")
	}
	return nil
}

func nodeHTTPHeaderValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == 0x7f || ch < 0x20 && ch != '\t' {
			return false
		}
	}
	return true
}

func nodeHTTPTransportReservedHeader(key string) bool {
	switch strings.ToLower(key) {
	case "host", "connection", "proxy-connection", "upgrade",
		"content-length", "transfer-encoding", "sec-websocket-key",
		"sec-websocket-version", "sec-websocket-accept",
		"sec-websocket-protocol", "sec-websocket-extensions":
		return true
	default:
		return false
	}
}
