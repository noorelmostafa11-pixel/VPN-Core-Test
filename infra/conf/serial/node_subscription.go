package serial

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

const (
	maxSubscriptionBytes = 1 << 20
	maxSubscriptionNodes = 128
)

// DecodeSubscriptionConfig imports an explicitly selected newline-delimited
// four-protocol share-link subscription. Whole-list Base64 encoding is also
// accepted. It performs no network fetch, resolver fallback or protocol probe.
//
// Unlike the original "uri" decoder, which still requires exactly one node,
// "sub"/"subscription" is opt-in. An invalid line rejects the entire input;
// never skip a malformed or unsupported remote proxy entry silently.
func DecodeSubscriptionConfig(reader io.Reader) (*conf.Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxSubscriptionBytes+1))
	if err != nil || len(data) > maxSubscriptionBytes {
		return nil, errors.New("subscription: unreadable or oversized input")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("subscription: empty input")
	}
	if !bytes.Contains(data, []byte("://")) {
		var decoded []byte
		for _, enc := range []*base64.Encoding{
			base64.RawURLEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.StdEncoding,
		} {
			decoded, err = enc.Strict().DecodeString(string(data))
			if err == nil {
				break
			}
		}
		if err != nil || len(decoded) == 0 || len(decoded) > maxSubscriptionBytes {
			return nil, errors.New("subscription: invalid base64 list")
		}
		data = decoded
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), conf.MaxNodeURIBytes+2)
	result := &conf.Config{
		OutboundConfigs: make([]conf.OutboundDetourConfig, 0, 16),
	}
	for line := 1; scanner.Scan(); line++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if len(raw) > conf.MaxNodeURIBytes || len(result.OutboundConfigs) >= maxSubscriptionNodes {
			return nil, errors.New("subscription: node count or size limit exceeded")
		}
		node, err := conf.ParseNodeURI(raw)
		if err != nil {
			// Avoid embedding the URL/credentials or parser errors in logs.
			return nil, fmt.Errorf("subscription: invalid node at line %d", line)
		}
		// Subscription names are advisory and may collide or be empty. Use
		// deterministic, unique outbound tags without altering the server,
		// method, credentials, or transport selected by ParseNodeURI.
		node.Tag = fmt.Sprintf("subscription-%03d", len(result.OutboundConfigs)+1)
		result.OutboundConfigs = append(result.OutboundConfigs, *node)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("subscription: line too long or unreadable")
	}
	if len(result.OutboundConfigs) == 0 {
		return nil, errors.New("subscription: no supported nodes")
	}
	return result, nil
}
