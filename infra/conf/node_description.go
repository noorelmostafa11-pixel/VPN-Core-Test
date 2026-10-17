package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// DecodeNodeDescription accepts only the declared, versioned node schema. It
// never detects or rewrites an original Xray config based on overlapping keys.
func DecodeNodeDescription(data []byte) (*NodeDescription, error) {
	if len(data) > MaxNodeURIBytes || !utf8.Valid(data) {
		return nil, errors.New("node: invalid or oversized description")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	if !nodeJSONObject(check, 0) {
		return nil, errors.New("node: malformed, duplicate or deeply nested description")
	}
	var tail any
	if check.Decode(&tail) != io.EOF {
		return nil, errors.New("node: trailing description data")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var node NodeDescription
	if decoder.Decode(&node) != nil || node.Version != 1 {
		return nil, errors.New("node: invalid or unsupported description fields")
	}
	return &node, nil
}

// JSON's default decoder accepts duplicate keys. At a connection boundary,
// reject duplicates (including differently cased aliases) before decoding.
func nodeJSONObject(decoder *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(seen) >= 64 {
			return false
		}
		key = strings.ToLower(key)
		if seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
		value = bytes.TrimSpace(value)
		if len(value) != 0 && value[0] == '{' {
			if !nodeJSONObject(json.NewDecoder(bytes.NewReader(value)), depth+1) {
				return false
			}
		}
	}
	close, err := decoder.Token()
	return err == nil && close == json.Delim('}')
}

func ParseNodeJSON(data []byte) (*OutboundDetourConfig, error) {
	node, err := DecodeNodeDescription(data)
	if err != nil {
		return nil, err
	}
	selection, err := ResolveNode(node)
	if err != nil {
		return nil, err
	}
	return selection.Outbound, nil
}
