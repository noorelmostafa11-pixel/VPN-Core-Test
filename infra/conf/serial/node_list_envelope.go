package serial

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// validatedNodeListEnvelope is an explicit versioned alternative to the
// existing raw JSON node array. Reject duplicate/mixed-case and unrecognized
// metadata. Each node still passes the original strict ParseNodeJSON path.
func validatedNodeListEnvelope(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	begin, err := decoder.Token()
	if err != nil || begin != json.Delim('{') {
		return nil, errors.New("node list: invalid envelope")
	}
	keys := make(map[string]bool, 2)
	var nodes json.RawMessage
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("node list: malformed envelope key")
		}
		name = strings.ToLower(name)
		if keys[name] {
			return nil, errors.New("node list: duplicate envelope field")
		}
		keys[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("node list: invalid envelope value")
		}
		value = bytes.TrimSpace(value)
		switch name {
		case "version":
			if !bytes.Equal(value, []byte("1")) {
				return nil, errors.New("node list: unsupported envelope version")
			}
		case "nodes":
			if len(value) == 0 || value[0] != '[' {
				return nil, errors.New("node list: envelope nodes must be an array")
			}
			nodes = value
		default:
			return nil, errors.New("node list: unsupported envelope parameter")
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("node list: malformed envelope closing")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("node list: trailing envelope data")
	}
	if !keys["version"] || !keys["nodes"] {
		return nil, errors.New("node list: missing envelope fields")
	}
	return nodes, nil
}
