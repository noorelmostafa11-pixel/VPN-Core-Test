package conf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxNodeURIBytes = 65536

// nodeFields consumes every connection parameter. Unknown/conflicting data is
// not silently dropped, and errors never include the original URI/credentials.
type nodeFields struct {
	values map[string]string
	err    error
}

func (f *nodeFields) take(keys ...string) string {
	var result string
	set := false
	for _, key := range keys {
		if value, ok := f.values[key]; ok {
			if set && value != result {
				f.err = errors.New("node URI: conflicting connection parameters")
			}
			result, set = value, true
			delete(f.values, key)
		}
	}
	return result
}

func (f *nodeFields) finish() error {
	if f.err != nil {
		return f.err
	}
	if len(f.values) != 0 {
		return errors.New("node URI: unsupported connection parameter")
	}
	return nil
}

func nodeBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.Strict().DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("node URI: invalid base64 profile")
}

func nodeEndpoint(host, port string) (uint16, error) {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t /?#@%") {
		return 0, errors.New("node URI: invalid endpoint")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return 0, errors.New("node URI: invalid hostname")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
					return 0, errors.New("node URI: invalid hostname")
				}
			}
		}
	}
	return uint16(n), nil
}

func nodeJSONFields(body string) (*nodeFields, error) {
	decoded, err := nodeBase64(body)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(decoded) {
		return nil, errors.New("node URI: invalid VMess object")
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return nil, errors.New("node URI: invalid VMess object")
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(object) >= 64 {
			return nil, errors.New("node URI: invalid VMess parameter")
		}
		key = strings.ToLower(key)
		if _, duplicate := object[key]; duplicate {
			return nil, errors.New("node URI: duplicate VMess parameter")
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, errors.New("node URI: invalid VMess parameter")
		}
		object[key] = raw
	}
	if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
		return nil, errors.New("node URI: invalid VMess object")
	}
	var tail any
	if err := decoder.Decode(&tail); err != io.EOF {
		return nil, errors.New("node URI: trailing VMess data")
	}
	fields := &nodeFields{values: make(map[string]string)}
	for key, raw := range object {
		key = strings.ToLower(key)
		var value string
		if string(raw) == "null" {
			continue
		}
		if json.Unmarshal(raw, &value) != nil {
			if (key == "alpn" || key == "host") && len(raw) != 0 && raw[0] == '[' {
				var list []string
				if json.Unmarshal(raw, &list) != nil {
					return nil, errors.New("node URI: invalid list parameter")
				}
				value = strings.Join(list, ",")
			} else if key == "extra" && len(raw) != 0 && raw[0] == '{' {
				value = string(raw)
			} else {
				var scalar any
				if json.Unmarshal(raw, &scalar) != nil {
					return nil, errors.New("node URI: invalid parameter")
				}
				switch scalar.(type) {
				case float64, bool:
					value = string(raw)
				default:
					return nil, errors.New("node URI: invalid scalar parameter")
				}
			}
		}
		if previous, exists := fields.values[key]; exists && previous != value {
			return nil, errors.New("node URI: conflicting parameter names")
		}
		fields.values[key] = value
	}
	return fields, nil
}

// DescribeNodeURI reads connection data only. All capability decisions and
// construction are owned by ResolveNode, shared with structured node input.
func DescribeNodeURI(input string) (*NodeDescription, error) {
	if len(input) > MaxNodeURIBytes {
		return nil, errors.New("node URI: profile too large")
	}
	input = strings.TrimSpace(input)
	if input == "" || strings.ContainsFunc(input, unicode.IsControl) {
		return nil, errors.New("node URI: invalid input")
	}
	scheme, body, ok := strings.Cut(input, "://")
	if !ok {
		return nil, errors.New("node URI: missing scheme")
	}
	scheme = strings.ToLower(scheme)
	fields := &nodeFields{values: make(map[string]string)}
	var host, port, user, password, tag string
	var hasPassword bool
	if scheme == "vmess" && !strings.Contains(strings.SplitN(body, "#", 2)[0], "@") {
		payload, fragment, _ := strings.Cut(body, "#")
		var err error
		fields, err = nodeJSONFields(payload)
		if err != nil {
			return nil, err
		}
		host, port, user = fields.take("add", "address"), fields.take("port"), fields.take("id")
		tag = fields.take("ps", "name", "remarks")
		if fragment != "" {
			tag, err = url.PathUnescape(fragment)
			if err != nil {
				return nil, errors.New("node URI: invalid label")
			}
		}
		fields.take("v") // Version of the share-link envelope, not wire VMess.
		// Some share-link envelopes call the body cipher "security". This is
		// envelope metadata, not a reinterpretation of Xray's original JSON.
		if security := strings.ToLower(fields.values["security"]); security == "auto" || security == "aes-128-gcm" || security == "chacha20-poly1305" || security == "aes-128-cfb" || security == "zero" {
			if cipher := fields.values["scy"]; cipher != "" && !strings.EqualFold(cipher, security) {
				return nil, errors.New("node URI: conflicting VMess body security")
			}
			fields.values["scy"] = security
			delete(fields.values, "security")
		}
		if header := fields.take("type"); header != "" {
			if previous, present := fields.values["headertype"]; present && previous != header {
				return nil, errors.New("node URI: conflicting transport header")
			}
			fields.values["headertype"] = header
		}
	} else {
		var fullSSAuth string
		if scheme == "ss" && !strings.Contains(strings.SplitN(body, "?", 2)[0], "@") {
			payload, query, _ := strings.Cut(strings.SplitN(body, "#", 2)[0], "?")
			decoded, err := nodeBase64(payload)
			if err != nil {
				return nil, err
			}
			auth, endpoint, found := strings.Cut(string(decoded), "@")
			// Passwords can contain @; the endpoint follows the last one.
			if at := strings.LastIndexByte(string(decoded), '@'); at >= 0 {
				auth, endpoint, found = string(decoded[:at]), string(decoded[at+1:]), true
			}
			if !found {
				return nil, errors.New("node URI: invalid Shadowsocks profile")
			}
			fullSSAuth = auth
			input = "ss://" + endpoint
			if query != "" {
				input += "?" + query
			}
			if _, fragment, present := strings.Cut(body, "#"); present {
				input += "#" + fragment
			}
		}
		u, err := url.Parse(input)
		if err != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("node URI: invalid URL")
		}
		host, port, tag = u.Hostname(), u.Port(), u.Fragment
		if u.User != nil {
			user = u.User.Username()
			password, hasPassword = u.User.Password()
		}
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(query) > 64 {
			return nil, errors.New("node URI: invalid query")
		}
		for key, values := range query {
			key = strings.ToLower(key)
			for _, value := range values {
				if previous, exists := fields.values[key]; exists && previous != value {
					return nil, errors.New("node URI: conflicting query parameters")
				}
				fields.values[key] = value
			}
		}
		if scheme == "ss" {
			auth := fullSSAuth
			if auth == "" {
				if hasPassword {
					auth = user + ":" + password
				} else if strings.Contains(user, ":") {
					auth = user
				} else {
					decoded, err := nodeBase64(user)
					if err != nil {
						return nil, err
					}
					auth = string(decoded)
				}
			}
			var found bool
			user, password, found = strings.Cut(auth, ":")
			if !found {
				return nil, errors.New("node URI: invalid Shadowsocks credentials")
			}
		}
	}
	n, err := nodeEndpoint(host, port)
	if err != nil {
		return nil, err
	}
	if !utf8.ValidString(user) || !utf8.ValidString(password) || !utf8.ValidString(tag) {
		return nil, errors.New("node URI: invalid UTF-8 credentials or label")
	}
	if len(tag) > 256 || strings.ContainsFunc(tag, unicode.IsControl) {
		return nil, errors.New("node URI: invalid label")
	}
	credentials := NodeCredentials{}
	switch scheme {
	case "vmess", "vless":
		if user == "" || hasPassword {
			return nil, errors.New("node URI: invalid identity")
		}
		credentials.ID = user
	case "trojan":
		if hasPassword {
			user += ":" + password
		}
		credentials.Password = &user
	case "ss":
		credentials.Method, credentials.Password = user, &password
	default:
		credentials.Username = user
		if hasPassword {
			credentials.Password = &password
		}
	}
	if fields.err != nil {
		return nil, fields.err
	}
	return &NodeDescription{Version: 1, Protocol: scheme, Address: host, Port: n, Name: tag, Credentials: credentials, Parameters: fields.values}, nil
}
