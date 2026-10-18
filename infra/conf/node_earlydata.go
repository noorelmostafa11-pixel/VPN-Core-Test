package conf

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// nodeEarlyDataPath is opt-in and maps node metadata onto the pre-existing
// WebSocket/HTTPUpgrade early-data path parameter. No field means no rewrite.
func nodeEarlyDataPath(fields *nodeFields, path string) (string, error) {
	present := false
	for _, key := range []string{"ed", "earlydata", "early-data"} {
		if _, ok := fields.values[key]; ok {
			present = true
		}
	}
	raw := fields.take("ed", "earlydata", "early-data")
	if !present {
		return path, nil
	}
	if raw == "" {
		return "", errors.New("node URI: empty early-data length")
	}
	amount, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || amount > 2048 {
		return "", errors.New("node URI: invalid early-data length")
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
		strings.ContainsAny(path, "\x00\r\n\t") {
		return "", errors.New("node URI: invalid early-data path")
	}
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return "", errors.New("node URI: invalid early-data path")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("node URI: invalid early-data query")
	}
	if q.Has("ed") {
		return "", errors.New("node URI: conflicting early-data length")
	}
	q.Set("ed", raw)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
