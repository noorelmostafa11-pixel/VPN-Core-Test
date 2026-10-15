package core

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// XHTTPServerOptions exposes only the server options implemented here.
// Unknown fields are rejected by the routing profile's strict JSON decoder.
type XHTTPServerOptions struct {
	SessionIDPlacement string `json:"sessionIDPlacement,omitempty"`
	SessionIDKey       string `json:"sessionIDKey,omitempty"`
	SeqPlacement       string `json:"seqPlacement,omitempty"`
	SeqKey             string `json:"seqKey,omitempty"`
}

func compileXHTTPMetadata(x XHTTPServerOptions) (XHTTPServerOptions, error) {
	bad := errors.New("XHTTP_SERVER_METADATA_CONFIGURATION")
	if x.SessionIDPlacement == "" {
		x.SessionIDPlacement = "path"
	}
	if x.SeqPlacement == "" {
		x.SeqPlacement = "path"
	}
	fields := []struct {
		placement string
		key       *string
		stem      string
	}{
		{x.SessionIDPlacement, &x.SessionIDKey, "Session"},
		{x.SeqPlacement, &x.SeqKey, "Seq"},
	}
	for _, f := range fields {
		if !contains([]string{"path", "query", "header", "cookie"}, f.placement) {
			return x, bad
		}
		if f.placement == "path" {
			if *f.key != "" {
				return x, bad
			}
			continue
		}
		if *f.key == "" {
			*f.key = "x_" + strings.ToLower(f.stem)
			if f.placement == "header" {
				*f.key = "X-" + f.stem
			}
		}
		if len(*f.key) > 128 || !httpToken(*f.key) {
			return x, bad
		}
		if f.placement == "header" {
			switch strings.ToLower(*f.key) {
			case "host", "connection", "transfer-encoding", "content-length", "content-encoding", "content-type", "cookie", "te", "trailer", "upgrade", "accept-encoding":
				return x, bad
			}
		}
	}
	if x.SessionIDPlacement != "path" && x.SessionIDPlacement == x.SeqPlacement {
		same := x.SessionIDKey == x.SeqKey
		if x.SessionIDPlacement == "header" {
			same = strings.EqualFold(x.SessionIDKey, x.SeqKey)
		}
		if same {
			return x, bad
		}
	}
	return x, nil
}

func (t *ServerTransportConfig) xhttpMetadata() XHTTPServerOptions {
	if t.Extra != nil {
		return *t.Extra
	}
	return XHTTPServerOptions{SessionIDPlacement: "path", SeqPlacement: "path"}
}

// A configured carrier is authoritative. Repeated/empty metadata and alternate
// carriers for the same configured/default keys are rejected before admission.
func xServerMetadata(r *http.Request, query url.Values, cookies []*http.Cookie, placement, key string) (string, bool, bool) {
	var values []string
	switch placement {
	case "header":
		values = r.Header.Values(key)
	case "query":
		values = query[key]
	case "cookie":
		var value string
		count := 0
		for _, cookie := range cookies {
			if cookie.Name == key {
				value = cookie.Value
				count++
			}
		}
		return value, count != 0, count == 0 || count == 1 && value != ""
	}
	if len(values) == 0 {
		return "", false, true
	}
	return values[0], true, len(values) == 1 && values[0] != ""
}

func xServerRequest(r *http.Request, t *ServerTransportConfig) (kind, id string, seq uint64, ok bool) {
	if !serverHostMatches(r.Host, t.Host) || len(r.Header.Values("Content-Encoding")) > 1 || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return
	}
	cookies := r.Cookies()
	x := t.xhttpMetadata()
	allowed := func(placement, key string) bool {
		match := func(p, k string) bool {
			return p == placement && (k == key || p == "header" && strings.EqualFold(k, key))
		}
		return match(x.SessionIDPlacement, x.SessionIDKey) || match(x.SeqPlacement, x.SeqKey)
	}
	for _, key := range []string{"X-Session", "X-Seq", "x_session", "x_seq", x.SessionIDKey, x.SeqKey} {
		if key == "" {
			continue
		}
		for _, placement := range []string{"header", "query", "cookie"} {
			_, present, _ := xServerMetadata(r, query, cookies, placement, key)
			if present && !allowed(placement, key) {
				return
			}
		}
	}
	var parts []string
	if r.URL.Path != t.Path {
		if x.SessionIDPlacement != "path" && x.SeqPlacement != "path" || !strings.HasPrefix(r.URL.Path, t.Path) {
			return
		}
		parts = strings.Split(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, t.Path), "/"), "/")
	}
	extract := func(placement, key string) (string, bool, bool) {
		if placement != "path" {
			return xServerMetadata(r, query, cookies, placement, key)
		}
		if len(parts) == 0 {
			return "", false, true
		}
		value := parts[0]
		parts = parts[1:]
		return value, true, value != ""
	}
	id, hasID, validID := extract(x.SessionIDPlacement, x.SessionIDKey)
	sequence, hasSeq, validSeq := extract(x.SeqPlacement, x.SeqKey)
	if !validID || !validSeq || len(parts) != 0 {
		return "", "", 0, false
	}
	if !hasID {
		return "single", "", 0, !hasSeq && r.Method == t.Method && t.Mode != "packet-up"
	}
	if t.Mode == "stream-one" || len(id) > 128 {
		return "", "", 0, false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return "", "", 0, false
		}
	}
	if r.Method == "GET" {
		return "down", id, 0, !hasSeq && (r.ContentLength == 0 || r.ProtoMajor == 3 && r.ContentLength < 0) && len(r.TransferEncoding) == 0
	}
	if r.Method != t.Method {
		return "", "", 0, false
	}
	if !hasSeq {
		return "upload", id, 0, t.Mode == "auto" || t.Mode == "stream-up"
	}
	if t.Mode != "auto" && t.Mode != "packet-up" || len(sequence) > 20 {
		return "", "", 0, false
	}
	for _, c := range sequence {
		if c < '0' || c > '9' {
			return "", "", 0, false
		}
	}
	seq, err = strconv.ParseUint(sequence, 10, 64)
	return "packet", id, seq, err == nil && seq != ^uint64(0)
}
