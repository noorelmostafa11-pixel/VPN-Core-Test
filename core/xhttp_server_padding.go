package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// XHTTPPaddingRange accepts a JSON number or "min-max", like the XHTTP client.
// From/To are inclusive HPACK byte targets for tokenish, raw bytes otherwise.
type XHTTPPaddingRange struct{ From, To int }

func (r *XHTTPPaddingRange) UnmarshalJSON(data []byte) error {
	var v intRange
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	r.From, r.To = v.Lo, v.Hi
	return nil
}

func (r XHTTPPaddingRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.Itoa(r.From) + "-" + strconv.Itoa(r.To))
}

func (x XHTTPServerOptions) paddingRange() intRange {
	if x.XPaddingBytes == nil {
		return intRange{100, 1000}
	}
	return intRange{x.XPaddingBytes.From, x.XPaddingBytes.To}
}

func compileXHTTPPadding(x XHTTPServerOptions) (XHTTPServerOptions, error) {
	bad := errors.New("XHTTP_SERVER_PADDING_CONFIGURATION")
	x.paddingRequired = x.XPaddingBytes != nil || x.XPaddingObfsMode || x.XPaddingKey != "" || x.XPaddingHeader != "" || x.XPaddingPlacement != "" || x.XPaddingMethod != ""
	if !x.paddingRequired {
		return x, nil // Serialization must not turn disabled policy into opt-in.
	}
	if x.XPaddingBytes != nil {
		r := *x.XPaddingBytes
		if r.From < 1 || r.To < r.From || r.To > 4096 {
			return x, bad
		}
		x.XPaddingBytes = &r // Never retain caller-owned mutable range state.
	}
	if x.XPaddingKey == "" {
		x.XPaddingKey = "x_padding"
	}
	if x.XPaddingHeader == "" {
		x.XPaddingHeader = "X-Padding"
	}
	if x.XPaddingPlacement == "" {
		x.XPaddingPlacement = "queryInHeader"
	}
	if x.XPaddingMethod == "" {
		x.XPaddingMethod = "repeat-x"
	}
	if !contains([]string{"query", "header", "cookie", "queryInHeader"}, x.XPaddingPlacement) || !contains([]string{"repeat-x", "tokenish"}, x.XPaddingMethod) || len(x.XPaddingKey) > 128 || !httpToken(x.XPaddingKey) || len(x.XPaddingHeader) > 128 || !httpToken(x.XPaddingHeader) {
		return x, bad
	}
	switch strings.ToLower(x.XPaddingHeader) {
	case "host", "connection", "transfer-encoding", "content-length", "content-encoding", "content-type", "cookie", "set-cookie", "te", "trailer", "upgrade", "accept-encoding", "cache-control", "x-accel-buffering":
		return x, bad
	}
	// The metadata parser rejects these markers in alternate carriers too.
	effectiveHeader, effectiveKey := x.XPaddingHeader, x.XPaddingKey
	if !x.XPaddingObfsMode {
		effectiveHeader, effectiveKey = "Referer", "x_padding"
	}
	for _, key := range []string{x.SessionIDKey, x.SeqKey, "X-Session", "X-Seq", "x_session", "x_seq"} {
		if key != "" && (strings.EqualFold(x.XPaddingHeader, key) || x.XPaddingKey == key || strings.EqualFold(effectiveHeader, key) || effectiveKey == key) {
			return x, bad
		}
	}
	for _, header := range []string{x.XPaddingHeader, effectiveHeader} {
		if _, matched := xServerPayloadSuffix(header, x.UplinkDataKey, '-', true); matched {
			return x, bad
		}
	}
	for _, key := range []string{x.XPaddingKey, effectiveKey} {
		if _, matched := xServerPayloadSuffix(key, x.UplinkDataKey, '_', false); matched {
			return x, bad
		}
	}
	return x, nil
}

func xServerValidPadding(r *http.Request, query url.Values, cookies []*http.Cookie, x XHTTPServerOptions) bool {
	if !x.paddingRequired {
		return true // Existing listeners did not interpret request padding.
	}
	placement, key, header := x.XPaddingPlacement, x.XPaddingKey, x.XPaddingHeader
	if !x.XPaddingObfsMode {
		placement, key, header = "queryInHeader", "x_padding", "Referer"
		if len(r.Header.Values(header)) == 0 {
			placement = "query" // Legacy direct-query clients remain accepted.
		}
	}
	rawCookies := 0
	for _, line := range r.Header.Values("Cookie") {
		if strings.ContainsAny(line, "\r\n\x00") {
			return false
		}
		for _, part := range strings.Split(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if strings.TrimSpace(name) == key {
				rawCookies++
			}
		}
	}
	parsedCookies := 0
	for _, cookie := range cookies {
		if cookie.Name == key {
			parsedCookies++
		}
	}
	if rawCookies != parsedCookies {
		return false // Standard parsing may silently discard malformed copies.
	}
	value, present, valid := xServerMetadata(r, query, cookies, placement, key)
	if placement == "header" || placement == "queryInHeader" {
		value, present, valid = xServerMetadata(r, query, cookies, "header", header)
		if placement == "queryInHeader" && present && valid {
			u, err := url.Parse(value)
			if err != nil || u.Fragment != "" {
				return false
			}
			q, err := url.ParseQuery(u.RawQuery)
			if err != nil {
				return false
			}
			value, present, valid = xServerMetadata(r, q, nil, "query", key)
		}
	}
	// Do not silently choose one of multiple copies in different carriers.
	for _, carrier := range []string{"query", "cookie", "header"} {
		name := key
		if carrier == "header" {
			name = header
		}
		_, exists, _ := xServerMetadata(r, query, cookies, carrier, name)
		selected := carrier == placement || placement == "queryInHeader" && carrier == "header"
		if exists && !selected {
			return false
		}
	}
	if !valid {
		return false
	}
	if !present {
		return !x.paddingRequired
	}
	if len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	rangeBytes := x.paddingRange()
	if x.XPaddingMethod == "tokenish" {
		n := int(hpack.HuffmanEncodeLength(value))
		return n >= max(0, rangeBytes.Lo-2) && n <= rangeBytes.Hi+2
	}
	return len(value) >= rangeBytes.Lo && len(value) <= rangeBytes.Hi
}

func xServerResponsePadding(w http.ResponseWriter, x XHTTPServerOptions) {
	if x.XPaddingObfsMode && x.XPaddingPlacement == "query" {
		return // A response has no URL query to pad.
	}
	method := x.XPaddingMethod
	if !x.XPaddingObfsMode {
		method = "repeat-x"
	}
	paddingRange := x.paddingRange()
	if !x.paddingRequired {
		paddingRange = intRange{100, 100} // Preserve the existing response default.
	}
	value := (xOptions{XPaddingBytes: paddingRange, XPaddingMethod: method}).padding()
	if !x.XPaddingObfsMode {
		w.Header().Set("X-Padding", value)
		return
	}
	switch x.XPaddingPlacement {
	case "header":
		w.Header().Set(x.XPaddingHeader, value)
	case "queryInHeader":
		w.Header().Set(x.XPaddingHeader, "?"+url.QueryEscape(x.XPaddingKey)+"="+value)
	case "cookie":
		http.SetCookie(w, &http.Cookie{Name: x.XPaddingKey, Value: value, Path: "/"})
	}
}
