package core

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// XHTTPCORSOptions is an opt-in browser policy, not protocol authentication.
type XHTTPCORSOptions struct {
	Origins          []string `json:"origins"`
	AllowCredentials bool     `json:"allowCredentials,omitempty"`
	AllowHeaders     []string `json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders,omitempty"`
	MaxAgeSeconds    int      `json:"maxAgeSeconds,omitempty"`
}

func xServerOrigin(value string) bool {
	if len(value) > 256 || strings.ContainsAny(value, " \t\r\n\x00,\\") {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Scheme != "http" && u.Scheme != "https" || strings.Contains(u.Host, "%") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return false
			}
		}
	}
	return value == u.Scheme+"://"+u.Host
}

func xServerForbiddenHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding", "cookie", "set-cookie", "te", "trailer", "upgrade", "cache-control", "x-accel-buffering", "vary":
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "access-control-")
}

func xServerTemplate(value, method, version string) (string, bool) {
	var out strings.Builder
	for {
		index := strings.Index(value, "${")
		if index < 0 {
			out.WriteString(value)
			break
		}
		out.WriteString(value[:index])
		value = value[index+2:]
		end := strings.IndexByte(value, '}')
		if end < 0 {
			return "", false
		}
		switch value[:end] {
		case "method":
			out.WriteString(method)
		case "httpVersion":
			out.WriteString(version)
		case "version":
			out.WriteString(Version)
		default:
			return "", false
		}
		value = value[end+1:]
	}
	return out.String(), out.Len() <= 512
}

func compileXHTTPResponse(x XHTTPServerOptions) (XHTTPServerOptions, error) {
	bad := errors.New("XHTTP_SERVER_RESPONSE_CONFIGURATION")
	if x.ScStreamUpServerSecs != nil {
		r := *x.ScStreamUpServerSecs
		if !(r.From == 0 && r.To == 0) && (r.From < 1 || r.To < r.From || r.To > 300) {
			return x, bad
		}
		x.ScStreamUpServerSecs = &r
	}
	// Include field-list overhead, padding expansion and optional CORS maxima.
	budget := 384
	pad := 100
	if x.paddingRequired {
		pad = x.paddingRange().Hi
		if x.XPaddingObfsMode && x.XPaddingMethod == "tokenish" {
			n := (pad*5 + 3) / 4
			pad += (3*n+7)/8 + 2
		}
	}
	if x.XPaddingObfsMode && x.XPaddingPlacement == "query" {
		pad = 0
	}
	budget += pad + 64 + len(x.XPaddingHeader) + 3*len(x.XPaddingKey)
	if len(x.ResponseHeaders) > 16 {
		return x, bad
	}
	headers := make(map[string]string, len(x.ResponseHeaders))
	customBudget := 0
	for name, value := range x.ResponseHeaders {
		name = http.CanonicalHeaderKey(name)
		if len(name) > 128 || !httpToken(name) || xServerForbiddenHeader(name) || strings.EqualFold(name, "Content-Type") && !x.NoSSEHeader || strings.EqualFold(name, "X-Padding") || strings.EqualFold(name, x.XPaddingHeader) || len(value) > 512 {
			return x, bad
		}
		for _, c := range value {
			if c < 32 || c == 127 {
				return x, bad
			}
		}
		if _, duplicate := headers[name]; duplicate {
			return x, bad
		}
		expanded, ok := xServerTemplate(value, strings.Repeat("M", 32), "HTTP/1.1")
		if !ok {
			return x, bad
		}
		customBudget += 32 + len(name) + len(expanded)
		headers[name] = value
	}
	if customBudget > 1024 {
		return x, bad
	}
	if x.ResponseHeaders != nil {
		x.ResponseHeaders = headers
	}
	budget += customBudget
	if x.CORS != nil {
		c := *x.CORS
		if len(c.Origins) == 0 || len(c.Origins) > 16 || c.MaxAgeSeconds < 0 || c.MaxAgeSeconds > 600 || len(c.AllowHeaders) > 32 || len(c.ExposeHeaders) > 16 {
			return x, bad
		}
		c.Origins = append([]string(nil), c.Origins...)
		seen := map[string]bool{}
		for _, origin := range c.Origins {
			if seen[origin] || origin == "*" && (c.AllowCredentials || len(c.Origins) != 1) || origin != "*" && !xServerOrigin(origin) {
				return x, bad
			}
			seen[origin] = true
		}
		lists := []*[]string{&c.AllowHeaders, &c.ExposeHeaders}
		for _, list := range lists {
			seen = map[string]bool{}
			length := 0
			copyOf := append([]string(nil), (*list)...)
			for i, name := range copyOf {
				name = http.CanonicalHeaderKey(name)
				if len(name) > 128 || !httpToken(name) || xServerForbiddenHeader(name) || strings.EqualFold(name, "Origin") || seen[name] {
					return x, bad
				}
				copyOf[i], seen[name] = name, true
				length += len(name) + 2
			}
			if length > 512 {
				return x, bad
			}
			*list = copyOf
		}
		x.CORS = &c
		budget += 2304 // Origin, validated requested fields, expose list and Vary.
	}
	if budget > 8192 {
		return x, bad
	}
	return x, nil
}

func xServerCustomHeaders(w http.ResponseWriter, r *http.Request, x XHTTPServerOptions) {
	version := "HTTP/1.1"
	if r.ProtoMajor == 2 {
		version = "HTTP/2.0"
	} else if r.ProtoMajor == 3 {
		version = "HTTP/3.0"
	}
	for name, template := range x.ResponseHeaders {
		value, _ := xServerTemplate(template, r.Method, version)
		w.Header().Set(name, value)
	}
}

func xServerPreflightPath(r *http.Request, t *ServerTransportConfig) bool {
	if r.URL.Path == t.Path {
		return true
	}
	x := t.xhttpMetadata()
	if !strings.HasPrefix(r.URL.Path, t.Path) || x.SessionIDPlacement != "path" && x.SeqPlacement != "path" {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, t.Path), "/"), "/")
	for field, placement := range []string{x.SessionIDPlacement, x.SeqPlacement} {
		if placement != "path" || len(parts) == 0 {
			continue
		}
		part := parts[0]
		parts = parts[1:]
		if part == "" || len(part) > 128 {
			return false
		}
		if field == 1 {
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil || len(part) > 20 || n == ^uint64(0) {
				return false
			}
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
				return false
			}
		}
	}
	return len(parts) == 0
}

// Preflights are finite HTTP responses and never allocate protocol sessions.
func xServerCORS(w http.ResponseWriter, r *http.Request, t *ServerTransportConfig, preflight bool) int {
	x := t.xhttpMetadata()
	c := x.CORS
	if c == nil {
		if preflight {
			return http.StatusNotFound
		}
		return 0
	}
	w.Header().Set("Vary", "Origin")
	origins := r.Header.Values("Origin")
	if len(origins) == 0 && !preflight {
		return 0
	}
	if len(origins) != 1 || !xServerOrigin(origins[0]) {
		return http.StatusBadRequest
	}
	origin := origins[0]
	if contains(c.Origins, "*") {
		origin = "*"
	} else if !contains(c.Origins, origin) {
		return http.StatusForbidden
	}
	if preflight {
		w.Header().Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
		methods := r.Header.Values("Access-Control-Request-Method")
		if len(methods) != 1 || !httpToken(methods[0]) {
			return http.StatusBadRequest
		}
		method := methods[0]
		if method != t.Method && method != "GET" {
			return http.StatusForbidden
		}
		fields := r.Header.Values("Access-Control-Request-Headers")
		if len(fields) > 1 || len(strings.Join(fields, "")) > 1024 {
			return http.StatusBadRequest
		}
		allowed := []string{}
		seen := map[string]bool{}
		if len(fields) > 0 && fields[0] != "" {
			for _, name := range strings.Split(fields[0], ",") {
				name = http.CanonicalHeaderKey(strings.TrimSpace(name))
				if !httpToken(name) || len(name) > 128 || seen[name] || len(allowed) >= 64 {
					return http.StatusBadRequest
				}
				permitted := contains(c.AllowHeaders, name) || name == "Content-Type" || name == "Accept" || x.SessionIDPlacement == "header" && strings.EqualFold(name, x.SessionIDKey) || x.SeqPlacement == "header" && strings.EqualFold(name, x.SeqKey)
				if x.XPaddingObfsMode && (x.XPaddingPlacement == "header" || x.XPaddingPlacement == "queryInHeader") && strings.EqualFold(name, x.XPaddingHeader) {
					permitted = true
				}
				if suffix, match := xServerPayloadSuffix(name, x.UplinkDataKey, '-', true); match && (x.UplinkDataPlacement == "header" || x.UplinkDataPlacement == "auto") {
					index, err := strconv.Atoi(suffix)
					permitted = err == nil && index >= 0 && index < xServerPayloadChunkLimit && strconv.Itoa(index) == suffix
				}
				if !permitted || xServerForbiddenHeader(name) || name == "Origin" {
					return http.StatusForbidden
				}
				allowed, seen[name] = append(allowed, name), true
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", method)
		if len(allowed) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowed, ", "))
		}
		if c.MaxAgeSeconds > 0 {
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(c.MaxAgeSeconds))
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	if c.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if !preflight && len(c.ExposeHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.ExposeHeaders, ", "))
	}
	return 0
}
