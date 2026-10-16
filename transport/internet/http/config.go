package http

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http/httpguts"
)

const protocolName = "http"

func (c *Config) requestMethod() string {
	if c.Method == "" {
		return "PUT"
	}
	return c.Method
}

func (c *Config) requestURL() (*url.URL, error) {
	path := c.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.Host != "" || u.Scheme != "" || u.Fragment != "" || strings.ContainsAny(path, "\r\n#") || len(path) > 2048 {
		return nil, errors.New("invalid legacy HTTP/2 path")
	}
	return u, nil
}

// Validate also runs on protobuf inputs; JSON validation is not a security boundary.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("missing legacy HTTP/2 settings")
	}
	if _, err := c.requestURL(); err != nil {
		return err
	}
	method := c.requestMethod()
	if !httpguts.ValidHeaderFieldName(method) || len(method) > 32 {
		return errors.New("invalid legacy HTTP/2 method")
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "CONNECT", "TRACE":
		return errors.New("legacy HTTP/2 requires a body-capable method")
	}
	if c.IdleTimeout < 0 || c.IdleTimeout > 600 || c.HealthCheckTimeout < 0 || c.HealthCheckTimeout > 60 || (c.HealthCheckTimeout != 0 && c.IdleTimeout == 0) {
		return errors.New("invalid legacy HTTP/2 health-check timeouts")
	}
	if len(c.Host) > 64 || len(c.Header) > 64 {
		return errors.New("too many legacy HTTP/2 hosts or headers")
	}
	total := 0
	for _, host := range c.Host {
		if host == "" || len(host) > 512 || !httpguts.ValidHostHeader(host) || (&url.URL{Host: host}).Hostname() == "" {
			return errors.New("invalid legacy HTTP/2 host")
		}
		total += len(host)
	}
	seen := make(map[string]bool)
	for _, header := range c.Header {
		if header == nil || !httpguts.ValidHeaderFieldName(header.Name) || len(header.Value) == 0 || len(header.Value) > 16 {
			return errors.New("invalid legacy HTTP/2 header")
		}
		name := strings.ToLower(header.Name)
		if seen[name] {
			return errors.New("duplicate legacy HTTP/2 header name")
		}
		seen[name] = true
		switch name {
		case "host", "connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding", "content-length", "te", "trailer", "accept-encoding", "content-encoding":
			return errors.New("reserved legacy HTTP/2 header: ", name)
		}
		for _, value := range header.Value {
			if !httpguts.ValidHeaderFieldValue(value) {
				return errors.New("invalid legacy HTTP/2 header value")
			}
			total += len(name) + len(value) + 32
		}
	}
	if total > 8192 {
		return errors.New("legacy HTTP/2 metadata exceeds 8192 bytes")
	}
	return nil
}

func (c *Config) applyHeaders(header http.Header) {
	for _, field := range c.Header {
		for _, value := range field.Value {
			header.Add(field.Name, value)
		}
	}
}

func (c *Config) validHost(authority string) bool {
	if len(c.Host) == 0 {
		return true
	}
	got := &url.URL{Host: authority}
	for _, host := range c.Host {
		want := &url.URL{Host: host}
		if strings.EqualFold(got.Hostname(), want.Hostname()) && (want.Port() == "" || got.Port() == want.Port()) {
			return true
		}
	}
	return false
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} { return new(Config) }))
}
