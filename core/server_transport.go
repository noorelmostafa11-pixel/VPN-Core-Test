package core

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type ServerTransportConfig struct {
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	EarlyData   int    `json:"early_data,omitempty"`
	EarlyHeader string `json:"early_header,omitempty"`
	Service     string `json:"service,omitempty"`
	Method      string `json:"method,omitempty"`
	Mode        string `json:"mode,omitempty"`
	HTTPVersion string `json:"http_version,omitempty"`
}

func compileServerTransport(c ServerConfig) (*ServerTransportConfig, error) {
	if c.Transport == nil {
		return nil, nil
	}
	bad := errors.New("SERVER_TRANSPORT_CONFIGURATION")
	if !contains([]string{"vless", "vmess", "trojan", "ss"}, c.Protocol) {
		return nil, bad
	}
	t := *c.Transport
	if t.HTTPVersion != "" && t.Type != "xhttp" {
		return nil, bad
	}
	if t.Type == "raw" {
		if t.Path != "" || t.Host != "" || t.EarlyData != 0 || t.EarlyHeader != "" || t.Service != "" || t.Method != "" || t.Mode != "" {
			return nil, bad
		}
		return nil, nil
	}
	if !contains([]string{"websocket", "httpupgrade", "grpc", "http2", "xhttp"}, t.Type) || c.Reality != nil {
		return nil, bad
	}
	if t.Type == "grpc" {
		if t.Path != "" || t.Method != "" || t.Mode != "" || t.EarlyData != 0 || t.EarlyHeader != "" || len(t.Service) > 256 || strings.ContainsAny(t.Service, "\x00 \t\r\n?#") || len(t.Host) > 253 || strings.ContainsAny(t.Host, "\x00 \t\r\n/@?#") {
			return nil, bad
		}
		if _, _, err := grpcServerPaths(t.Service); err != nil {
			return nil, bad
		}
		return &t, nil
	}
	if t.Service != "" {
		return nil, bad
	}
	if t.Path == "" {
		t.Path = "/"
	}
	if len(t.Path) > 2048 || !strings.HasPrefix(t.Path, "/") {
		return nil, bad
	}
	path, err := url.ParseRequestURI(t.Path)
	if err != nil || path.IsAbs() || path.Fragment != "" {
		return nil, bad
	}
	t.Path = path.Path
	if len(t.Host) > 253 || strings.ContainsAny(t.Host, "\x00 \t\r\n/@?#") {
		return nil, bad
	}
	if t.EarlyData < 0 || t.EarlyData > 4096 {
		return nil, bad
	}
	if t.Type == "xhttp" {
		if t.EarlyData != 0 || t.EarlyHeader != "" {
			return nil, bad
		}
		if t.Mode == "" {
			t.Mode = "stream-one"
		}
		if t.Mode != "stream-one" {
			return nil, bad
		}
		if t.HTTPVersion == "" {
			t.HTTPVersion = "auto"
		}
		if !contains([]string{"auto", "h1", "h2"}, t.HTTPVersion) {
			return nil, bad
		}
		t.Path = strings.TrimSuffix(t.Path, "/") + "/"
		if t.Method == "" {
			t.Method = "POST"
		}
		if len(t.Method) > 32 || !httpToken(t.Method) || contains([]string{"CONNECT", "GET", "HEAD", "TRACE", "OPTIONS"}, t.Method) {
			return nil, bad
		}
		return &t, nil
	}
	if t.Mode != "" {
		return nil, bad
	}
	if t.Type == "http2" {
		if t.EarlyData != 0 || t.EarlyHeader != "" {
			return nil, bad
		}
		if t.Method == "" {
			t.Method = "PUT"
		}
		if len(t.Method) > 32 || !httpToken(t.Method) || contains([]string{"CONNECT", "GET", "HEAD", "TRACE"}, t.Method) {
			return nil, bad
		}
		return &t, nil
	}
	if t.Method != "" {
		return nil, bad
	}
	if t.Type == "httpupgrade" && (t.EarlyData != 0 || t.EarlyHeader != "") {
		return nil, bad
	}
	if t.EarlyData > 0 && t.EarlyHeader == "" {
		t.EarlyHeader = "Sec-WebSocket-Protocol"
	}
	if t.EarlyHeader != "" {
		if t.EarlyData == 0 || len(t.EarlyHeader) > 128 {
			return nil, bad
		}
		for _, r := range t.EarlyHeader {
			if r < 33 || r > 126 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", r) {
				return nil, bad
			}
		}
		if contains([]string{"host", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "content-length", "transfer-encoding"}, strings.ToLower(t.EarlyHeader)) {
			return nil, bad
		}
	}
	return &t, nil
}

func readServerUpgradeHeaders(reader *bufio.Reader) (*http.Request, error) {
	var wire bytes.Buffer
	for wire.Len() <= 8192 {
		line, err := reader.ReadSlice('\n')
		if wire.Len()+len(line) > 8192 {
			return nil, errors.New("SERVER_HTTP_HEADER_LIMIT")
		}
		wire.Write(line)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) {
			return http.ReadRequest(bufio.NewReader(bytes.NewReader(wire.Bytes())))
		}
	}
	return nil, errors.New("SERVER_HTTP_HEADER_LIMIT")
}

func serverHostMatches(actual, configured string) bool {
	if configured == "" {
		return true
	}
	if strings.EqualFold(actual, configured) {
		return true
	}
	if host, _, err := net.SplitHostPort(actual); err == nil {
		return strings.EqualFold(host, configured)
	}
	return false
}

func acceptServerUpgrade(raw net.Conn, t *ServerTransportConfig) (net.Conn, error) {
	reader := bufio.NewReaderSize(raw, 8192)
	request, err := readServerUpgradeHeaders(reader)
	if err != nil {
		httpError(raw, 400)
		return nil, err
	}
	defer request.Body.Close()
	bad := errors.New("SERVER_HTTP_UPGRADE_INVALID")
	if request.Method != "GET" || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.URL.IsAbs() || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		httpError(raw, 400)
		return nil, bad
	}
	if request.URL.Path != t.Path || !serverHostMatches(request.Host, t.Host) {
		httpError(raw, 404)
		return nil, bad
	}
	for _, header := range []string{"Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions", "Content-Length"} {
		if len(request.Header.Values(header)) > 1 {
			httpError(raw, 400)
			return nil, bad
		}
	}
	if !headerToken(strings.Join(request.Header.Values("Connection"), ","), "upgrade") || !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		httpError(raw, 400)
		return nil, bad
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
	if t.Type == "httpupgrade" {
		if err = writeAll(raw, []byte(response+"\r\n")); err != nil {
			return nil, err
		}
		return &bufferedConn{Conn: raw, r: reader}, nil
	}
	if request.Header.Get("Sec-WebSocket-Version") != "13" || request.Header.Get("Sec-WebSocket-Extensions") != "" {
		httpError(raw, 400)
		return nil, bad
	}
	key, err := base64.StdEncoding.DecodeString(request.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 {
		httpError(raw, 400)
		return nil, bad
	}
	var early []byte
	if t.EarlyHeader != "" {
		values := request.Header.Values(t.EarlyHeader)
		if len(values) > 1 {
			httpError(raw, 400)
			return nil, bad
		}
		if len(values) == 1 {
			encoded := values[0]
			if len(encoded) > base64.RawURLEncoding.EncodedLen(t.EarlyData)+2 {
				httpError(raw, 400)
				return nil, bad
			}
			normalized := strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(encoded, "="))
			early, err = base64.RawURLEncoding.DecodeString(normalized)
			if err != nil || len(early) > t.EarlyData {
				httpError(raw, 400)
				return nil, bad
			}
			if strings.EqualFold(t.EarlyHeader, "Sec-WebSocket-Protocol") {
				response += "Sec-WebSocket-Protocol: " + encoded + "\r\n"
			}
		}
	}
	if request.Header.Get("Sec-WebSocket-Protocol") != "" && !strings.EqualFold(t.EarlyHeader, "Sec-WebSocket-Protocol") {
		httpError(raw, 400)
		return nil, bad
	}
	sum := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	response += "Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	if err = writeAll(raw, []byte(response)); err != nil {
		return nil, err
	}
	ws := &wsConn{Conn: raw, r: reader, server: true}
	if len(early) > 0 {
		return &bufferedConn{Conn: ws, r: io.MultiReader(bytes.NewReader(early), ws)}, nil
	}
	return ws, nil
}
