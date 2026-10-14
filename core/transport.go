package core

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *bufferedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func httpPath(c Config) string {
	p := c.Path
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	var out strings.Builder
	digits := "0123456789ABCDEF"
	for i := 0; i < len(p); i++ {
		ch := p[i]
		if ch == '%' && i+2 < len(p) && strings.ContainsRune("0123456789abcdefABCDEF", rune(p[i+1])) && strings.ContainsRune("0123456789abcdefABCDEF", rune(p[i+2])) {
			out.WriteString(p[i : i+3])
			i += 2
		} else if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@/?", rune(ch)) {
			out.WriteByte(ch)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[ch>>4])
			out.WriteByte(digits[ch&15])
		}
	}
	return out.String()
}
func httpHost(c Config) string {
	if c.Host != "" {
		return c.Host
	}
	host := c.Server
	upgrade := c.Transport == "websocket" || c.Transport == "httpupgrade"
	if upgrade && c.Security != "none" && c.ServerName != "" {
		host = c.ServerName
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if !upgrade {
		standard := 80
		if c.Security == "tls" {
			standard = 443
		}
		if c.Port != standard {
			host += ":" + itoa(c.Port)
		}
	}
	return host
}

func openTLS(ctx context.Context, raw net.Conn, c Config) (net.Conn, error) {
	if c.Security == "none" {
		return raw, nil
	}
	settings, e := c.tlsSettings()
	if e != nil {
		return nil, e
	}
	bounded := net.Conn(raw)
	if settings.Vision || settings.LegacyXTLS != "" {
		bounded = &recordBoundedConn{Conn: raw}
	}
	u, _, e := configuredTLS(ctx, bounded, settings)
	if e != nil {
		return nil, e
	}
	if settings.LegacyXTLS != "" {
		return &legacyXTLS{Conn: u, tls: u, raw: raw, direct: settings.LegacyXTLS != "xtls-rprx-origin"}, nil
	}
	if settings.Vision {
		return &directConn{Conn: u, raw: raw}, nil
	}
	return u, nil
}

type wsConn struct {
	net.Conn
	r                *bufio.Reader
	writeMu          sync.Mutex
	pending          []byte
	fragment, closed bool
}

func wsFrame(op byte, b []byte) []byte {
	out := []byte{128 | op}
	n := len(b)
	if n < 126 {
		out = append(out, 128|byte(n))
	} else if n <= 65535 {
		out = append(out, 128|126)
		out = append(out, word(n)...)
	} else {
		out = append(out, 128|127)
		out = append(out, wide(uint64(n))...)
	}
	mask := randomBytes(4)
	out = append(out, mask...)
	for i, v := range b {
		out = append(out, v^mask[i%4])
	}
	return out
}
func (c *wsConn) control(op byte, b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeAll(c.Conn, wsFrame(op, b))
}
func (c *wsConn) Write(b []byte) (int, error) {
	if e := c.control(2, b); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (c *wsConn) CloseWrite() error { return c.control(8, []byte{3, 232}) }
func (c *wsConn) Read(b []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.closed {
			return 0, io.EOF
		}
		var h [2]byte
		if _, e := io.ReadFull(c.r, h[:]); e != nil {
			return 0, e
		}
		fin, op := h[0]&128 != 0, h[0]&15
		if h[0]&0x70 != 0 || h[1]&128 != 0 {
			return 0, errors.New("WEBSOCKET_FLAGS")
		}
		n := uint64(h[1] & 127)
		if n == 126 {
			var x [2]byte
			if _, e := io.ReadFull(c.r, x[:]); e != nil {
				return 0, e
			}
			n = uint64(binary.BigEndian.Uint16(x[:]))
			if n < 126 {
				return 0, errors.New("WEBSOCKET_LENGTH")
			}
		} else if n == 127 {
			var x [8]byte
			if _, e := io.ReadFull(c.r, x[:]); e != nil {
				return 0, e
			}
			n = binary.BigEndian.Uint64(x[:])
			if n <= 65535 {
				return 0, errors.New("WEBSOCKET_LENGTH")
			}
		}
		if n > 524288 || op >= 8 && (!fin || n > 125) {
			return 0, errors.New("WEBSOCKET_FRAME_LIMIT")
		}
		payload := make([]byte, n)
		if _, e := io.ReadFull(c.r, payload); e != nil {
			return 0, e
		}
		switch op {
		case 8:
			if n == 1 {
				return 0, errors.New("WEBSOCKET_CLOSE")
			}
			c.control(8, payload)
			c.closed = true
			return 0, io.EOF
		case 9:
			if e := c.control(10, payload); e != nil {
				return 0, e
			}
			continue
		case 10:
			continue
		case 2:
			if c.fragment {
				return 0, errors.New("WEBSOCKET_FRAGMENT")
			}
			c.fragment = !fin
		case 0:
			if !c.fragment {
				return 0, errors.New("WEBSOCKET_CONTINUATION")
			}
			c.fragment = !fin
		default:
			return 0, errors.New("WEBSOCKET_OPCODE")
		}
		c.pending = payload
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func openUpgrade(raw net.Conn, c Config, early []byte) (net.Conn, int, error) {
	key := base64.StdEncoding.EncodeToString(randomBytes(16))
	request := "GET " + httpPath(c) + " HTTP/1.1\r\nHost: " + httpHost(c) + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
	used := 0
	earlyValue := ""
	if c.Transport == "websocket" {
		request += "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n"
		if c.EarlyData > 0 && len(early) > 0 {
			used = min(c.EarlyData, len(early))
			earlyValue = base64.RawURLEncoding.EncodeToString(early[:used])
			request += c.EarlyHeader + ": " + earlyValue + "\r\n"
		}
	}
	request += "\r\n"
	if e := writeAll(raw, []byte(request)); e != nil {
		return nil, 0, e
	}
	r := bufio.NewReaderSize(raw, 4096)
	resp, e := http.ReadResponse(r, &http.Request{Method: "GET"})
	if e != nil {
		return nil, 0, e
	}
	if resp.StatusCode != 101 {
		return nil, 0, httpStatusError{"HTTP_UPGRADE_STATUS", resp.StatusCode}
	}
	for _, k := range []string{"Upgrade", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions", "Content-Length", "Transfer-Encoding", "Server", "Content-Type", "Content-Encoding"} {
		if len(resp.Header.Values(k)) > 1 {
			return nil, 0, errors.New("HTTP_DUPLICATE_HEADER")
		}
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || !headerToken(strings.Join(resp.Header.Values("Connection"), ","), "upgrade") {
		return nil, 0, errors.New("HTTP_UPGRADE_HEADERS")
	}
	if c.Transport == "httpupgrade" {
		return &bufferedConn{raw, r}, 0, nil
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return nil, 0, errors.New("WEBSOCKET_ACCEPT")
	}
	if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return nil, 0, errors.New("WEBSOCKET_EXTENSION")
	}
	if s := resp.Header.Get("Sec-WebSocket-Protocol"); s != "" && (strings.ToLower(c.EarlyHeader) != "sec-websocket-protocol" || s != earlyValue) {
		return nil, 0, errors.New("WEBSOCKET_PROTOCOL")
	}
	return &wsConn{Conn: raw, r: r}, used, nil
}
func headerToken(s, token string) bool {
	for _, v := range strings.Split(s, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}

type wireCodec interface {
	encode([]byte) ([]byte, error)
	decode([]byte) ([]byte, error)
	finish() []byte
}
type codecConn struct {
	net.Conn
	codec   wireCodec
	pending []byte
	readErr error
	writeMu sync.Mutex
}

func (c *codecConn) Read(b []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		wire := make([]byte, 32768)
		n, e := c.Conn.Read(wire)
		c.pending, c.readErr = c.codec.decode(wire[:n])
		if c.readErr != nil {
			return 0, c.readErr
		}
		if e != nil {
			c.readErr = e
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *codecConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire, e := c.codec.encode(b)
	if e == nil {
		e = writeAll(c.Conn, wire)
	}
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
func (c *codecConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if e := writeAll(c.Conn, c.codec.finish()); e != nil {
		return e
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type muxCodec struct {
	c                     Config
	input                 []byte
	opened, closed, ended bool
}

func (m *muxCodec) frame(status byte, b []byte) []byte {
	opt := byte(0)
	if len(b) > 0 {
		opt = 1
	}
	meta := []byte{0, 1, status, opt}
	if status == 1 {
		a, _ := Address(m.c.Server, m.c.Port)
		meta = append(meta, 1)
		meta = append(meta, word(m.c.Port)...)
		mapped := mappedAddress(a)
		meta = append(meta, mapped[2:]...)
	}
	out := join(word(len(meta)), meta)
	if len(b) > 0 {
		out = append(out, word(len(b))...)
		out = append(out, b...)
	}
	return out
}
func (m *muxCodec) encode(b []byte) ([]byte, error) {
	if m.ended {
		return nil, errors.New("MUX_WRITE_AFTER_END")
	}
	var out []byte
	for len(b) > 0 {
		n := min(16384, len(b))
		s := byte(2)
		if !m.opened {
			s = 1
		}
		out = append(out, m.frame(s, b[:n])...)
		m.opened = true
		b = b[n:]
	}
	return out, nil
}
func (m *muxCodec) finish() []byte {
	if m.ended || !m.opened {
		return nil
	}
	m.ended = true
	return m.frame(3, nil)
}
func (m *muxCodec) decode(b []byte) ([]byte, error) {
	m.input = append(m.input, b...)
	if len(m.input) > 1048576 {
		return nil, errors.New("MUX_BUFFER_LIMIT")
	}
	var out []byte
	for len(m.input) >= 2 {
		n := getWord(m.input, 0)
		if n < 4 || n > 512 {
			return nil, errors.New("MUX_METADATA")
		}
		if len(m.input) < n+2 {
			break
		}
		id, status, opt := getWord(m.input, 2), m.input[4], m.input[5]
		if status < 2 || status > 4 || opt&^3 != 0 || opt&2 != 0 && status != 3 {
			return nil, errors.New("MUX_METADATA")
		}
		total, length := n+2, 0
		if opt&1 != 0 {
			if len(m.input) < total+2 {
				break
			}
			length = getWord(m.input, total)
			total += 2 + length
		}
		if len(m.input) < total {
			break
		}
		if status != 4 {
			if id != 1 || m.closed || opt&2 != 0 {
				return nil, errors.New("MUX_SESSION")
			}
			if length > 0 {
				out = append(out, m.input[total-length:total]...)
			}
			if status == 3 {
				m.closed = true
			}
		}
		m.input = m.input[total:]
	}
	return out, nil
}

func varint(n uint64) []byte { var b [10]byte; l := binary.PutUvarint(b[:], n); return b[:l] }

type grpcCodec struct {
	input []byte
	multi bool
}

func (g *grpcCodec) encode(b []byte) ([]byte, error) {
	message := join([]byte{10}, varint(uint64(len(b))), b)
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[1:], uint32(len(message)))
	return append(header, message...), nil
}
func (g *grpcCodec) finish() []byte { return nil }
func (g *grpcCodec) decode(b []byte) ([]byte, error) {
	g.input = append(g.input, b...)
	if len(g.input) > 1048576 {
		return nil, errors.New("GRPC_BUFFER_LIMIT")
	}
	var out []byte
	for len(g.input) >= 5 {
		n := int(binary.BigEndian.Uint32(g.input[1:5]))
		if g.input[0] != 0 || n > 524288 {
			return nil, errors.New("GRPC_MESSAGE")
		}
		if len(g.input) < n+5 {
			break
		}
		body := g.input[5 : n+5]
		g.input = g.input[n+5:]
		var data []byte
		for len(body) > 0 {
			tag, l := binary.Uvarint(body)
			if l <= 0 || tag>>3 == 0 {
				return nil, errors.New("GRPC_PROTOBUF")
			}
			body = body[l:]
			switch tag & 7 {
			case 2:
				size, l := binary.Uvarint(body)
				if l <= 0 || size > uint64(len(body)-l) {
					return nil, errors.New("GRPC_LENGTH")
				}
				body = body[l:]
				if tag>>3 == 1 {
					if !g.multi {
						data = nil
					}
					data = append(data, body[:size]...)
				}
				body = body[size:]
			case 0:
				_, l := binary.Uvarint(body)
				if l <= 0 {
					return nil, errors.New("GRPC_VARINT")
				}
				body = body[l:]
			case 1, 5:
				n := 8
				if tag&7 == 5 {
					n = 4
				}
				if len(body) < n {
					return nil, errors.New("GRPC_FIXED")
				}
				body = body[n:]
			default:
				return nil, errors.New("GRPC_WIRE")
			}
		}
		out = append(out, data...)
	}
	return out, nil
}
func openGRPC(ctx context.Context, raw net.Conn, c Config) (net.Conn, error) {
	tr := &http2.Transport{AllowHTTP: true, DisableCompression: true}
	client, e := tr.NewClientConn(raw)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	q := &queueConn{up: newByteQueue(), down: newByteQueue(), metaConn: raw}
	q.closeFn = func() { cancel(); client.Close(); raw.Close() }
	multi := contains([]string{"multi", "multi-mode", "multimode"}, strings.ToLower(c.Mode))
	method := "Tun"
	if multi {
		method = "TunMulti"
	}
	service := c.Service
	path := "/" + url.PathEscape(service) + "/" + method
	if strings.HasPrefix(service, "/") {
		parts := strings.Split(service, "/")
		tail := parts[len(parts)-1]
		methods := strings.SplitN(tail, "|", 2)
		method = methods[0]
		if multi && len(methods) > 1 {
			method = methods[1]
		}
		var escaped []string
		for _, s := range parts[1 : len(parts)-1] {
			escaped = append(escaped, url.PathEscape(s))
		}
		path = "/" + strings.Join(escaped, "/") + "/" + url.PathEscape(method)
	}
	scheme := "https"
	if c.Security == "none" || c.Security == "reality" {
		scheme = "http"
	}
	authority := c.Authority
	if authority == "" {
		authority = net.JoinHostPort(c.Server, fmt.Sprint(c.Port))
	}
	req := &http.Request{Method: "POST", URL: &url.URL{Scheme: scheme, Host: authority, Path: path}, Host: authority, Header: http.Header{"Content-Type": {"application/grpc"}, "Te": {"trailers"}, "Grpc-Accept-Encoding": {"identity"}}, Body: io.NopCloser(q.up)}
	req = req.WithContext(ctx)
	go func() {
		resp, e := client.RoundTrip(req)
		if e != nil {
			q.down.close(e)
			q.up.close(e)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/grpc") || resp.Header.Get("Grpc-Encoding") != "" && resp.Header.Get("Grpc-Encoding") != "identity" {
			q.down.close(errors.New("GRPC_RESPONSE"))
			q.up.close(errors.New("GRPC_RESPONSE"))
			return
		}
		_, e = io.Copy(q.down, resp.Body)
		if e == nil && resp.Trailer.Get("Grpc-Status") != "0" {
			e = errors.New("GRPC_STATUS")
		}
		q.down.close(e)
	}()
	return &codecConn{Conn: q, codec: &grpcCodec{multi: multi}}, nil
}

type rawHTTPConn struct {
	net.Conn
	c    Config
	r    *bufio.Reader
	body io.Reader
	init bool
}

func (c *rawHTTPConn) Read(b []byte) (int, error) {
	if !c.init {
		resp, e := http.ReadResponse(c.r, &http.Request{Method: "GET"})
		if e != nil {
			return 0, e
		}
		if resp.StatusCode != 200 {
			return 0, errors.New("HTTP_STATUS")
		}
		if s := resp.Header.Get("Content-Encoding"); s != "" && s != "identity" {
			return 0, errors.New("HTTP_CONTENT_ENCODING")
		}
		c.body = resp.Body
		c.init = true
	}
	return c.body.Read(b)
}
func (c *rawHTTPConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}

func openCarrier(ctx context.Context, c Config, header []byte) (net.Conn, error) {
	if contains([]string{"xhttp", "http", "kcp", "quic"}, c.Transport) {
		return openX(ctx, c, header)
	}
	raw, e := outboundDial(ctx, "tcp", net.JoinHostPort(c.Server, fmt.Sprint(c.Port)), c.ConnectTimeout)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	raw.SetDeadline(time.Now().Add(c.ConnectTimeout))
	m, e := c.masks()
	if e != nil {
		return nil, e
	}
	if len(m) > 0 {
		raw = newMaskedConn(raw, m)
	}
	conn, e := openTLS(ctx, raw, c)
	if e != nil {
		return nil, e
	}
	// Carrier ALPN is checked after authentication without changing explicit ALPN.
	if s, ok := conn.(interface{ ConnectionState() interface{} }); ok {
		_ = s
	}
	used := 0
	initial := header
	var mux *muxCodec
	if c.PluginMux {
		mux = &muxCodec{c: c}
		initial, e = mux.encode(header)
		if e != nil {
			return nil, e
		}
	}
	_, alpn := connectionMeta(conn)
	if c.Security != "none" {
		if c.Transport == "grpc" && c.Security != "reality" && alpn != "h2" {
			return nil, errors.New("ALPN_CARRIER_INCOMPATIBLE")
		}
		if contains([]string{"websocket", "httpupgrade"}, c.Transport) && alpn != "" && alpn != "http/1.1" {
			return nil, errors.New("ALPN_CARRIER_INCOMPATIBLE")
		}
	}
	switch c.Transport {
	case "websocket", "httpupgrade":
		conn, used, e = openUpgrade(conn, c, initial)
	case "grpc":
		conn, e = openGRPC(ctx, conn, c)
	case "obfs-http", "obfs-tls":
		conn = &codecConn{Conn: conn, codec: &obfsCodec{c: c}}
	case "raw":
		if strings.EqualFold(c.Header, "http") {
			request := "GET " + httpPath(c) + " HTTP/1.1\r\nHost: " + httpHost(c) + "\r\nConnection: keep-alive\r\n\r\n"
			e = writeAll(conn, []byte(request))
			conn = &rawHTTPConn{Conn: conn, c: c, r: bufio.NewReader(conn)}
		}
	}
	if e != nil {
		return nil, e
	}
	if e = writeAll(conn, initial[used:]); e != nil {
		return nil, e
	}
	if mux != nil {
		conn = &codecConn{Conn: conn, codec: mux}
	}
	raw.SetDeadline(time.Time{})
	success = true
	return conn, nil
}

// Address encodes an RFC 1928 destination, shared by SOCKS and native TUN.
func Address(host string, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("DESTINATION_PORT")
	}
	var a []byte
	if ip := net.ParseIP(host); ip != nil {
		if v := ip.To4(); v != nil {
			a = append([]byte{1}, v...)
		} else {
			a = append([]byte{4}, ip.To16()...)
		}
	} else {
		if !hostValid(host) || len(host) > 255 {
			return nil, errors.New("DESTINATION_HOST")
		}
		a = join([]byte{3, byte(len(host))}, []byte(host))
	}
	return append(a, word(port)...), nil
}

// Dial opens a project-owned proxy stream. Destination DNS stays inside the proxy.
func Dial(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if c.Routing != nil {
		return nil, errors.New("ROUTE_ENGINE_REQUIRED")
	}
	if c.Protocol == "ss" && c.Plugin == "shadowtls" {
		converted, err := shadowFromSS(c)
		if err != nil {
			return nil, err
		}
		return dialShadowTLS(ctx, converted, host, port)
	}
	if c.Protocol == "tuic" {
		return dialTUIC(ctx, c, host, port)
	}
	if c.Protocol == "shadowtls" {
		return dialShadowTLS(ctx, c, host, port)
	}
	if c.Protocol == "ssh" {
		return dialSSH(ctx, c, host, port)
	}
	if c.Protocol == "wireguard" {
		return dialWireGuard(ctx, c, host, port)
	}
	if c.Protocol == "anytls" {
		return dialAnyTLS(ctx, c, host, port)
	}
	if c.Protocol == "hysteria" {
		return dialHy1(ctx, c, host, port)
	}
	if c.Protocol == "hysteria2" {
		return dialHysteria(ctx, c, host, port)
	}
	if isProxyProtocol(c.Protocol) {
		return dialProxy(ctx, c, host, port)
	}
	return dialProtocol(ctx, c, host, port, false)
}
func dialProtocol(ctx context.Context, c Config, host string, port int, udp bool) (net.Conn, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	address, e := Address(host, port)
	if e != nil {
		return nil, e
	}
	p := newProtocol(c, udp)
	header, e := p.open(address)
	if e != nil {
		return nil, e
	}
	encrypted := c.Protocol == "vless" && c.Encryption != "none"
	initial := header
	if encrypted {
		initial = nil
	}

	conn, e := openCarrier(ctx, c, initial)
	if e != nil {
		return nil, e
	}
	if encrypted {
		conn, e = openEncryption(ctx, conn, c)
		if e != nil {
			return nil, e
		}
		if e = writeAll(conn, header); e != nil {
			conn.Close()
			return nil, e
		}
	}
	return &protocolConn{Conn: conn, p: p}, nil
}
