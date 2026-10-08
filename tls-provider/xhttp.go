// Project-owned XHTTP byte transport. HTTP framing and TLS primitives come
// from pinned libraries; no external proxy engine is imported.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type intRange struct{ Lo, Hi int }

func (r *intRange) UnmarshalJSON(b []byte) error {
	var text string
	if len(b) > 0 && b[0] == '"' {
		if json.Unmarshal(b, &text) != nil {
			return errors.New("range")
		}
	} else {
		text = string(b)
	}
	if text == "null" || text == "" {
		return nil
	}
	parts := strings.Split(text, "-")
	if len(parts) > 2 {
		return errors.New("range")
	}
	parse := func(s string) (int, error) {
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil || f < 0 || f > 2147483647 || f != float64(int(f)) {
			return 0, errors.New("range")
		}
		return int(f), nil
	}
	lo, err := parse(parts[0])
	if err != nil {
		return err
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = parse(parts[1])
		if err != nil {
			return err
		}
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	r.Lo, r.Hi = lo, hi
	return nil
}
func (r intRange) choose() int {
	if r.Hi <= r.Lo {
		return r.Lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(r.Hi-r.Lo+1)))
	if err != nil {
		return r.Lo
	}
	return r.Lo + int(n.Int64())
}
func (r intRange) defaults(lo, hi int) intRange {
	if r.Hi == 0 {
		return intRange{lo, hi}
	}
	return r
}

type xMux struct {
	MaxConcurrency   intRange `json:"maxConcurrency"`
	MaxConnections   intRange `json:"maxConnections"`
	CMaxReuseTimes   intRange `json:"cMaxReuseTimes"`
	HMaxRequestTimes intRange `json:"hMaxRequestTimes"`
	HMaxReusableSecs intRange `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int      `json:"hKeepAlivePeriod"`
	CMaxLifetimeMS   intRange `json:"cMaxLifetimeMs"`
	MaxReuseTimes    intRange `json:"maxReuseTimes"`
}
type xOptions struct {
	Legacy                                                             bool `json:"-"`
	Host, Path, Mode                                                   string
	Headers                                                            map[string]string
	XPaddingBytes                                                      intRange
	XPaddingObfsMode                                                   bool
	XPaddingKey, XPaddingHeader, XPaddingPlacement, XPaddingMethod     string
	UplinkHTTPMethod, SessionIDPlacement, SessionIDKey, SessionIDTable string
	SessionIDLength                                                    intRange
	SeqPlacement, SeqKey, UplinkDataPlacement, UplinkDataKey           string
	UplinkChunkSize                                                    intRange
	NoGRPCHeader, NoSSEHeader                                          bool
	ScMaxEachPostBytes, ScMinPostsIntervalMs, ScStreamUpServerSecs     intRange
	ScMaxBufferedPosts, ScMaxConcurrentPosts, ServerMaxHeaderBytes     int
	Xmux                                                               xMux
	DownloadSettings                                                   json.RawMessage
	Extra                                                              json.RawMessage
	SessionPlacement, SessionKey                                       string // earlier exported aliases
}

func (x *xOptions) UnmarshalJSON(data []byte) error {
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	integers := map[string]bool{"scMaxBufferedPosts": true, "scMaxConcurrentPosts": true, "serverMaxHeaderBytes": true, "hKeepAlivePeriod": true}
	var walk func(any, string) any
	walk = func(value any, key string) any {
		switch v := value.(type) {
		case map[string]any:
			for k, item := range v {
				v[k] = walk(item, k)
			}
		case []any:
			for i, item := range v {
				v[i] = walk(item, key)
			}
		case json.Number:
			if integers[key] {
				n, err := strconv.ParseFloat(string(v), 64)
				if err == nil && n >= 0 && n <= 2147483647 && n == float64(int64(n)) {
					return json.Number(strconv.FormatInt(int64(n), 10))
				}
			}
		}
		return value
	}
	value = walk(value, "")
	normalized, err := json.Marshal(value)
	if err != nil {
		return err
	}
	type plain xOptions
	return json.Unmarshal(normalized, (*plain)(x))
}

type xSettings struct {
	Transport  string            `json:"transport"`
	KCP        kcpOptions        `json:"kcp"`
	QUIC       legacyQUICOptions `json:"quic"`
	LegacyHTTP bool              `json:"legacy_http"`
	Server     string            `json:"server"`
	Port       int               `json:"port"`
	Host       string            `json:"host"`
	Path       string            `json:"path"`
	Mode       string            `json:"mode"`
	Extra      json.RawMessage   `json:"extra"`
	TLS        settings          `json:"tls"`
	Masks      []wireMask        `json:"masks"`
}

func (c xSettings) options() (xOptions, error) {
	var x xOptions
	if len(c.Extra) > 0 && string(c.Extra) != "null" {
		if json.Unmarshal(c.Extra, &x) != nil {
			return x, providerError(400)
		}
	}
	x.Host, x.Path, x.Mode = c.Host, c.Path, c.Mode
	if c.LegacyHTTP {
		x.Legacy, x.Mode, x.NoGRPCHeader, x.UplinkHTTPMethod = true, "stream-one", true, "PUT"
		if x.Path == "" {
			x.Path = "/"
		}
		if !strings.HasPrefix(x.Path, "/") {
			x.Path = "/" + x.Path
		}
		return x, nil
	}
	if x.Mode == "" || x.Mode == "auto" {
		x.Mode = "packet-up"
		if c.TLS.Security == "reality" {
			x.Mode = "stream-one"
			if len(x.DownloadSettings) > 0 && string(x.DownloadSettings) != "null" {
				x.Mode = "stream-up"
			}
		}
	}
	if x.Mode != "packet-up" && x.Mode != "stream-up" && x.Mode != "stream-one" {
		return x, providerError(400)
	}
	if x.Path == "" {
		x.Path = "/"
	}
	if !strings.HasPrefix(x.Path, "/") {
		x.Path = "/" + x.Path
	}
	if x.SessionIDPlacement == "" {
		x.SessionIDPlacement = x.SessionPlacement
	}
	if x.SessionIDKey == "" {
		x.SessionIDKey = x.SessionKey
	}
	if x.SessionIDPlacement == "" {
		x.SessionIDPlacement = "path"
	}
	if x.SeqPlacement == "" {
		x.SeqPlacement = "path"
	}
	for _, p := range []string{x.SessionIDPlacement, x.SeqPlacement} {
		if p != "path" && p != "header" && p != "query" && p != "cookie" {
			return x, providerError(400)
		}
	}
	if x.UplinkDataPlacement == "" || x.UplinkDataPlacement == "auto" {
		x.UplinkDataPlacement = "body"
	}
	if x.UplinkDataPlacement != "body" && x.UplinkDataPlacement != "header" && x.UplinkDataPlacement != "cookie" {
		return x, providerError(400)
	}
	if x.Mode != "packet-up" && x.UplinkDataPlacement != "body" {
		return x, providerError(400)
	}
	if x.UplinkHTTPMethod == "" {
		x.UplinkHTTPMethod = "POST"
	}
	x.UplinkHTTPMethod = strings.ToUpper(x.UplinkHTTPMethod)
	if !httpToken(x.UplinkHTTPMethod) || (x.UplinkHTTPMethod == "GET" && x.Mode != "packet-up") {
		return x, providerError(400)
	}
	defaultKey := func(placement, value, stem string) string {
		if value != "" {
			return value
		}
		if placement == "header" {
			return "X-" + stem
		}
		return "x_" + strings.ToLower(stem)
	}
	x.SessionIDKey = defaultKey(x.SessionIDPlacement, x.SessionIDKey, "Session")
	x.SeqKey = defaultKey(x.SeqPlacement, x.SeqKey, "Seq")
	x.UplinkDataKey = defaultKey(x.UplinkDataPlacement, x.UplinkDataKey, "Data")
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
	if x.XPaddingMethod != "repeat-x" && x.XPaddingMethod != "tokenish" {
		return x, providerError(400)
	}
	if !map[string]bool{"header": true, "cookie": true, "query": true, "queryInHeader": true}[x.XPaddingPlacement] {
		return x, providerError(400)
	}
	for _, key := range []string{x.SessionIDKey, x.SeqKey, x.UplinkDataKey, x.XPaddingKey, x.XPaddingHeader} {
		if !httpToken(key) {
			return x, providerError(400)
		}
	}
	for name, value := range x.Headers {
		if !httpToken(name) || strings.ContainsAny(value, "\r\n\x00") {
			return x, providerError(400)
		}
		switch strings.ToLower(name) {
		case "host", "connection", "transfer-encoding", "content-length", "upgrade", "te":
			return x, providerError(400)
		}
	}
	x.XPaddingBytes = x.XPaddingBytes.defaults(100, 1000)
	if x.XPaddingBytes.Lo < 1 || x.XPaddingBytes.Hi > 8192 {
		return x, providerError(400)
	}
	x.ScMaxEachPostBytes = x.ScMaxEachPostBytes.defaults(1000000, 1000000)
	if x.ScMaxEachPostBytes.Lo < 1 || x.ScMaxEachPostBytes.Hi > 16*1024*1024 {
		return x, providerError(400)
	}
	x.ScMinPostsIntervalMs = x.ScMinPostsIntervalMs.defaults(30, 30)
	if x.ScMinPostsIntervalMs.Hi > 60000 {
		return x, providerError(400)
	}
	if x.ScMaxBufferedPosts == 0 {
		x.ScMaxBufferedPosts = 30
	}
	if x.ScMaxBufferedPosts < 1 || x.ScMaxBufferedPosts > 4096 || x.ScMaxConcurrentPosts < 0 || x.ScMaxConcurrentPosts > 4096 {
		return x, providerError(400)
	}
	x.ScStreamUpServerSecs = x.ScStreamUpServerSecs.defaults(20, 80)
	if x.UplinkChunkSize.Hi == 0 {
		switch x.UplinkDataPlacement {
		case "header":
			x.UplinkChunkSize = intRange{3000, 4000}
		case "cookie":
			x.UplinkChunkSize = intRange{2048, 3072}
		default:
			x.UplinkChunkSize = x.ScMaxEachPostBytes
		}
	}
	if x.UplinkChunkSize.Lo < 64 {
		x.UplinkChunkSize.Lo = 64
	}
	if x.UplinkChunkSize.Hi < x.UplinkChunkSize.Lo {
		x.UplinkChunkSize.Hi = x.UplinkChunkSize.Lo
	}
	if x.UplinkChunkSize.Hi > 16*1024*1024 {
		return x, providerError(400)
	}
	if x.ServerMaxHeaderBytes == 0 {
		x.ServerMaxHeaderBytes = 8192
	}
	if x.ServerMaxHeaderBytes < 256 || x.ServerMaxHeaderBytes > 1048576 {
		return x, providerError(400)
	}
	if x.Xmux.MaxConnections.Hi > 0 && x.Xmux.MaxConcurrency.Hi > 0 {
		return x, providerError(400)
	}
	tables := map[string]string{"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "BASE36": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "HEX": "0123456789ABCDEF", "alphabet": "abcdefghijklmnopqrstuvwxyz", "base36": "0123456789abcdefghijklmnopqrstuvwxyz", "hex": "0123456789abcdef", "number": "0123456789"}
	if v, ok := tables[x.SessionIDTable]; ok {
		x.SessionIDTable = v
	}
	if x.SessionIDTable != "" {
		if x.SessionIDLength.Lo < 1 || x.SessionIDLength.Hi > 256 || len(x.SessionIDTable) < 2 {
			return x, providerError(400)
		}
		for _, ch := range []byte(x.SessionIDTable) {
			if ch < 33 || ch > 126 || strings.ContainsRune("/;=?&#%\\\"", rune(ch)) {
				return x, providerError(400)
			}
		}
		room := new(big.Int).Exp(big.NewInt(int64(len(x.SessionIDTable))), big.NewInt(int64(x.SessionIDLength.Lo)), nil)
		if room.Cmp(big.NewInt(1<<31)) < 0 {
			return x, providerError(400)
		}
	}
	return x, nil
}
func httpToken(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range []byte(value) {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch))) {
			return false
		}
	}
	return true
}
func randomText(n int, alphabet string) string {
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return ""
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}
func (x xOptions) sessionID() string {
	if x.SessionIDTable != "" {
		return randomText(x.SessionIDLength.choose(), x.SessionIDTable)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func (x xOptions) padding() string {
	n := x.XPaddingBytes.choose()
	if x.XPaddingMethod != "tokenish" {
		return strings.Repeat("X", n)
	}
	s := randomText((n*5+3)/4, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	for hpack.HuffmanEncodeLength(s) > uint64(n+2) && len(s) > 1 {
		s = s[:len(s)-1]
	}
	for hpack.HuffmanEncodeLength(s)+2 < uint64(n) {
		s += "X"
	}
	return s
}
func (x xOptions) request(ctx context.Context, base, session, seq string, body io.Reader, packet bool, payload []byte) (*http.Request, error) {
	method := "GET"
	if body != nil || packet {
		method = x.UplinkHTTPMethod
	}
	if packet && x.UplinkDataPlacement == "body" {
		body = strings.NewReader(string(payload))
	}
	req, err := http.NewRequestWithContext(ctx, method, base, body)
	if err != nil {
		return nil, providerError(400)
	}
	for key, value := range x.Headers {
		req.Header.Set(key, value)
	}
	// The transport owns framing and does not negotiate content compression.
	req.Header.Set("Accept-Encoding", "identity")
	if x.Legacy {
		return req, nil
	}
	if packet && x.UplinkDataPlacement != "body" {
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		for i := 0; len(encoded) > 0; i++ {
			n := x.UplinkChunkSize.choose()
			if n > len(encoded) {
				n = len(encoded)
			}
			chunk := encoded[:n]
			encoded = encoded[n:]
			if x.UplinkDataPlacement == "header" {
				req.Header.Set(fmt.Sprintf("%s-%d", x.UplinkDataKey, i), chunk)
			} else {
				req.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", x.UplinkDataKey, i), Value: chunk})
			}
		}
	}
	padding := x.padding()
	placement, key, header := x.XPaddingPlacement, x.XPaddingKey, x.XPaddingHeader
	if !x.XPaddingObfsMode {
		placement, key, header = "queryInHeader", "x_padding", "Referer"
	}
	switch placement {
	case "queryInHeader":
		u := *req.URL
		u.RawQuery = url.QueryEscape(key) + "=" + padding
		req.Header.Set(header, u.String())
	case "header":
		req.Header.Set(header, padding)
	case "query":
		q := req.URL.Query()
		q.Set(key, padding)
		req.URL.RawQuery = q.Encode()
	case "cookie":
		req.AddCookie(&http.Cookie{Name: key, Value: padding})
	}
	add := func(placement, key, value string) {
		if value == "" {
			return
		}
		switch placement {
		case "path":
			req.URL.Path = strings.TrimSuffix(req.URL.Path, "/") + "/" + value
			req.URL.RawPath = ""
		case "query":
			q := req.URL.Query()
			q.Set(key, value)
			req.URL.RawQuery = q.Encode()
		case "header":
			req.Header.Set(key, value)
		case "cookie":
			req.AddCookie(&http.Cookie{Name: key, Value: value})
		}
	}
	add(x.SessionIDPlacement, x.SessionIDKey, session)
	if packet {
		add(x.SeqPlacement, x.SeqKey, seq)
	}
	if !packet && body != nil && !x.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
	if packet && x.UplinkDataPlacement != "body" {
		total := 0
		for k, values := range req.Header {
			for _, v := range values {
				total += len(k) + len(v) + 4
			}
		}
		if total > x.ServerMaxHeaderBytes {
			return nil, providerError(406)
		}
	}
	return req, nil
}

// Queue writes from the C ABI are nonblocking. HTTP readers and response
// writers block at a bounded queue to propagate backpressure to TCP.
type byteQueue struct {
	mu      sync.Mutex
	changed *sync.Cond
	data    []byte
	closed  bool
	err     error
}

func newByteQueue() *byteQueue { q := &byteQueue{}; q.changed = sync.NewCond(&q.mu); return q }
func (q *byteQueue) Read(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.data) == 0 && !q.closed {
		q.changed.Wait()
	}
	if len(q.data) == 0 {
		if q.err != nil {
			return 0, q.err
		}
		return 0, io.EOF
	}
	n := copy(b, q.data)
	copy(q.data, q.data[n:])
	q.data = q.data[:len(q.data)-n]
	q.changed.Broadcast()
	return n, nil
}
func (q *byteQueue) Write(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.data)+len(b) > bufferLimit && !q.closed {
		q.changed.Wait()
	}
	if q.closed {
		return 0, io.ErrClosedPipe
	}
	q.data = append(q.data, b...)
	q.changed.Broadcast()
	return len(b), nil
}
func (q *byteQueue) close(err error) {
	q.mu.Lock()
	q.closed = true
	q.err = err
	q.changed.Broadcast()
	q.mu.Unlock()
}

type xSession struct {
	released            bool
	mu                  sync.Mutex
	up, down            *byteQueue
	state, code, status int
	version             uint16
	alpn                string
	cancel              context.CancelFunc
	closers             []io.Closer
}

var xSessions sync.Map

func findX(id C.uint64_t) *xSession {
	v, ok := xSessions.Load(uint64(id))
	if !ok {
		return nil
	}
	return v.(*xSession)
}
func (s *xSession) fail(err error) {
	code := xhttpErrorCode(err)
	s.mu.Lock()
	if s.state == 2 || s.released {
		s.mu.Unlock()
		return
	}
	if s.state >= 0 {
		s.state = -1
		s.code = code
	}
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.up.close(err)
	s.down.close(err)
}
func (s *xSession) metadata(conn net.Conn) {
	s.mu.Lock()
	if u, ok := conn.(interface{ projectTLSState() (uint16, string) }); ok {
		s.version, s.alpn = u.projectTLSState()
	}
	if s.state == 0 {
		s.state = 1
	}
	s.mu.Unlock()
}

type tlsHTTPConn struct {
	net.Conn
	version uint16
	alpn    string
}

func (c *tlsHTTPConn) projectTLSState() (uint16, string) { return c.version, c.alpn }
func (s *xSession) dial(ctx context.Context, c xSettings, forced string) (net.Conn, error) {
	raw, err := outboundDial(ctx, "tcp", net.JoinHostPort(c.Server, strconv.Itoa(c.Port)), time.Duration(c.TLS.TimeoutMS)*time.Millisecond)
	if err != nil {
		return nil, providerError(tlsErrorCode(err, 402))
	}
	conn := net.Conn(raw)
	if len(c.Masks) > 0 {
		conn = newMaskedConn(raw, c.Masks)
	}
	if c.TLS.Security != "none" {
		t := c.TLS
		if forced != "" {
			t.ALPN = []string{forced}
		}
		u, _, err := configuredTLS(ctx, conn, t)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		state := u.ConnectionState()
		conn = &tlsHTTPConn{u, state.Version, state.NegotiatedProtocol}
	}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		_ = raw.Close()
		return nil, context.Canceled
	}
	s.closers = append(s.closers, raw)
	s.mu.Unlock()
	s.metadata(conn)
	return conn, nil
}

type firstDial struct {
	mu   sync.Mutex
	conn net.Conn
}

func (f *firstDial) take() net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.conn
	f.conn = nil
	return c
}
func (s *xSession) client(ctx context.Context, c xSettings, x xOptions) (*http.Client, func(), error) {
	if c.TLS.Security == "reality" || c.LegacyHTTP {
		c.TLS.ALPN = []string{"h2"}
	}
	if c.TLS.Security == "tls" && len(c.TLS.ALPN) > 0 && c.TLS.ALPN[0] == "h3" {
		return s.http3Client(c, x)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(c.TLS.TimeoutMS)*time.Millisecond)
	conn, err := s.dial(timeoutCtx, c, "")
	cancel()
	if err != nil {
		return nil, nil, err
	}
	first := &firstDial{conn: conn}
	alpn := ""
	if c.LegacyHTTP && c.TLS.Security == "none" {
		alpn = "h2"
	}
	if u, ok := conn.(*tlsHTTPConn); ok {
		alpn = u.alpn
	}
	dial := func(ctx context.Context, forced string) (net.Conn, error) {
		if c := first.take(); c != nil {
			return c, nil
		}
		return s.dial(ctx, c, forced)
	}
	var rt http.RoundTripper
	var closeIdle func()
	if alpn == "h2" {
		tr := &http2.Transport{AllowHTTP: true, DisableCompression: true, ReadIdleTimeout: time.Duration(x.Xmux.HKeepAlivePeriod) * time.Second, PingTimeout: 10 * time.Second, DialTLSContext: func(ctx context.Context, _, _ string, _ *gotls.Config) (net.Conn, error) { return dial(ctx, "h2") }}
		rt, closeIdle = tr, tr.CloseIdleConnections
	} else if alpn == "" || alpn == "http/1.1" {
		tr := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: time.Duration(c.TLS.TimeoutMS) * time.Millisecond, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "") }, DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "http/1.1") }}
		rt, closeIdle = tr, tr.CloseIdleConnections
	} else {
		_ = conn.Close()
		return nil, nil, providerError(403)
	}
	return &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, closeIdle, nil
}
func xBase(c xSettings, x xOptions) string {
	scheme := "http"
	if c.TLS.Security != "none" {
		scheme = "https"
	}
	host := x.Host
	if host == "" {
		host = c.TLS.ServerName
	}
	if host == "" {
		host = c.Server
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	path := x.Path
	parts := strings.SplitN(path, "?", 2)
	path = parts[0]
	if !x.Legacy && (x.SessionIDPlacement == "path" || x.SeqPlacement == "path") {
		path = strings.TrimSuffix(path, "/") + "/"
	}
	u := url.URL{Scheme: scheme, Host: host, Path: path}
	if len(parts) > 1 {
		u.RawQuery = parts[1]
	}
	return u.String()
}
func (s *xSession) response(client *http.Client, req *http.Request, download bool) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		s.mu.Lock()
		s.status = resp.StatusCode
		s.mu.Unlock()
		return providerError(404)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return providerError(405)
	}
	if download {
		_, err = io.CopyBuffer(s.down, resp.Body, make([]byte, 16384))
	} else {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 65537))
	}
	return err
}
func (s *xSession) run(c xSettings) {
	if c.Transport == "quic" {
		s.runLegacyQUIC(c)
		return
	}
	if c.Transport == "kcp" {
		s.runMKCP(c)
		return
	}
	ctx, cancel := context.WithCancel(providerContext())
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		cancel()
		return
	}
	s.cancel = cancel
	s.mu.Unlock()
	defer cancel()
	x, err := c.options()
	if err != nil {
		s.fail(err)
		return
	}
	client, closeIdle, err := s.client(ctx, c, x)
	if err != nil {
		s.fail(err)
		return
	}
	defer closeIdle()
	base := xBase(c, x)
	id := ""
	if x.Mode != "stream-one" {
		id = x.sessionID()
	}
	if x.Mode == "stream-one" {
		req, err := x.request(ctx, base, "", "", s.up, false, nil)
		if err == nil {
			err = s.response(client, req, true)
		}
		if err != nil {
			s.fail(err)
			return
		}
		s.down.close(nil)
		s.mu.Lock()
		s.state = 2
		s.mu.Unlock()
		return
	}
	downClient, downClose, downBase, downX := client, func() {}, base, x
	if len(x.DownloadSettings) > 0 && string(x.DownloadSettings) != "null" {
		dc, err := downloadConfig(c, x.DownloadSettings)
		if err != nil {
			s.fail(err)
			return
		}
		downX, err = dc.options()
		if err != nil {
			s.fail(err)
			return
		}
		downClient, downClose, err = s.client(ctx, dc, downX)
		if err != nil {
			s.fail(err)
			return
		}
		downBase = xBase(dc, downX)
	}
	defer downClose()
	done := make(chan error, 1)
	go func() {
		req, err := downX.request(ctx, downBase, id, "", nil, false, nil)
		if err == nil {
			err = s.response(downClient, req, true)
		}
		done <- err
	}()
	go func() {
		var err error
		if x.Mode == "stream-up" {
			req, e := x.request(ctx, base, id, "", s.up, false, nil)
			err = e
			if err == nil {
				err = s.response(client, req, false)
			}
		} else {
			err = s.packets(ctx, c, x, client, base, id)
		}
		if err != nil {
			s.fail(err)
		}
	}()
	select {
	case err = <-done:
		if err != nil {
			s.fail(err)
			return
		}
		s.down.close(nil)
		s.mu.Lock()
		if s.state >= 0 {
			s.state = 2
		}
		s.mu.Unlock()
	case <-ctx.Done():
		return
	}
}
func (s *xSession) packets(ctx context.Context, c xSettings, x xOptions, client *http.Client, base, id string) error {
	var seq uint64
	last := time.Time{}
	buffer := make([]byte, min(x.ScMaxEachPostBytes.Hi, 16384))
	requests, limit := 0, x.Xmux.HMaxRequestTimes.choose()
	started := time.Now()
	reuseSecs := x.Xmux.HMaxReusableSecs.choose()
	lifetimeMS := x.Xmux.CMaxLifetimeMS.choose()
	var extraClose []func()
	defer func() {
		for _, close := range extraClose {
			close()
		}
	}()
	for {
		n, err := s.up.Read(buffer)
		if n > 0 {
			maxPost := x.ScMaxEachPostBytes.choose()
			if x.UplinkDataPlacement != "body" {
				maxPost = min(maxPost, max(1, (x.ServerMaxHeaderBytes-2048)*3/4))
			}
			for offset := 0; offset < n; {
				count := min(maxPost, n-offset)
				wait := time.Duration(x.ScMinPostsIntervalMs.choose())*time.Millisecond - time.Since(last)
				if wait > 0 {
					select {
					case <-time.After(wait):
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if (limit > 0 && requests >= limit) || (reuseSecs > 0 && time.Since(started) >= time.Duration(reuseSecs)*time.Second) || (lifetimeMS > 0 && time.Since(started) >= time.Duration(lifetimeMS)*time.Millisecond) {
					next, close, e := s.client(ctx, c, x)
					if e != nil {
						return e
					}
					client = next
					extraClose = append(extraClose, close)
					requests = 0
					started = time.Now()
					limit = x.Xmux.HMaxRequestTimes.choose()
					reuseSecs = x.Xmux.HMaxReusableSecs.choose()
					lifetimeMS = x.Xmux.CMaxLifetimeMS.choose()
				}
				req, e := x.request(ctx, base, id, strconv.FormatUint(seq, 10), nil, true, buffer[offset:offset+count])
				if e != nil {
					return e
				}
				if e = s.response(client, req, false); e != nil {
					return e
				}
				last = time.Now()
				seq++
				requests++
				offset += count
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
func downloadConfig(parent xSettings, raw json.RawMessage) (xSettings, error) {
	var d struct {
		Address           string
		Port              int
		Network, Security string
		TLSSettings       json.RawMessage
		RealitySettings   json.RawMessage
		XHTTPSettings     json.RawMessage
		SplitHTTPSettings json.RawMessage
	}
	if json.Unmarshal(raw, &d) != nil {
		return parent, providerError(400)
	}
	c := parent
	if d.Address != "" {
		c.Server = d.Address
	}
	if d.Port != 0 {
		c.Port = d.Port
	}
	if d.Network != "" && d.Network != "xhttp" && d.Network != "splithttp" {
		return c, providerError(400)
	}
	if d.Security != "" {
		c.TLS.Security = d.Security
	}
	if c.TLS.Security != "none" && c.TLS.Security != "tls" && c.TLS.Security != "reality" {
		return c, providerError(400)
	}
	var tls struct {
		ServerName, Fingerprint, ECHConfigList, PublicKey, ShortID, Mldsa65Verify string
		ALPN                                                                      []string
		PinnedPeerCertSha256, VerifyPeerCertByName                                []string
	}
	tr := d.TLSSettings
	if c.TLS.Security == "reality" {
		tr = d.RealitySettings
	}
	if len(tr) > 0 && string(tr) != "null" {
		if json.Unmarshal(tr, &tls) != nil {
			return c, providerError(400)
		}
		if tls.ServerName != "" {
			c.TLS.ServerName = tls.ServerName
		}
		if tls.Fingerprint != "" {
			c.TLS.Fingerprint = tls.Fingerprint
		}
		if len(tls.ALPN) > 0 {
			c.TLS.ALPN = tls.ALPN
		}
		if tls.ECHConfigList != "" {
			c.TLS.ECH = tls.ECHConfigList
		}
		if tls.PublicKey != "" {
			c.TLS.PublicKey = tls.PublicKey
		}
		c.TLS.ShortID = tls.ShortID
		c.TLS.PQVerify = tls.Mldsa65Verify
		if len(tls.PinnedPeerCertSha256) > 0 {
			c.TLS.Pins = tls.PinnedPeerCertSha256
		}
		if len(tls.VerifyPeerCertByName) > 0 {
			c.TLS.Names = tls.VerifyPeerCertByName
		}
	}
	options := d.XHTTPSettings
	if len(options) == 0 {
		options = d.SplitHTTPSettings
	}
	if len(options) > 0 && string(options) != "null" {
		var x xOptions
		if json.Unmarshal(options, &x) != nil {
			return c, providerError(400)
		}
		c.Host, c.Path, c.Mode = x.Host, x.Path, x.Mode
		c.Extra = options
		if len(x.Extra) > 0 && string(x.Extra) != "null" {
			c.Extra = x.Extra
		}
	}
	return c, nil
}

//export vpn_xhttp_new
func vpn_xhttp_new(data *C.char, length C.int, initial *C.char, n C.int) C.uint64_t {
	if length <= 0 || length > 131072 || n < 0 || n > 65536 {
		return 0
	}
	var c xSettings
	if json.Unmarshal(C.GoBytes(unsafe.Pointer(data), length), &c) != nil || c.Port < 1 || c.Port > 65535 || c.TLS.TimeoutMS < 1000 {
		return 0
	}
	s := &xSession{up: newByteQueue(), down: newByteQueue()}
	s.up.data = C.GoBytes(unsafe.Pointer(initial), n)
	id := nextID.Add(1)
	xSessions.Store(id, s)
	go s.run(c)
	return C.uint64_t(id)
}

//export vpn_xhttp_validate
func vpn_xhttp_validate(data *C.char, length C.int) C.int {
	if length <= 0 || length > 131072 {
		return 400
	}
	var c xSettings
	if json.Unmarshal(C.GoBytes(unsafe.Pointer(data), length), &c) != nil {
		return 400
	}
	if c.Transport == "quic" {
		if err := c.QUIC.validate(); err != nil {
			return 400
		}
		if c.TLS.Security != "tls" && c.TLS.Security != "none" {
			return 400
		}
		return 0
	}
	if c.Transport == "kcp" {
		if _, err := c.KCP.validate(); err != nil {
			return 400
		}
		return 0
	}
	x, err := c.options()
	if err != nil {
		return 400
	}
	if len(x.DownloadSettings) > 0 && string(x.DownloadSettings) != "null" {
		dc, err := downloadConfig(c, x.DownloadSettings)
		if err != nil {
			return 400
		}
		if _, err = dc.options(); err != nil {
			return 400
		}
	}
	return 0
}

//export vpn_xhttp_write
func vpn_xhttp_write(id C.uint64_t, data *C.char, length C.int) C.int {
	s := findX(id)
	if s == nil || length < 0 || length > 65536 {
		return -1
	}
	q := s.up
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return -1
	}
	if len(q.data)+int(length) > bufferLimit {
		return 0
	}
	q.data = append(q.data, C.GoBytes(unsafe.Pointer(data), length)...)
	q.changed.Broadcast()
	return length
}

//export vpn_xhttp_read
func vpn_xhttp_read(id C.uint64_t, data *C.char, length C.int) C.int {
	s := findX(id)
	if s == nil || length < 0 || length > 65536 {
		return -1
	}
	q := s.down
	q.mu.Lock()
	defer q.mu.Unlock()
	n := min(len(q.data), int(length))
	if n > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(data)), n), q.data[:n])
		copy(q.data, q.data[n:])
		q.data = q.data[:len(q.data)-n]
		q.changed.Broadcast()
	}
	return C.int(n)
}

//export vpn_xhttp_state
func vpn_xhttp_state(id C.uint64_t) C.int {
	s := findX(id)
	if s == nil {
		return -400
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state < 0 {
		return C.int(-s.code)
	}
	return C.int(s.state)
}

//export vpn_xhttp_info
func vpn_xhttp_info(id C.uint64_t, data *C.char, length C.int) C.int {
	s := findX(id)
	if s == nil {
		return -1
	}
	s.mu.Lock()
	b, _ := json.Marshal(map[string]any{"version": s.version, "alpn": s.alpn, "http_status": s.status})
	s.mu.Unlock()
	if len(b) > int(length) {
		return -1
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(data)), len(b)), b)
	return C.int(len(b))
}

//export vpn_xhttp_pending
func vpn_xhttp_pending(id C.uint64_t) C.int {
	s := findX(id)
	if s == nil {
		return -1
	}
	s.up.mu.Lock()
	defer s.up.mu.Unlock()
	return C.int(len(s.up.data))
}

//export vpn_xhttp_finish
func vpn_xhttp_finish(id C.uint64_t) C.int {
	s := findX(id)
	if s == nil {
		return -1
	}
	s.up.close(nil)
	return 0
}

//export vpn_xhttp_free
func vpn_xhttp_free(id C.uint64_t) {
	v, ok := xSessions.LoadAndDelete(uint64(id))
	if !ok {
		return
	}
	s := v.(*xSession)
	s.mu.Lock()
	s.released = true
	cancel := s.cancel
	closers := append([]io.Closer(nil), s.closers...)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, closer := range closers {
		_ = closer.Close()
	}
	s.up.close(io.ErrClosedPipe)
	s.down.close(io.ErrClosedPipe)
}
