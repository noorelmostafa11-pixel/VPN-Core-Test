package core

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

const sniffLimit = 16 * 1024

var sniffBuffers = sync.Pool{New: func() any { return new([sniffLimit]byte) }}

// Only public web destinations need sniffing. Other protocols keep their
// original handshake order and incur no initial-read delay.
func sniffEligible(host string, port int) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && (port == 80 || port == 443 || port == 8080 || port == 8443)
}

type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(b)
	}
	return c.Conn.Read(b)
}
func (c *prefixConn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}

func (e *Engine) destination(c net.Conn, host string, port int) (net.Conn, string) {
	if !e.config.Sniffing || !sniffEligible(host, port) {
		return c, host
	}
	scratch := sniffBuffers.Get().(*[sniffLimit]byte)
	defer sniffBuffers.Put(scratch)
	budget := e.sniffBudget
	if budget == 0 {
		budget = 150 * time.Millisecond
	}
	c.SetReadDeadline(time.Now().Add(budget))
	defer c.SetReadDeadline(time.Time{})
	n := 0
	for n < len(scratch) {
		count, err := c.Read(scratch[n:])
		n += count
		name, more := sniffDestination(scratch[:n])
		if name != "" {
			host = name
			break
		}
		if err != nil || !more {
			break
		}
	}
	if n == 0 {
		if e.dns != nil {
			if name := e.dns.name(host); name != "" {
				return c, name
			}
		}
		return c, host
	}
	if net.ParseIP(host) != nil && e.dns != nil {
		if name := e.dns.name(host); name != "" {
			host = name
		}
	}
	return &prefixConn{Conn: c, prefix: bytes.NewReader(append([]byte(nil), scratch[:n]...))}, host
}

func validSniffName(s string) bool {
	if !hostValid(s) || net.ParseIP(s) != nil {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func sniffDestination(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", true
	}
	if b[0] == 22 {
		var hello []byte
		for pos := 0; pos < len(b); {
			if len(b)-pos < 5 {
				return "", true
			}
			if b[pos] != 22 || b[pos+1] != 3 {
				return "", false
			}
			size := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
			if size == 0 || size > sniffLimit || len(hello)+size > sniffLimit {
				return "", false
			}
			if len(b)-pos-5 < size {
				return "", true
			}
			hello = append(hello, b[pos+5:pos+5+size]...)
			pos += 5 + size
			if len(hello) < 4 {
				continue
			}
			if hello[0] != 1 {
				return "", false
			}
			total := 4 + (int(hello[1]) << 16) + (int(hello[2]) << 8) + int(hello[3])
			if total > sniffLimit {
				return "", false
			}
			if len(hello) < total {
				continue
			}
			return clientHelloName(hello[4:total]), false
		}
		return "", true
	}
	// HTTP/1 headers only; do not wait on arbitrary binary or server-first data.
	prefixes := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}
	possible := false
	for _, p := range prefixes {
		if bytes.HasPrefix(b, []byte(p)) || (len(b) < len(p) && bytes.HasPrefix([]byte(p), b)) {
			possible = true
			break
		}
	}
	if !possible {
		return "", false
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return "", true
	}
	for _, line := range strings.Split(string(b[:end]), "\r\n")[1:] {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(key, "host") {
			name := strings.TrimSpace(value)
			if h, _, err := net.SplitHostPort(name); err == nil {
				name = h
			}
			if validSniffName(name) {
				return name, false
			}
			return "", false
		}
	}
	return "", false
}

func clientHelloName(b []byte) string {
	if len(b) < 35 {
		return ""
	}
	pos := 34
	skip := func(n int) bool {
		if n < 0 || n > len(b)-pos {
			return false
		}
		pos += n
		return true
	}
	session := int(b[pos])
	pos++
	if !skip(session) || len(b)-pos < 2 {
		return ""
	}
	cipher := int(binary.BigEndian.Uint16(b[pos:]))
	pos += 2
	if !skip(cipher) || pos >= len(b) {
		return ""
	}
	compression := int(b[pos])
	pos++
	if !skip(compression) || len(b)-pos < 2 {
		return ""
	}
	size := int(binary.BigEndian.Uint16(b[pos:]))
	pos += 2
	if size > len(b)-pos {
		return ""
	}
	end := pos + size
	name := ""
	for pos+4 <= end {
		kind := binary.BigEndian.Uint16(b[pos:])
		n := int(binary.BigEndian.Uint16(b[pos+2:]))
		pos += 4
		if n > end-pos {
			return ""
		}
		extension := b[pos : pos+n]
		pos += n
		// An encrypted inner name must not be replaced by its public cover name.
		if kind == 0xfe0d {
			return ""
		}
		if kind == 0 && len(extension) >= 5 {
			list := int(binary.BigEndian.Uint16(extension))
			if list != len(extension)-2 {
				return ""
			}
			if extension[2] != 0 {
				return ""
			}
			l := int(binary.BigEndian.Uint16(extension[3:]))
			if l > len(extension)-5 {
				return ""
			}
			candidate := string(extension[5 : 5+l])
			if validSniffName(candidate) {
				name = candidate
			}
		}
	}
	if pos != end {
		return ""
	}
	return name
}
