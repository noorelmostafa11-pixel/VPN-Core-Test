package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func isProxyProtocol(p string) bool {
	return contains([]string{"http", "socks4", "socks4a", "socks5", "direct", "block"}, p)
}

func parseProxyURI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI, c.Transport, c.Security = uri, "raw", "none"
	u, err := url.Parse(uri)
	if err != nil || u == nil || u.Opaque != "" {
		return c, errors.New("PARSE_INVALID: proxy URI")
	}
	c.Protocol = strings.ToLower(u.Scheme)
	if c.Protocol == "direct" || c.Protocol == "block" {
		if u.Host != "" || u.User != nil || u.Path != "" || u.RawQuery != "" {
			return c, errors.New("PARSE_INVALID: direct/block URI takes no parameters")
		}
		return c, nil
	}
	switch c.Protocol {
	case "https":
		c.Protocol, c.Security = "http", "tls"
	case "socks", "socks5h":
		c.Protocol = "socks5"
	}
	c.Server, c.ServerName = u.Hostname(), u.Hostname()
	c.Port, err = number(u.Port(), 1, 65535)
	if err != nil {
		return c, errors.New("PARSE_INVALID: proxy port is required")
	}
	if u.Path != "" && u.Path != "/" {
		return c, errors.New("PARSE_INVALID: proxy URI path")
	}
	if u.User != nil {
		c.Username = u.User.Username()
		c.Password, _ = u.User.Password()
	}
	c.Options = map[string]string{}
	for k, values := range u.Query() {
		if len(values) != 1 || !contains([]string{"sni", "security", "fp", "alpn", "pinsha256"}, k) {
			return c, errors.New("PARSE_INVALID: proxy option")
		}
		c.Options[k] = values[0]
	}
	c.ServerName = option(c.Options, c.ServerName, "sni")
	c.Security = security(option(c.Options, c.Security, "security"))
	c.Fingerprint = c.Options["fp"]
	if v := c.Options["alpn"]; v != "" {
		c.ALPN = strings.Split(v, ",")
	}
	return c, validateProxyConfig(c)
}

func validateProxyConfig(c Config) error {
	if c.Protocol == "direct" || c.Protocol == "block" {
		return nil
	}
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 {
		return errors.New("PARSE_INVALID: proxy endpoint")
	}
	if c.Transport != "raw" || !contains([]string{"none", "tls"}, c.Security) || c.Flow != "" || c.Encryption != "none" {
		return errors.New("PROXY_CONFIGURATION")
	}
	if len(c.Username) > 255 || len(c.Password) > 255 || strings.ContainsAny(c.Username+c.Password, "\x00\r\n") {
		return errors.New("PROXY_CREDENTIAL_INVALID")
	}
	if c.Protocol == "socks5" && c.Username == "" && c.Password != "" || (c.Protocol == "socks4" || c.Protocol == "socks4a") && c.Password != "" {
		return errors.New("PROXY_CREDENTIAL_INVALID")
	}
	if c.Security == "tls" {
		if _, err := profile(c.Fingerprint); err != nil {
			return errors.New("TLS_FINGERPRINT_INVALID")
		}
	}
	if c.Protocol == "http" && len(c.ALPN) > 0 && (len(c.ALPN) != 1 || c.ALPN[0] != "http/1.1") {
		return errors.New("HTTP_PROXY_ALPN")
	}
	_, err := c.tlsSettings()
	return err
}

func proxySocket(ctx context.Context, c Config) (net.Conn, error) {
	raw, err := outboundDial(ctx, "tcp", net.JoinHostPort(c.Server, strconv.Itoa(c.Port)), c.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(c.ConnectTimeout))
	if c.Protocol == "http" && c.Security == "tls" && len(c.ALPN) == 0 {
		c.ALPN = []string{"http/1.1"}
	}
	conn, err := openTLS(ctx, raw, c)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func dialProxy(ctx context.Context, c Config, host string, port int) (net.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	address, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	if c.Protocol == "block" {
		return nil, errors.New("ROUTE_BLOCKED")
	}
	if c.Protocol == "direct" {
		return outboundDial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), c.ConnectTimeout)
	}
	conn, err := proxySocket(ctx, c)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	result := conn
	if c.Protocol == "http" {
		target := net.JoinHostPort(host, strconv.Itoa(port))
		r := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
		if c.Username != "" || c.Password != "" {
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
		}
		if err = r.Write(conn); err == nil {
			reader := bufio.NewReader(io.LimitReader(conn, 16385))
			var resp *http.Response
			resp, err = http.ReadResponse(reader, r)
			if err == nil && resp.StatusCode/100 != 2 {
				err = errors.New("HTTP_PROXY_REJECTED")
			}
			if err == nil {
				// Replay bytes read with the response header, then use the raw
				// stream without the bounded handshake reader.
				prefix := make([]byte, reader.Buffered())
				io.ReadFull(reader, prefix)
				result = &prefixConn{Conn: conn, prefix: bytes.NewReader(prefix)}
			}
		}
	} else if c.Protocol == "socks5" {
		if err = socks5Auth(conn, c); err == nil {
			_, err = socks5Request(conn, 1, address)
		}
	} else {
		err = socks4Request(ctx, conn, c, host, port)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !stop() && ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	conn.SetDeadline(time.Time{})
	return result, nil
}

func socks5Auth(conn net.Conn, c Config) error {
	method := byte(0)
	if c.Username != "" {
		method = 2
	}
	if err := writeAll(conn, []byte{5, 1, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{5, method} {
		return errors.New("SOCKS_AUTH_REJECTED")
	}
	if method == 2 {
		b := append([]byte{1, byte(len(c.Username))}, c.Username...)
		b = append(b, byte(len(c.Password)))
		b = append(b, c.Password...)
		if err := writeAll(conn, b); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		if reply != [2]byte{1, 0} {
			return errors.New("SOCKS_AUTH_REJECTED")
		}
	}
	return nil
}

func socks5Request(conn net.Conn, command byte, address []byte) ([]byte, error) {
	if err := writeAll(conn, join([]byte{5, command, 0}, address)); err != nil {
		return nil, err
	}
	var reply [3]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply != [3]byte{5, 0, 0} {
		return nil, errors.New("SOCKS_REQUEST_REJECTED")
	}
	return readAddress(conn)
}

func socks4Request(ctx context.Context, conn net.Conn, c Config, host string, port int) error {
	ip := net.ParseIP(host).To4()
	if ip == nil && c.Protocol == "socks4" {
		ips, err := bootstrapIPs(ctx, host)
		if err != nil {
			return err
		}
		for _, a := range ips {
			if ip = a.IP.To4(); ip != nil {
				break
			}
		}
		if ip == nil {
			return errors.New("SOCKS4_IPV4_REQUIRED")
		}
	}
	if ip == nil && net.ParseIP(host) != nil {
		return errors.New("SOCKS4_IPV4_REQUIRED")
	}
	b := append([]byte{4, 1}, word(port)...)
	if ip == nil {
		b = append(b, 0, 0, 0, 1)
	} else {
		b = append(b, ip...)
	}
	b = append(append(b, c.Username...), 0)
	if ip == nil {
		b = append(append(b, host...), 0)
	}
	if err := writeAll(conn, b); err != nil {
		return err
	}
	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0 || reply[1] != 90 {
		return errors.New("SOCKS_REQUEST_REJECTED")
	}
	return nil
}

type directPackets struct {
	net.Conn
	address []byte
}

func writeDatagram(conn net.Conn, b []byte) error {
	n, err := conn.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}
func (s *directPackets) WritePacket(b []byte) error { return writeDatagram(s.Conn, b) }
func (s *directPackets) ReadPacket() (Datagram, error) {
	b := make([]byte, 65507)
	n, err := s.Read(b)
	return Datagram{Address: s.address, Payload: b[:n]}, err
}

type socksPackets struct {
	net.Conn
	control   net.Conn
	address   []byte
	once      sync.Once
	watchDone chan struct{}
}

func (s *socksPackets) Close() error {
	var err error
	s.once.Do(func() { s.control.Close(); err = s.Conn.Close() })
	<-s.watchDone
	return err
}
func (s *socksPackets) WritePacket(b []byte) error {
	if len(b)+len(s.address)+3 > 65507 {
		return errors.New("UDP_DATAGRAM_LENGTH")
	}
	return writeDatagram(s.Conn, join([]byte{0, 0, 0}, s.address, b))
}
func (s *socksPackets) ReadPacket() (Datagram, error) {
	b := make([]byte, 65507)
	for {
		n, err := s.Read(b)
		if err != nil {
			return Datagram{}, err
		}
		if n < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
			continue
		}
		size, err := addressSize(b[3:n])
		if err != nil || size == 0 {
			continue
		}
		return Datagram{Address: append([]byte(nil), b[3:3+size]...), Payload: append([]byte(nil), b[3+size:n]...)}, nil
	}
}

func dialProxyPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	a, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	if c.Protocol == "block" {
		return nil, errors.New("ROUTE_BLOCKED")
	}
	if c.Protocol == "direct" {
		conn, err := outboundDial(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)), c.ConnectTimeout)
		if err != nil {
			return nil, err
		}
		return &directPackets{Conn: conn, address: a}, nil
	}
	if c.Protocol != "socks5" {
		return nil, errors.New("PROXY_UDP_UNSUPPORTED")
	}
	control, err := proxySocket(ctx, c)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	if err = socks5Auth(control, c); err != nil {
		control.Close()
		return nil, err
	}
	relay, err := socks5Request(control, 3, []byte{1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		control.Close()
		return nil, err
	}
	relayHost, relayPort, err := decodeAddress(relay)
	if err != nil {
		control.Close()
		return nil, err
	}
	if ip := net.ParseIP(relayHost); ip != nil && ip.IsUnspecified() {
		relayHost = c.Server
	}
	conn, err := outboundDial(ctx, "udp", net.JoinHostPort(relayHost, strconv.Itoa(relayPort)), c.ConnectTimeout)
	if err != nil {
		control.Close()
		return nil, err
	}
	s := &socksPackets{Conn: conn, control: control, address: a, watchDone: make(chan struct{})}
	control.SetDeadline(time.Time{})
	go func() { defer close(s.watchDone); var b [1]byte; control.Read(b[:]); conn.Close() }()
	if !stop() && ctx.Err() != nil {
		s.Close()
		return nil, ctx.Err()
	}
	return s, nil
}
