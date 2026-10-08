package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DNS HTTPS/SVCB records (RFC 9460) carry the ECHConfigList in svcparam 5.
// Queries use the resolver explicitly supplied by the node configuration.
func dnsQuestion(domain string, id uint16) ([]byte, error) {
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out, id)
	out[2] = 1
	out[5] = 1
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("DNS label")
		}
		for _, c := range []byte(label) {
			if c <= 32 || c >= 127 {
				return nil, errors.New("DNS ASCII name")
			}
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	if len(out) > 266 {
		return nil, errors.New("DNS name length")
	}
	return append(out, 0, 0, 65, 0, 1), nil
}
func dnsNameEnd(data []byte, p int) (int, error) {
	for count := 0; count < 128; count++ {
		if p >= len(data) {
			break
		}
		size := int(data[p])
		p++
		if size == 0 {
			return p, nil
		}
		if size&0xc0 == 0xc0 {
			if p >= len(data) {
				break
			}
			return p + 1, nil
		}
		if size > 63 || p+size > len(data) {
			break
		}
		p += size
	}
	return 0, errors.New("DNS name framing")
}
func echAnswer(data []byte, id uint16) ([]byte, error) {
	if len(data) < 12 || len(data) > 65535 || binary.BigEndian.Uint16(data) != id || data[2]&0x80 == 0 || data[3]&15 != 0 {
		return nil, errors.New("DNS response")
	}
	questions := int(binary.BigEndian.Uint16(data[4:6]))
	answers := int(binary.BigEndian.Uint16(data[6:8]))
	if questions > 1 || answers > 256 {
		return nil, errors.New("DNS count limit")
	}
	p := 12
	for i := 0; i < questions; i++ {
		var err error
		p, err = dnsNameEnd(data, p)
		if err != nil || p+4 > len(data) {
			return nil, errors.New("DNS question framing")
		}
		p += 4
	}
	for i := 0; i < answers; i++ {
		var err error
		p, err = dnsNameEnd(data, p)
		if err != nil || p+10 > len(data) {
			return nil, errors.New("DNS resource framing")
		}
		kind := binary.BigEndian.Uint16(data[p : p+2])
		size := int(binary.BigEndian.Uint16(data[p+8 : p+10]))
		p += 10
		end := p + size
		if end > len(data) {
			return nil, errors.New("DNS resource length")
		}
		if kind == 65 && size >= 3 {
			q, err := dnsNameEnd(data, p+2)
			if err != nil || q > end {
				return nil, errors.New("HTTPS target framing")
			}
			last := -1
			for q < end {
				if q+4 > end {
					return nil, errors.New("HTTPS parameter framing")
				}
				key := int(binary.BigEndian.Uint16(data[q : q+2]))
				n := int(binary.BigEndian.Uint16(data[q+2 : q+4]))
				q += 4
				if key <= last || q+n > end {
					return nil, errors.New("HTTPS parameter order/length")
				}
				last = key
				if key == 5 {
					if n < 6 {
						return nil, errors.New("ECH parameter length")
					}
					return append([]byte(nil), data[q:q+n]...), nil
				}
				q += n
			}
		}
		p = end
	}
	return nil, providerError(333)
}
func resolveECH(ctx context.Context, text, serverName string, roots *x509.CertPool) ([]byte, error) {
	domain, endpoint := serverName, text
	if split := strings.Index(text, "+"); split >= 0 {
		domain, endpoint = text[:split], text[split+1:]
	} else if fields := strings.Fields(text); len(fields) == 2 {
		domain, endpoint = fields[0], fields[1]
	}
	if !strings.Contains(endpoint, "://") {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := encoding.DecodeString(text); err == nil && len(b) >= 6 && int(binary.BigEndian.Uint16(b)) == len(b)-2 {
				return b, nil
			}
		}
		return nil, providerError(330)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return nil, providerError(331)
	}
	id := uint16(0)
	if parsed.Scheme != "https" {
		var random [2]byte
		if _, err = rand.Read(random[:]); err != nil {
			return nil, echLookupError(err)
		}
		id = binary.BigEndian.Uint16(random[:])
	}
	query, err := dnsQuestion(domain, id)
	if err != nil {
		return nil, providerError(331)
	}
	var response []byte
	switch parsed.Scheme {
	case "https":
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return outboundDial(ctx, network, address, 10*time.Second)
			}}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(query))
		if err != nil {
			return nil, echLookupError(err)
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("ECH resolver redirect") }}
		reply, err := client.Do(request)
		if err != nil {
			return nil, echLookupError(err)
		}
		defer reply.Body.Close()
		if reply.StatusCode != 200 {
			return nil, providerError(335)
		}
		response, err = io.ReadAll(io.LimitReader(reply.Body, 65536))
		if err != nil {
			return nil, echLookupError(err)
		}
	case "udp", "tcp", "tls":
		port := parsed.Port()
		if port == "" {
			port = "53"
			if parsed.Scheme == "tls" {
				port = "853"
			}
		}
		address := net.JoinHostPort(parsed.Hostname(), port)
		var conn net.Conn
		if parsed.Scheme == "tls" {
			conn, err = outboundDial(ctx, "tcp", address, 10*time.Second)
			if err == nil {
				secure := tls.Client(conn, &tls.Config{ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: roots})
				handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
				err = secure.HandshakeContext(handshake)
				cancel()
				if err != nil {
					_ = conn.Close()
				} else {
					conn = secure
				}
			}
		} else {
			conn, err = outboundDial(ctx, parsed.Scheme, address, 10*time.Second)
		}
		if err != nil {
			return nil, echLookupError(err)
		}
		defer conn.Close()
		deadline := time.Now().Add(10 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		if parsed.Scheme == "udp" {
			if _, err = conn.Write(query); err != nil {
				return nil, echLookupError(err)
			}
			response = make([]byte, 65535)
			n, err := conn.Read(response)
			if err != nil {
				return nil, echLookupError(err)
			}
			response = response[:n]
		} else {
			frame := []byte{byte(len(query) >> 8), byte(len(query))}
			frame = append(frame, query...)
			for len(frame) > 0 {
				n, err := conn.Write(frame)
				if err != nil {
					return nil, echLookupError(err)
				}
				frame = frame[n:]
			}
			var length [2]byte
			if _, err = io.ReadFull(conn, length[:]); err != nil {
				return nil, echLookupError(err)
			}
			response = make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err = io.ReadFull(conn, response); err != nil {
				return nil, echLookupError(err)
			}
		}
	default:
		return nil, providerError(331)
	}
	config, err := echAnswer(response, id)
	if err != nil {
		var pe providerError
		if errors.As(err, &pe) {
			return nil, pe
		}
		return nil, providerError(335)
	}
	return config, nil
}
