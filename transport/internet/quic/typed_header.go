package quic

import (
	"errors"

	headerdns "github.com/xtls/xray-core/transport/internet/headers/dns"
	"github.com/xtls/xray-core/transport/internet/headers/noop"
	"github.com/xtls/xray-core/transport/internet/headers/srtp"
	headertls "github.com/xtls/xray-core/transport/internet/headers/tls"
	"github.com/xtls/xray-core/transport/internet/headers/utp"
	"github.com/xtls/xray-core/transport/internet/headers/wechat"
	"github.com/xtls/xray-core/transport/internet/headers/wireguard"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// packetHeader accepts historical field 3 OR the added JSON/URI selectors, never
// both. Decode only packet header types: generic TypedMessage construction could
// otherwise interpret an unrelated transport/security configuration here.
func (c *Config) packetHeader() (*packetHeader, error) {
	if c.Header == nil {
		return newHeader(c.HeaderType, c.HeaderDomain)
	}
	if c.HeaderType != "" || c.HeaderDomain != "" {
		return nil, errors.New("legacy QUIC: mixed typed and named packet headers")
	}
	if len(c.Header.Value) > 4096 {
		return nil, errors.New("legacy QUIC: oversized typed packet header")
	}
	var message proto.Message
	var kind string
	switch c.Header.Type {
	case "xray.transport.internet.headers.noop.Config":
		message, kind = new(noop.Config), "none"
	case "xray.transport.internet.headers.srtp.Config":
		message, kind = new(srtp.Config), "srtp"
	case "xray.transport.internet.headers.utp.Config":
		message, kind = new(utp.Config), "utp"
	case "xray.transport.internet.headers.tls.PacketConfig":
		message, kind = new(headertls.PacketConfig), "dtls"
	case "xray.transport.internet.headers.wechat.VideoConfig":
		message, kind = new(wechat.VideoConfig), "wechat"
	case "xray.transport.internet.headers.wireguard.WireguardConfig":
		message, kind = new(wireguard.WireguardConfig), "wireguard"
	case "xray.transport.internet.headers.dns.Config":
		message, kind = new(headerdns.Config), "dns"
	default:
		return nil, errors.New("legacy QUIC: unsupported typed packet header")
	}
	if !validTypedHeaderWire(c.Header.Value) {
		return nil, errors.New("legacy QUIC: malformed or deeply nested typed packet header")
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true, RecursionLimit: 16}).Unmarshal(c.Header.Value, message); err != nil {
		return nil, errors.New("legacy QUIC: malformed typed packet header")
	}
	header, err := newHeader(kind, "")
	if err != nil {
		return nil, err
	}
	// Historical SRTP/uTP constructors ignored their schema fields. Retain that
	// behavior, not a new interpretation of their version/payload/flag values.
	if dns, ok := message.(*headerdns.Config); ok {
		domain, err := historicalDNSDomain(dns.Domain)
		if err != nil {
			return nil, err
		}
		header.dns = append([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, domain...)
		header.dns = append(header.dns, 0, 1, 0, 1)
	}
	return header, nil
}

// All supported schemas are flat. Protobuf's RecursionLimit does not constrain
// unknown wire groups, so bound those iteratively before generated decoding.
// Ordinary valid unknown fields/groups remain ignored, as in the old schemas.
func validTypedHeaderWire(wire []byte) bool {
	var groups [16]protowire.Number
	depth := 0
	for len(wire) != 0 {
		number, kind, n := protowire.ConsumeTag(wire)
		if n < 0 || number > protowire.MaxValidNumber {
			return false
		}
		wire = wire[n:]
		switch kind {
		case protowire.StartGroupType:
			if depth == len(groups) {
				return false
			}
			groups[depth] = number
			depth++
		case protowire.EndGroupType:
			if depth == 0 || groups[depth-1] != number {
				return false
			}
			depth--
		default:
			n = protowire.ConsumeFieldValue(number, kind, wire)
			if n < 0 {
				return false
			}
			wire = wire[n:]
		}
	}
	return depth == 0
}

// historicalDNSDomain retains ab3c00e9 headers/dns/packDomainName semantics,
// including empty/root, trailing dots and escaped characters. It is isolated
// from the new JSON/URI DNS selector, which has different default/validation
// semantics. Reserve the final zero to reject the old 256-byte buffer overflow
// instead of panicking. The source remains attributed to Xray's miekg/dns port.
func historicalDNSDomain(domain string) ([]byte, error) {
	s := domain + "."
	var buffer [256]byte
	off, begin, length := 0, 0, len(s)
	var escaped []byte
	for i := 0; i < length; i++ {
		var ch byte
		if escaped == nil {
			ch = s[i]
		} else {
			ch = escaped[i]
		}
		switch ch {
		case '\\':
			if escaped == nil {
				escaped = []byte(s)
			}
			copy(escaped[i:length-1], escaped[i+1:])
			length--
		case '.':
			labelLength := i - begin
			if labelLength >= 64 || off+1+labelLength >= len(buffer) {
				return nil, errors.New("legacy QUIC: invalid historical DNS camouflage domain")
			}
			buffer[off] = byte(labelLength)
			if escaped == nil {
				copy(buffer[off+1:], s[begin:i])
			} else {
				copy(buffer[off+1:], escaped[begin:i])
			}
			off += 1 + labelLength
			begin = i + 1
		}
	}
	return buffer[:off+1], nil
}
