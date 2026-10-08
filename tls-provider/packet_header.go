// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Project-owned encoding of the legacy mKCP packet-header wire formats.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
)

type packetHeader struct {
	kind       string
	sequence   uint32
	id         uint16
	dtlsLength uint16
	dns        []byte
}

func newPacketHeader(kind, domain string) (*packetHeader, error) {
	h := &packetHeader{kind: strings.ToLower(strings.TrimSpace(kind))}
	if h.kind == "wechat-video" {
		h.kind = "wechat"
	}
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	h.sequence, h.id = binary.BigEndian.Uint32(random[:4]), binary.BigEndian.Uint16(random[4:])
	if h.kind == "dtls" {
		h.sequence = 0
		h.dtlsLength = 17
	}
	switch h.kind {
	case "", "none", "srtp", "utp", "dtls", "wechat", "wireguard":
	case "dns":
		if domain == "" {
			domain = "www.example.com"
		}
		h.dns = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, errors.New("packet header DNS name")
			}
			h.dns = append(h.dns, byte(len(label)))
			h.dns = append(h.dns, label...)
		}
		h.dns = append(h.dns, 0, 0, 1, 0, 1)
		if len(h.dns) > 271 {
			return nil, errors.New("packet header DNS name length")
		}
	default:
		return nil, errors.New("packet header name")
	}
	return h, nil
}

func (h *packetHeader) size() int {
	switch h.kind {
	case "srtp", "utp", "wireguard":
		return 4
	case "dtls", "wechat":
		return 13
	case "dns":
		return len(h.dns)
	default:
		return 0
	}
}

func (h *packetHeader) wrap(payload []byte) []byte {
	n := h.size()
	if n == 0 {
		return payload
	}
	packet := make([]byte, n+len(payload))
	copy(packet[n:], payload)
	h.sequence++
	switch h.kind {
	case "srtp":
		packet[0], packet[1] = 0xb5, 0xe8
		binary.BigEndian.PutUint16(packet[2:], uint16(h.sequence))
	case "utp":
		binary.BigEndian.PutUint16(packet, h.id)
		packet[2] = 1
	case "wireguard":
		packet[0] = 4
	case "wechat":
		copy(packet, []byte{0xa1, 8, 0, 0, 0, 0, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30})
		binary.BigEndian.PutUint32(packet[2:], h.sequence)
	case "dtls":
		packet[0], packet[1], packet[2] = 23, 254, 253
		binary.BigEndian.PutUint16(packet[3:], h.id)
		binary.BigEndian.PutUint32(packet[7:], h.sequence-1)
		// Legacy obfuscation uses a cosmetic length, not a DTLS handshake.
		binary.BigEndian.PutUint16(packet[11:], h.dtlsLength)
		h.dtlsLength += 17
		if h.dtlsLength > 100 {
			h.dtlsLength -= 50
		}
	case "dns":
		copy(packet, h.dns)
		binary.BigEndian.PutUint16(packet, uint16(h.sequence))
	}
	return packet
}

func (h *packetHeader) unwrap(packet []byte) ([]byte, error) {
	n := h.size()
	if len(packet) < n {
		return nil, errors.New("truncated packet header")
	}
	// The peer's sequence, transaction ID and cosmetic length are independent.
	return packet[n:], nil
}
