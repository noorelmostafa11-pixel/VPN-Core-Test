package quic

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
)

func TestForkLegacyQUICHeaderGoldens(t *testing.T) {
	for kind, want := range map[string]string{"none": "", "srtp": "b5e80305", "utp": "33440100", "wireguard": "04000000", "wechat": "a1080102030500101118302230", "wechat-video": "a1080102030500101118302230", "dtls": "17fefd33440000000000000011", "dns": "03050100000100000000000003777777076578616d706c6503636f6d0000010001"} {
		header, err := newHeader(kind, "")
		if err != nil {
			t.Fatal(err)
		}
		header.id = 0x3344
		header.sequence = 0x01020304
		if kind == "dtls" {
			header.sequence = 0
		}
		if got := hex.EncodeToString(header.appendTo(nil)); got != want {
			t.Fatal("header wire mismatch", kind, got, want)
		}
	}
	for _, domain := range []string{".", "a..b", strings.Repeat("x", 64) + ".example", strings.Repeat("x", 255)} {
		if _, err := newHeader("dns", domain); err == nil {
			t.Fatal("invalid DNS camouflage accepted")
		}
	}
}

func TestForkLegacyQUICPacketIndependentOracle(t *testing.T) {
	for _, security := range ciphers {
		for _, header := range headers {
			t.Run(security.String()+"/"+header, func(t *testing.T) {
				sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer receiver.Close()
				sender.SetDeadline(time.Now().Add(3 * time.Second))
				receiver.SetDeadline(time.Now().Add(3 * time.Second))
				config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: security}, HeaderType: header}
				wrapped, err := wrapPacket(sender, config)
				if err != nil {
					t.Fatal(err)
				}
				peer := oracle(t, receiver, security, header)
				for _, size := range []int{1, 32, 1400, 3800} {
					payload := bytes.Repeat([]byte{0x37}, size)
					if n, err := wrapped.WriteTo(payload, receiver.LocalAddr()); err != nil || n != size {
						t.Fatal("payload byte accounting wrong", n, err)
					}
					wire := make([]byte, 65536)
					n, _, err := receiver.ReadFrom(wire)
					if err != nil {
						t.Fatal(err)
					}
					decoded := wire[len(peer.prefix):n]
					if peer.auth != nil {
						nonce := peer.auth.NonceSize()
						decoded, err = peer.auth.Open(nil, decoded[:nonce], decoded[nonce:], nil)
					}
					if err != nil || !bytes.Equal(decoded, payload) {
						t.Fatal("independent KDF/AEAD decode mismatch", err)
					}
					if n, err := peer.WriteTo(payload, sender.LocalAddr()); err != nil || n != size {
						t.Fatal(n, err)
					}
					got := make([]byte, size)
					n, _, err = wrapped.ReadFrom(got)
					if err != nil || n != size || !bytes.Equal(got, payload) {
						t.Fatal("independent reverse packet mismatch", n, err)
					}
				}
			})
		}
	}
}

func TestForkLegacyQUICMalformedAndBoundedPackets(t *testing.T) {
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender.SetDeadline(time.Now().Add(3 * time.Second))
	receiver.SetDeadline(time.Now().Add(3 * time.Second))
	config := &Config{Key: "password", Security: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}, HeaderType: "dtls"}
	wrapped, err := wrapPacket(receiver, config)
	if err != nil {
		t.Fatal(err)
	}
	peer := oracle(t, sender, config.Security.Type, "dtls")
	for _, invalid := range [][]byte{{}, make([]byte, 12), make([]byte, 13), make([]byte, 40), make([]byte, 60)} {
		if _, err := sender.WriteTo(invalid, receiver.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	// Valid but too big for the caller's destination must not be truncated.
	peer.WriteTo(bytes.Repeat([]byte{0xff}, 100), receiver.LocalAddr())
	peer.WriteTo([]byte("exact"), receiver.LocalAddr())
	got := make([]byte, 5)
	n, _, err := wrapped.ReadFrom(got)
	if err != nil || n != 5 || string(got) != "exact" {
		t.Fatal("malformed/oversized frame was not discarded", n, err)
	}
	if _, err := wrapped.WriteTo(make([]byte, 65508), sender.LocalAddr()); err == nil {
		t.Fatal("oversized UDP write accepted")
	}
	for _, bad := range []*Config{{Security: &protocol.SecurityConfig{Type: protocol.SecurityType_UNKNOWN}}, {Key: strings.Repeat("x", 1025)}, {HeaderType: "unknown"}, {Header: &serial.TypedMessage{Type: "historical.Config"}}} {
		if bad.Validate() == nil {
			t.Fatal("invalid protobuf bypassed guard")
		}
	}
}
