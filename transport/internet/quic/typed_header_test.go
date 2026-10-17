package quic

import (
	"bytes"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	headerdns "github.com/xtls/xray-core/transport/internet/headers/dns"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Values are literal pre-removal protobuf payloads, not marshaled by the new
// header schemas. Historical SRTP/uTP configuration fields were ignored by
// their constructors, so non-default values must not change the wire prefix.
var historicalHeaders = []struct {
	kind, name, value, prefix string
}{
	{"none", "noop.Config", "", ""},
	{"srtp", "srtp.Config", "080110011801200728013002", "b5e80305"},
	{"utp", "utp.Config", "087f", "33440100"},
	{"dtls", "tls.PacketConfig", "", "17fefd33440000000000000011"},
	{"wechat", "wechat.VideoConfig", "", "a1080102030500101118302230"},
	{"wireguard", "wireguard.WireguardConfig", "", "04000000"},
	{"dns", "dns.Config", "0a0b6578616d706c652e636f6d", "030501000001000000000000076578616d706c6503636f6d0000010001"},
}

func TestForkLegacyQUICTypedHeaderValidation(t *testing.T) {
	for _, fixture := range historicalHeaders {
		// Old proto3 messages ignored structurally valid unknown fields.
		config := historicalConfig(t, fixture.name, fixture.value)
		config.Header.Value = protowire.AppendTag(config.Header.Value, 100, protowire.BytesType)
		config.Header.Value = protowire.AppendBytes(config.Header.Value, []byte("unknown but valid"))
		if err := config.Validate(); err != nil {
			t.Fatal("unknown historical protobuf field changed known header", err)
		}
	}
	var nested []byte
	for range 17 {
		nested = protowire.AppendTag(nested, 100, protowire.StartGroupType)
	}
	for range 17 {
		nested = protowire.AppendTag(nested, 100, protowire.EndGroupType)
	}
	if err := (&Config{Header: &serial.TypedMessage{Type: "xray.transport.internet.headers.noop.Config", Value: nested[2 : len(nested)-2]}}).Validate(); err != nil {
		t.Fatal("valid bounded unknown groups rejected", err)
	}
	for _, config := range []*Config{
		historicalConfig(t, "noop.ConnectionConfig", ""),
		historicalConfig(t, "tls.Config", ""),
		historicalConfig(t, "dtls.PacketConfig", ""),
		historicalConfig(t, "srtp.Config", "80"),
		historicalConfig(t, "dns.Config", "0a02ff"),
		historicalConfig(t, "dns.Config", "0a01ff"),
		{Header: &serial.TypedMessage{}},
		{Header: &serial.TypedMessage{Type: "xray.transport.internet.headers.noop.Config", Value: make([]byte, 4097)}},
		{Header: &serial.TypedMessage{Type: "xray.transport.internet.headers.noop.Config", Value: nested}},
		{Header: &serial.TypedMessage{Type: "xray.transport.internet.headers.noop.Config"}, HeaderType: "none"},
		{Header: &serial.TypedMessage{Type: "xray.transport.internet.headers.dns.Config"}, HeaderDomain: "example.com"},
	} {
		config.Key = "do-not-echo-secret"
		err := config.Validate()
		if err == nil || strings.Contains(err.Error(), config.Key) {
			t.Fatal("invalid/mixed header accepted or secret leaked", err)
		}
	}
}

func TestForkLegacyQUICTypedDNSHistoricalSemantics(t *testing.T) {
	for _, fixture := range []struct{ domain, wire string }{
		{"", "0000"},
		{".", "000000"},
		{"example.com", "076578616d706c6503636f6d00"},
		{"example.com.", "076578616d706c6503636f6d0000"},
		{"a..b", "016100016200"},
		{`a\.b.example`, "03612e62076578616d706c6500"},
		{`a\032b.example`, "056130333262076578616d706c6500"},
	} {
		t.Run(fixture.domain, func(t *testing.T) {
			config := &Config{Header: serial.ToTypedMessage(&headerdns.Config{Domain: fixture.domain})}
			packet, err := wrapPacket(nil, config)
			if err != nil {
				t.Fatal(err)
			}
			packet.header.sequence = 0
			want := "000101000001000000000000" + fixture.wire + "00010001"
			if got := hex.EncodeToString(packet.header.appendTo(nil)); got != want {
				t.Fatal("typed DNS changed historical domain encoding", got, want)
			}
		})
	}
	// 256 bytes including the terminal zero fit. A 256-byte encoded name
	// without that zero used to panic on buf[:257]; reject it before slicing.
	for _, length := range []int{61, 62, 63, 64} {
		domain := strings.Repeat(strings.Repeat("x", 63)+".", 3) + strings.Repeat("y", length)
		config := &Config{Header: serial.ToTypedMessage(&headerdns.Config{Domain: domain})}
		err := config.Validate()
		if (err == nil) != (length <= 62) {
			t.Fatal("historical DNS boundary was not enforced", length, err)
		}
	}
	// A duplicate singular protobuf field keeps the last value, as before.
	config := historicalConfig(t, "dns.Config", "0a01610a0162")
	header, err := config.packetHeader()
	if err != nil || hex.EncodeToString(header.dns[12:]) != "01620000010001" {
		t.Fatal("duplicate DNS field lost protobuf semantics", err)
	}
}

func TestForkLegacyQUICTypedHeaderConcurrentReadOnly(t *testing.T) {
	for _, fixture := range historicalHeaders {
		config := historicalConfig(t, fixture.name, fixture.value)
		before := proto.Clone(config)
		var workers sync.WaitGroup
		for range 16 {
			workers.Go(func() {
				for range 16 {
					if err := config.Validate(); err != nil {
						t.Error(err)
						return
					}
				}
			})
		}
		workers.Wait()
		if !proto.Equal(config, before) {
			t.Fatal("shared typed header was mutated")
		}
	}
}

func FuzzForkLegacyQUICTypedHeader(f *testing.F) {
	for _, fixture := range historicalHeaders {
		value, _ := hex.DecodeString(fixture.value)
		f.Add("xray.transport.internet.headers."+fixture.name, value)
	}
	f.Add("xray.transport.internet.headers.dns.Config", []byte{0x0a, 0x01, 0xff})
	f.Fuzz(func(t *testing.T, name string, value []byte) {
		if len(name) > 256 || len(value) > 8192 {
			return
		}
		config := &Config{Header: &serial.TypedMessage{Type: name, Value: value}}
		before := proto.Clone(config)
		err := config.Validate()
		if err == nil {
			header, buildErr := config.packetHeader()
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			packet := header.appendTo(nil)
			if len(packet) != header.size() || len(packet) > 272 {
				t.Fatal("unbounded or inconsistent header serialization")
			}
		}
		if !proto.Equal(config, before) {
			t.Fatal("header validation/serialization mutated input")
		}
	})
}

func historicalConfig(t *testing.T, name, value string) *Config {
	t.Helper()
	payload, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return &Config{Key: "password", Header: &serial.TypedMessage{Type: "xray.transport.internet.headers." + name, Value: payload}}
}

func TestForkLegacyQUICTypedHeaderGoldens(t *testing.T) {
	for _, fixture := range historicalHeaders {
		t.Run(fixture.name, func(t *testing.T) {
			config := historicalConfig(t, fixture.name, fixture.value)
			before := proto.Clone(config)
			wire, err := proto.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Config
			if err := proto.Unmarshal(wire, &decoded); err != nil {
				t.Fatal(err)
			}
			packet, err := wrapPacket(nil, &decoded)
			if err != nil {
				t.Fatal("historical typed header rejected", err)
			}
			packet.header.id, packet.header.sequence = 0x3344, 0x01020304
			if fixture.kind == "dtls" {
				packet.header.sequence = 0
			}
			if got := hex.EncodeToString(packet.header.appendTo(nil)); got != fixture.prefix {
				t.Fatal("historical wire prefix changed", got, fixture.prefix)
			}
			after, err := proto.Marshal(&decoded)
			if err != nil || !proto.Equal(config, before) || !bytes.Equal(wire, after) {
				t.Fatal("header conversion mutated caller protobuf", err)
			}
		})
	}
}
