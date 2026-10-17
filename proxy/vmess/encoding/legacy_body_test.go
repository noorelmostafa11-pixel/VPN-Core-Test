package encoding

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"testing"
	"testing/iotest"

	"github.com/xtls/xray-core/common/bitmask"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
)

var (
	legacyKey = bytes.Repeat([]byte{0x12}, 16)
	legacyIV  = bytes.Repeat([]byte{0x34}, 16)
)

func legacyBodyRequest(security protocol.SecurityType, options bitmask.Byte, command protocol.RequestCommand) *protocol.RequestHeader {
	return &protocol.RequestHeader{Security: security, Option: options, Command: command}
}

func writeLegacyBody(t *testing.T, w buf.Writer, data []byte) {
	t.Helper()
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, data)); err != nil {
		t.Fatal(err)
	}
}

func TestForkVMessLegacyBodyMatrix(t *testing.T) {
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE} {
		for _, option := range []bitmask.Byte{1, 5, 13} {
			for _, command := range []protocol.RequestCommand{protocol.RequestCommandTCP, protocol.RequestCommandUDP, protocol.RequestCommandMux} {
				t.Run(fmt.Sprintf("%v/%d/%d", security, option, command), func(t *testing.T) {
					request := legacyBodyRequest(security, option, command)
					var wire bytes.Buffer
					writer, err := newLegacyBodyWriter(request, legacyKey, legacyIV, &wire)
					if err != nil {
						t.Fatal(err)
					}
					var packets [][]byte
					if command == protocol.RequestCommandUDP {
						for _, size := range []int{1, 32, 1400, 3800} {
							packets = append(packets, bytes.Repeat([]byte{byte(size)}, size))
						}
					} else {
						packets = [][]byte{bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)}
					}
					for _, packet := range packets {
						writeLegacyBody(t, writer, packet)
					}
					if err := writer.WriteMultiBuffer(nil); err != nil {
						t.Fatal(err)
					}
					reader, err := newLegacyBodyReader(request, legacyKey, legacyIV, iotest.HalfReader(bytes.NewReader(wire.Bytes())))
					if err != nil {
						t.Fatal(err)
					}
					if command != protocol.RequestCommandUDP {
						got, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
						if err != nil || !bytes.Equal(got, packets[0]) {
							t.Fatal("fragmented stream mismatch", err)
						}
					} else {
						var got [][]byte
						for {
							mb, err := reader.ReadMultiBuffer()
							for _, b := range mb {
								got = append(got, append([]byte(nil), b.Bytes()...))
							}
							buf.ReleaseMulti(mb)
							if err == io.EOF {
								break
							}
							if err != nil {
								t.Fatal(err)
							}
						}
						if len(got) != len(packets) {
							t.Fatal("UDP packet boundaries changed", len(got))
						}
						for i := range got {
							if !bytes.Equal(got[i], packets[i]) {
								t.Fatal("UDP payload changed", i)
							}
						}
					}
				})
			}
		}
	}
}

func TestForkVMessLegacyBodyGoldenAndRaw(t *testing.T) {
	plain := []byte("independent golden payload")
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE} {
		var wire bytes.Buffer
		writer, err := newLegacyBodyWriter(legacyBodyRequest(security, 1, protocol.RequestCommandTCP), legacyKey, legacyIV, &wire)
		if err != nil {
			t.Fatal(err)
		}
		writeLegacyBody(t, writer, plain)
		payload := append([]byte(nil), plain...)
		if security == protocol.SecurityType_AES128_CFB {
			sum := fnv.New32a()
			sum.Write(plain)
			payload = append(sum.Sum(nil), payload...)
		}
		want := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(want, uint16(len(payload)))
		copy(want[2:], payload)
		if security == protocol.SecurityType_AES128_CFB {
			block, _ := aes.NewCipher(legacyKey)
			cipher.NewCFBEncrypter(block, legacyIV).XORKeyStream(want, want)
		}
		if !bytes.Equal(wire.Bytes(), want) {
			t.Fatal("independent wire encoding mismatch", security)
		}
	}
	request := legacyBodyRequest(protocol.SecurityType_NONE, 0, protocol.RequestCommandTCP)
	var raw bytes.Buffer
	writer, err := newLegacyBodyWriter(request, legacyKey, legacyIV, &raw)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyBody(t, writer, plain[:1])
	writeLegacyBody(t, writer, plain[1:])
	if !bytes.Equal(raw.Bytes(), plain) {
		t.Fatal("zero/raw NONE emitted length or checksum bytes")
	}
	reader, err := newLegacyBodyReader(request, legacyKey, legacyIV, iotest.OneByteReader(&raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("raw NONE read mismatch", err)
	}
}

func TestForkVMessLegacyBodyMalformed(t *testing.T) {
	for size := range 4 {
		if _, err := (legacyBodyAuth{checksum: true}).Open(nil, make([]byte, size)); err == nil {
			t.Fatal("short checksum accepted")
		}
	}
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE} {
		request := legacyBodyRequest(security, 13, protocol.RequestCommandTCP)
		shake := NewShakeSizeParser(legacyIV)
		pad := shake.NextPaddingLen()
		minimum := pad
		if security == protocol.SecurityType_AES128_CFB {
			minimum += 4
		}
		if minimum == 0 {
			t.Fatal("padding fixture must inject an actual underflow")
		}
		wire := shake.Encode(minimum-1, make([]byte, 2))
		if security == protocol.SecurityType_AES128_CFB {
			block, _ := aes.NewCipher(legacyKey)
			cipher.NewCFBEncrypter(block, legacyIV).XORKeyStream(wire, wire)
		}
		reader, err := newLegacyBodyReader(request, legacyKey, legacyIV, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if mb, err := reader.ReadMultiBuffer(); err == nil {
			buf.ReleaseMulti(mb)
			t.Fatal("checksum/padding underflow accepted")
		}
		for _, options := range []bitmask.Byte{8, 17} {
			if _, err := newLegacyBodyWriter(legacyBodyRequest(security, options, protocol.RequestCommandTCP), legacyKey, legacyIV, io.Discard); err == nil {
				t.Fatal("invalid legacy options accepted")
			}
		}
	}
	for _, wire := range [][]byte{{0, 3, 0, 0, 0}, {0, 5, 0, 0, 0, 0, 1}, {0}, {0, 5, 0}} {
		block, _ := aes.NewCipher(legacyKey)
		cipher.NewCFBEncrypter(block, legacyIV).XORKeyStream(wire, wire)
		reader, err := newLegacyBodyReader(legacyBodyRequest(protocol.SecurityType_AES128_CFB, 1, protocol.RequestCommandTCP), legacyKey, legacyIV, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if mb, err := reader.ReadMultiBuffer(); err == nil {
			buf.ReleaseMulti(mb)
			t.Fatal("corrupt or truncated CFB frame accepted")
		}
	}
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE} {
		for _, option := range []bitmask.Byte{1, 13} {
			var wire bytes.Buffer
			writer, err := newLegacyBodyWriter(legacyBodyRequest(security, option, protocol.RequestCommandUDP), legacyKey, legacyIV, &wire)
			if err != nil {
				t.Fatal(err)
			}
			limit := writer.(legacyPacketWriter).limit
			good, bad := buf.New(), buf.New()
			good.Write([]byte("good"))
			bad.Extend(limit + 1)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{good, bad}); err == nil || wire.Len() != 0 {
				t.Fatal("oversize datagram silently dropped or partial batch written", err)
			}
		}
	}
}

func TestForkVMessLegacyHeaderOptIn(t *testing.T) {
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE} {
		for _, allow := range []bool{false, true} {
			account, err := (&vmess.Account{Id: "00000000-0000-4000-8000-000000000001", LegacyCompatibility: true, AllowLegacyBody: allow}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			user := &protocol.MemoryUser{Account: account}
			validator := vmess.NewTimedUserValidator()
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			history := NewSessionHistory()
			t.Cleanup(func() { history.Close() })
			client := NewClientSession(context.Background(), 0)
			request := &protocol.RequestHeader{Version: 1, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 443, Security: security, Option: 1, User: user}
			var wire bytes.Buffer
			if err := client.EncodeRequestHeader(request, &wire); err != nil {
				t.Fatal(err)
			}
			copyWire := append([]byte(nil), wire.Bytes()...)
			server := NewServerSession(validator, history)
			decoded, err := server.DecodeRequestHeader(&wire, false)
			if (err == nil) != allow {
				t.Fatal("inbound body policy was not enforced", allow, err)
			}
			if !allow {
				continue
			}
			if decoded.Security != security {
				t.Fatal("decoded body security substituted")
			}
			writer, err := client.EncodeRequestBody(request, &wire)
			if err != nil {
				t.Fatal(err)
			}
			writeLegacyBody(t, writer, []byte("request"))
			writer.WriteMultiBuffer(nil)
			reader, err := server.DecodeRequestBody(decoded, &wire)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
			if err != nil || string(body) != "request" {
				t.Fatal("request session body mismatch", err)
			}
			wire.Reset()
			server.EncodeResponseHeader(&protocol.ResponseHeader{}, &wire)
			writer, err = server.EncodeResponseBody(decoded, &wire)
			if err != nil {
				t.Fatal(err)
			}
			writeLegacyBody(t, writer, []byte("server-first"))
			writer.WriteMultiBuffer(nil)
			if _, err := client.DecodeResponseHeader(&wire); err != nil {
				t.Fatal(err)
			}
			reader, err = client.DecodeResponseBody(request, &wire)
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(&buf.BufferedReader{Reader: reader})
			if err != nil || string(body) != "server-first" {
				t.Fatal("response session body mismatch", err)
			}
			if _, err := server.DecodeRequestHeader(bytes.NewReader(copyWire), false); err == nil {
				t.Fatal("AEAD replay accepted")
			}
		}
	}
}
