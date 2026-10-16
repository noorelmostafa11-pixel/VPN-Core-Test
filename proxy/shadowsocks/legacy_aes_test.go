package shadowsocks_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
	"testing/iotest"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

var legacyAESVectors = []struct {
	method shadowsocks.CipherType
	key    string
	iv     string
	wire   string
}{
	// NIST SP800-38A F.3.13/15/17, F.4.1/3/5 and F.5.1/3/5, first block.
	// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	{shadowsocks.CipherType_AES_128_CFB, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "3b3fd92eb72dad20333449f8e83cfb4a"},
	{shadowsocks.CipherType_AES_192_CFB, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "000102030405060708090a0b0c0d0e0f", "cdc80d6fddf18cab34c25909c99a4174"},
	{shadowsocks.CipherType_AES_256_CFB, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f", "dc7e84bfda79164b7ecd8486985d3860"},
	{shadowsocks.CipherType_AES_128_CTR, "2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "874d6191b620e3261bef6864990db6ce"},
	{shadowsocks.CipherType_AES_192_CTR, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "1abc932417521ca24f2b0459fe7e6e0b"},
	{shadowsocks.CipherType_AES_256_CTR, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "601ec313775789a5b7a7f504bbf3d228"},
	{shadowsocks.CipherType_AES_128_OFB, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "3b3fd92eb72dad20333449f8e83cfb4a"},
	{shadowsocks.CipherType_AES_192_OFB, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "000102030405060708090a0b0c0d0e0f", "cdc80d6fddf18cab34c25909c99a4174"},
	{shadowsocks.CipherType_AES_256_OFB, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f", "dc7e84bfda79164b7ecd8486985d3860"},
}

func legacyMemory(t *testing.T, method shadowsocks.CipherType) *shadowsocks.MemoryAccount {
	t.Helper()
	account, err := (&shadowsocks.Account{CipherType: method, Password: "test"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return account.(*shadowsocks.MemoryAccount)
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writePiece(t *testing.T, writer buf.Writer, piece []byte) {
	t.Helper()
	b := buf.New()
	b.Write(piece)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
}

func TestForkLegacyAESVectorsAndFragmentation(t *testing.T) {
	plain := unhex(t, "6bc1bee22e409f96e93d7e117393172a")
	for _, vector := range legacyAESVectors {
		t.Run(vector.method.String(), func(t *testing.T) {
			c := legacyMemory(t, vector.method).Cipher
			key, iv, expected := unhex(t, vector.key), unhex(t, vector.iv), unhex(t, vector.wire)
			var wire bytes.Buffer
			writer, err := c.NewEncryptionWriter(key, iv, &wire)
			if err != nil {
				t.Fatal(err)
			}
			writePiece(t, writer, plain[:1])
			writePiece(t, writer, plain[1:])
			if !bytes.Equal(wire.Bytes(), expected) {
				t.Fatal("NIST first-block wire mismatch")
			}
			body := append(append([]byte(nil), plain...), bytes.Repeat([]byte{0, 0xff, 0x5a}, 4001)...)
			for _, piece := range [][]byte{body[16:33], body[33:7000], body[7000:]} {
				writePiece(t, writer, piece)
			}
			reader, err := c.NewDecryptionReader(key, iv, iotest.HalfReader(bytes.NewReader(wire.Bytes())))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
			if err != nil || !bytes.Equal(decoded, body) {
				t.Fatal("fragmented stream state or plaintext mismatch", err)
			}
			packet := buf.New()
			defer packet.Release()
			packet.Write(iv)
			packet.Write(plain)
			if err := c.EncodePacket(key, packet); err != nil || !bytes.Equal(packet.Bytes(), append(append([]byte(nil), iv...), expected...)) {
				t.Fatal("UDP IV or NIST wire mismatch", err)
			}
			if err := c.DecodePacket(key, packet); err != nil || !bytes.Equal(packet.Bytes(), plain) {
				t.Fatal("UDP vector decode mismatch", err)
			}
			if _, err := c.NewEncryptionWriter(key[:len(key)-1], iv, &wire); err == nil {
				t.Fatal("wrong-size key accepted")
			}
			if _, err := c.NewDecryptionReader(key, iv[:15], &wire); err == nil {
				t.Fatal("wrong-size IV accepted")
			}
			for size := range 17 {
				packet.Clear()
				packet.Write(iv[:size])
				if err := c.DecodePacket(key, packet); err == nil {
					t.Fatal("truncated UDP IV accepted", size)
				}
			}
		})
	}
}

func TestForkLegacyAESHeaderOnlyAndUDP(t *testing.T) {
	for _, vector := range legacyAESVectors {
		t.Run(vector.method.String(), func(t *testing.T) {
			user := &protocol.MemoryUser{Account: legacyMemory(t, vector.method)}
			validator := new(shadowsocks.Validator)
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			for _, address := range []net.Address{net.LocalHostIP, net.DomainAddress("example.invalid"), net.ParseAddress("::1")} {
				request := &protocol.RequestHeader{Version: shadowsocks.Version, Command: protocol.RequestCommandTCP, User: user, Address: address, Port: 443}
				var wire bytes.Buffer
				if _, err := shadowsocks.WriteTCPRequest(request, &wire); err != nil {
					t.Fatal(err)
				}
				// No application bytes are written: server-first must not wait for
				// an AEAD-sized prefix, even for a small IPv4 target header.
				header, _, err := shadowsocks.ReadTCPSession(validator, &wire)
				if err != nil || header.Address.String() != address.String() || header.Port != 443 {
					t.Fatal("header-only TCP request rejected", err)
				}
				body := bytes.Repeat([]byte{0, 0x5a, 0xff}, 1266)
				packet, err := shadowsocks.EncodeUDPPacket(request, body)
				if err != nil {
					t.Fatal(err)
				}
				header, payload, err := shadowsocks.DecodeUDPPacket(validator, packet)
				if err != nil || header.Address.String() != address.String() || header.Port != 443 || !bytes.Equal(payload.Bytes(), body) {
					packet.Release()
					t.Fatal("UDP address or payload changed", err)
				}
				packet.Release()
			}
		})
	}
}

func TestForkLegacyAESValidatorIsolation(t *testing.T) {
	aead := &protocol.MemoryUser{Email: "aead@example.invalid", Account: legacyMemory(t, shadowsocks.CipherType_AES_128_GCM)}
	stream := &protocol.MemoryUser{Email: "stream@example.invalid", Account: legacyMemory(t, shadowsocks.CipherType_AES_128_CFB)}
	for _, users := range [][2]*protocol.MemoryUser{{aead, stream}, {stream, aead}, {stream, stream}} {
		validator := new(shadowsocks.Validator)
		if err := validator.Add(users[0]); err != nil {
			t.Fatal(err)
		}
		if err := validator.Add(users[1]); err == nil || validator.GetCount() != 1 {
			t.Fatal("legacy listener isolation changed after rejected user")
		}
		if err := validator.Del(users[0].Email); err != nil {
			t.Fatal(err)
		}
		if err := validator.Add(aead); err != nil {
			t.Fatal("empty listener could not switch to AEAD", err)
		}
	}
	if aead.Account.Equals(stream.Account) || stream.Account.Equals(aead.Account) || !stream.Account.Equals(stream.Account) {
		t.Fatal("same password with different cipher types must not identify the same account")
	}
	validator := new(shadowsocks.Validator)
	if err := validator.Add(aead); err != nil {
		t.Fatal(err)
	}
	second := &protocol.MemoryUser{Account: legacyMemory(t, shadowsocks.CipherType_AES_192_GCM)}
	if err := validator.Add(second); err != nil || validator.GetCount() != 2 {
		t.Fatal("AEAD multi-user support regressed", err)
	}
}

func TestForkCipherValidatorTruncatedInputs(t *testing.T) {
	for _, method := range []shadowsocks.CipherType{shadowsocks.CipherType_AES_128_GCM, shadowsocks.CipherType_AES_192_GCM, shadowsocks.CipherType_AES_256_GCM, shadowsocks.CipherType_AES_128_CFB} {
		validator := new(shadowsocks.Validator)
		account := legacyMemory(t, method)
		if err := validator.Add(&protocol.MemoryUser{Account: account}); err != nil {
			t.Fatal(err)
		}
		minimum := int(account.Cipher.IVSize())
		if account.Cipher.IsAEAD() {
			minimum += 18
		}
		for size := range minimum {
			if _, _, _, _, err := validator.Get(make([]byte, size), protocol.RequestCommandTCP); err == nil {
				t.Fatal("short validation prefix accepted", method, size)
			}
		}
		for size := range int(account.Cipher.IVSize() + 1) {
			packet := buf.New()
			packet.Extend(int32(size))
			_, _, err := shadowsocks.DecodeUDPPacket(validator, packet)
			packet.Release()
			if err == nil {
				t.Fatal("truncated UDP packet accepted", method, size)
			}
		}
	}
}
