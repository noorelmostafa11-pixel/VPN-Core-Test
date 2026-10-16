package shadowsocks_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestForkAES192GCMKnownVectorAndAuthentication(t *testing.T) {
	raw := &shadowsocks.Account{CipherType: shadowsocks.CipherType_AES_192_GCM, Password: "test"}
	account, err := raw.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	memory := account.(*shadowsocks.MemoryAccount)
	// Independently generated with Python hashlib/cryptography: EVP_BytesToKey,
	// HKDF-SHA1(ss-subkey), AES192-GCM with the first all-zero 12-byte nonce.
	wantKey, _ := hex.DecodeString("098f6bcd4621d373cade4e832627b4f60a9172716ae64284")
	wantWire, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314151617dcb815fd4cb695bfe785ec5f808c1fa6aa082e7e07dd1c087444d9cecf918ab67174")
	if !bytes.Equal(memory.Key, wantKey) || memory.Cipher.KeySize() != 24 || memory.Cipher.IVSize() != 24 {
		t.Fatal("wrong AES192 key or salt size")
	}
	wire := buf.New()
	defer wire.Release()
	wire.Write(wantWire[:24])
	wire.Write([]byte("fork aes192 vector"))
	if err := memory.Cipher.EncodePacket(memory.Key, wire); err != nil || !bytes.Equal(wire.Bytes(), wantWire) {
		t.Fatal("independent AES192 vector mismatch", err)
	}
	for _, malformed := range []string{"tag", "password", "short"} {
		t.Run(malformed, func(t *testing.T) {
			packet := buf.New()
			defer packet.Release()
			packet.Write(wantWire)
			key := append([]byte(nil), memory.Key...)
			switch malformed {
			case "tag":
				packet.Bytes()[packet.Len()-1] ^= 1
			case "password":
				key[0] ^= 1
			case "short":
				packet.Resize(0, 24)
			}
			if err := memory.Cipher.DecodePacket(key, packet); err == nil {
				t.Fatal("unauthenticated AES192 packet accepted")
			}
		})
	}
	if err := memory.Cipher.DecodePacket(memory.Key, wire); err != nil || string(wire.Bytes()) != "fork aes192 vector" {
		t.Fatal("valid vector rejected", err)
	}
}

func TestForkAES192GCMTCPAndUDPFraming(t *testing.T) {
	account, err := (&shadowsocks.Account{CipherType: shadowsocks.CipherType_AES_192_GCM, Password: "synthetic-wire"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		Version: shadowsocks.Version, Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.invalid"), Port: 443, User: &protocol.MemoryUser{Account: account},
	}
	// Both a domain and a nontrivial first record exercise the upstream
	// 50-byte validation prefix with a 24-byte salt and encrypted length.
	payload := bytes.Repeat([]byte{0x5a, 0, 0xff}, 1000)
	cache, data := buf.New(), buf.New()
	defer cache.Release()
	data.Write(payload)
	writer, err := shadowsocks.WriteTCPRequest(request, cache)
	if err != nil {
		data.Release()
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{data}); err != nil {
		t.Fatal(err)
	}
	validator := new(shadowsocks.Validator)
	if err := validator.Add(request.User); err != nil {
		t.Fatal(err)
	}
	header, reader, err := shadowsocks.ReadTCPSession(validator, cache)
	if err != nil || header.Address.String() != "example.invalid" || header.Port != 443 {
		t.Fatal("AES192 TCP header changed", err)
	}
	plain, err := reader.ReadMultiBuffer()
	defer buf.ReleaseMulti(plain)
	if err != nil || len(plain) != 1 || !bytes.Equal(plain[0].Bytes(), payload) {
		t.Fatal("AES192 TCP body changed", err)
	}
	request.Command = protocol.RequestCommandUDP
	packet, err := shadowsocks.EncodeUDPPacket(request, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	header, decoded, err := shadowsocks.DecodeUDPPacket(validator, packet)
	if err != nil || header.Address.String() != "example.invalid" || header.Port != 443 || !bytes.Equal(decoded.Bytes(), payload) {
		t.Fatal("AES192 UDP address/body changed", err)
	}
}
