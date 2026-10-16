package shadowsocks_test

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"io"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

var classicTypes = []shadowsocks.CipherType{
	shadowsocks.CipherType_CAMELLIA_128_CFB, shadowsocks.CipherType_CAMELLIA_192_CFB, shadowsocks.CipherType_CAMELLIA_256_CFB,
	shadowsocks.CipherType_IDEA_CFB, shadowsocks.CipherType_RC2_CFB, shadowsocks.CipherType_SEED_CFB,
	shadowsocks.CipherType_BLOWFISH_CFB, shadowsocks.CipherType_CAST5_CFB, shadowsocks.CipherType_DES_CFB,
	shadowsocks.CipherType_RC4, shadowsocks.CipherType_RC4_MD5, shadowsocks.CipherType_SALSA20,
	shadowsocks.CipherType_CHACHA20, shadowsocks.CipherType_CHACHA20_IETF, shadowsocks.CipherType_TABLE, shadowsocks.CipherType_NONE,
}

func TestForkClassicGoldenAndFragmentedStreams(t *testing.T) {
	// Block vectors: Blowfish's published zero vector, RFC2144 B.1 (CAST5),
	// the DES standard example; RC4 vector from RFC6229, 128-bit key, offset0.
	for _, vector := range []struct {
		method        shadowsocks.CipherType
		key, iv, want string
	}{
		{shadowsocks.CipherType_BLOWFISH_CFB, "00000000000000000000000000000000", "0000000000000000", "4ef997456198dd78"},
		{shadowsocks.CipherType_CAST5_CFB, "0123456712345678234567893456789a", "0123456789abcdef", "238b4fe5847e44b2"},
		{shadowsocks.CipherType_DES_CFB, "133457799bbcdff1", "0123456789abcdef", "85e813540f0ab405"},
		// RFC3713 Appendix A: CFB's first zero plaintext block equals E(key, IV).
		{shadowsocks.CipherType_CAMELLIA_128_CFB, "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"},
		{shadowsocks.CipherType_CAMELLIA_192_CFB, "0123456789abcdeffedcba98765432100011223344556677", "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"},
		{shadowsocks.CipherType_CAMELLIA_256_CFB, "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"},
		// IDEA NESSIE set1 vector0, RC2 RFC2268 section5 (128 effective bits),
		// and SEED RFC4269 Appendix B.1.
		{shadowsocks.CipherType_IDEA_CFB, "80000000000000000000000000000000", "0000000000000000", "b1f5f7f87901370f"},
		{shadowsocks.CipherType_RC2_CFB, "88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6"},
		{shadowsocks.CipherType_SEED_CFB, "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb"},
		{shadowsocks.CipherType_RC4, "0102030405060708090a0b0c0d0e0f10", "", "9ac7cc9a609d1ef7b2932899cde41b97"},
		{shadowsocks.CipherType_CHACHA20, "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"},
		{shadowsocks.CipherType_CHACHA20_IETF, "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"},
	} {
		t.Run(vector.method.String(), func(t *testing.T) {
			c := legacyMemory(t, vector.method).Cipher
			var wire bytes.Buffer
			want := unhex(t, vector.want)
			writer, err := c.NewEncryptionWriter(unhex(t, vector.key), unhex(t, vector.iv), &wire)
			if err != nil {
				t.Fatal(err)
			}
			writePiece(t, writer, make([]byte, len(want)))
			if !bytes.Equal(wire.Bytes(), want) {
				t.Fatal("published vector mismatch")
			}
		})
	}
	for _, method := range classicTypes {
		t.Run("fragmented-"+method.String(), func(t *testing.T) {
			account := legacyMemory(t, method)
			iv := make([]byte, account.Cipher.IVSize())
			for i := range iv {
				iv[i] = byte(i + 1)
			}
			var wire bytes.Buffer
			writer, err := account.Cipher.NewEncryptionWriter(account.Key, iv, &wire)
			if err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte{0, 0xff, 0x5a}, 4001)
			for _, piece := range [][]byte{body[:1], body[1:64], body[64:65], body[65:8001], body[8001:]} {
				writePiece(t, writer, piece)
			}
			reader, err := account.Cipher.NewDecryptionReader(account.Key, iv, iotest.HalfReader(bytes.NewReader(wire.Bytes())))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
			if err != nil || !bytes.Equal(plain, body) {
				t.Fatal("stream state or fragmented plaintext changed", err)
			}
			if _, err := account.Cipher.NewDecryptionReader(account.Key, append(iv, 1), &wire); err == nil {
				t.Fatal("wrong IV size accepted")
			}
			if _, err := account.Cipher.NewEncryptionWriter(append(append([]byte(nil), account.Key...), 1), iv, &wire); err == nil {
				t.Fatal("wrong key size accepted")
			}
			for size := range int(account.Cipher.IVSize() + 1) {
				packet := buf.New()
				packet.Extend(int32(size))
				err := account.Cipher.DecodePacket(account.Key, packet)
				packet.Release()
				if err == nil {
					t.Fatal("short UDP IV or empty packet accepted")
				}
			}
		})
	}
}

func TestForkClassicHeaderOnlyAndUDP(t *testing.T) {
	for _, method := range classicTypes {
		t.Run(method.String(), func(t *testing.T) {
			account := legacyMemory(t, method)
			user := &protocol.MemoryUser{Account: account}
			validator := new(shadowsocks.Validator)
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			for _, address := range []net.Address{net.LocalHostIP, net.ParseAddress("::1"), net.DomainAddress("example.invalid")} {
				request := &protocol.RequestHeader{Version: shadowsocks.Version, Command: protocol.RequestCommandTCP, User: user, Address: address, Port: 443}
				var wire bytes.Buffer
				if _, err := shadowsocks.WriteTCPRequest(request, &wire); err != nil {
					t.Fatal(err)
				}
				header, _, err := shadowsocks.ReadTCPSession(validator, &wire)
				if err != nil || header.Address.String() != address.String() || header.Port != 443 {
					t.Fatal("header-only legacy TCP rejected", err)
				}
				body := bytes.Repeat([]byte{0, 0xff, 0x5a}, 1266)
				packet, err := shadowsocks.EncodeUDPPacket(request, body)
				if err != nil {
					t.Fatal(err)
				}
				header, plain, err := shadowsocks.DecodeUDPPacket(validator, packet)
				if err != nil || header.Address.String() != address.String() || header.Port != 443 || !bytes.Equal(plain.Bytes(), body) {
					packet.Release()
					t.Fatal("UDP address or plaintext changed", err)
				}
				packet.Release()
			}
			if err := validator.Add(&protocol.MemoryUser{Account: legacyMemory(t, shadowsocks.CipherType_AES_128_GCM)}); err == nil {
				t.Fatal("AEAD mixed with unauthenticated classic listener")
			}
		})
	}
}

func TestForkRC4MD5PacketKeyAndFreshState(t *testing.T) {
	account := legacyMemory(t, shadowsocks.CipherType_RC4_MD5)
	iv := bytes.Repeat([]byte{0x5a}, 16)
	plain := bytes.Repeat([]byte{1, 2, 3, 4}, 100)
	sum := md5.Sum(append(append([]byte(nil), account.Key...), iv...))
	oracle, err := rc4.NewCipher(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]byte, len(plain))
	oracle.XORKeyStream(expected, plain)
	for range 3 {
		packet := buf.New()
		packet.Write(iv)
		packet.Write(plain)
		err := account.Cipher.EncodePacket(account.Key, packet)
		matches := bytes.Equal(packet.Bytes(), append(append([]byte(nil), iv...), expected...))
		packet.Release()
		if err != nil || !matches {
			t.Fatal("RC4-MD5 derivation or per-packet reset changed", err)
		}
	}
}

func TestForkTableConcurrentGolden(t *testing.T) {
	raw := &shadowsocks.Account{CipherType: shadowsocks.CipherType_TABLE, Password: "synthetic server secret"}
	converted, err := raw.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	account := converted.(*shadowsocks.MemoryAccount)
	// Independent stable-sort oracle digest retained in pinned main's table test.
	want := unhex(t, "173921da2f4651b1a0630a1420d5bbaf18fd7050f9bfccb2360650071ddcd95c")
	plain := append([]byte{1, 127, 0, 0, 1, 1, 0xbb}, make([]byte, 256)...)
	for i := range 256 {
		plain[7+i] = byte(i)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 8 {
				packet := buf.New()
				packet.Write(plain)
				err := account.Cipher.EncodePacket(account.Key, packet)
				digest := sha256.Sum256(packet.Bytes())
				if err != nil || !bytes.Equal(digest[:], want) {
					t.Error("table golden changed", err)
				}
				err = account.Cipher.DecodePacket(account.Key, packet)
				if err != nil || !bytes.Equal(packet.Bytes(), plain) {
					t.Error("shared table decode changed", err)
				}
				packet.Release()
			}
		})
	}
	workers.Wait()
}
