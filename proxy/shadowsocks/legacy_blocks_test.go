package shadowsocks_test

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/proxy/shadowsocks/internal/cryptobin/cipher/camellia"
	"github.com/xtls/xray-core/proxy/shadowsocks/internal/cryptobin/cipher/idea"
	"github.com/xtls/xray-core/proxy/shadowsocks/internal/cryptobin/cipher/rc2"
	"github.com/xtls/xray-core/proxy/shadowsocks/internal/cryptobin/cipher/seed"
)

func TestForkLegacyBlockContracts(t *testing.T) {
	constructors := []struct {
		name  string
		new   func([]byte) (cipher.Block, error)
		valid []int
	}{
		{"camellia", camellia.NewCipher, []int{16, 24, 32}},
		{"idea", idea.NewCipher, []int{16}},
		{"rc2", func(key []byte) (cipher.Block, error) { return rc2.NewCipher(key, 128) }, nil},
		{"seed", seed.NewCipher, []int{16, 32}},
	}
	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			for length := range 130 {
				valid := constructor.name == "rc2" && length >= 1 && length <= 128
				for _, size := range constructor.valid {
					valid = valid || size == length
				}
				block, err := constructor.new(make([]byte, length))
				if !valid {
					if err == nil || block != nil {
						t.Fatalf("invalid key length %d accepted", length)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				blockSize := block.BlockSize()
				plain := bytes.Repeat([]byte{0x5a}, blockSize)
				encrypted := make([]byte, blockSize)
				block.Encrypt(encrypted, plain)
				inplace := append([]byte(nil), plain...)
				block.Encrypt(inplace, inplace)
				if !bytes.Equal(inplace, encrypted) {
					t.Fatal("in-place encryption changed")
				}
				block.Decrypt(inplace, inplace)
				if !bytes.Equal(inplace, plain) {
					t.Fatal("in-place decryption changed")
				}
				for _, operation := range []func([]byte, []byte){block.Encrypt, block.Decrypt} {
					for size := range blockSize {
						requireBlockPanic(t, func() { operation(make([]byte, blockSize), make([]byte, size)) })
						requireBlockPanic(t, func() { operation(make([]byte, size), make([]byte, blockSize)) })
					}
					overlap := make([]byte, blockSize+1)
					requireBlockPanic(t, func() { operation(overlap[1:], overlap[:blockSize]) })
					requireBlockPanic(t, func() { operation(overlap[:blockSize], overlap[1:]) })
				}
			}
		})
	}
}

func requireBlockPanic(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("invalid block bounds or overlap did not panic")
		}
	}()
	operation()
}

func TestForkRC2EffectiveBitsAndVectors(t *testing.T) {
	// RFC2268 section5. In particular 64 and 128 effective bits with the
	// same 16-byte key must NOT produce the same result.
	for _, vector := range []struct {
		key         string
		bits        int
		plain, want string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", 129, "0000000000000000", "5b78d3a43dfff1f1"},
	} {
		t.Run(fmt.Sprintf("%s/%d", vector.key, vector.bits), func(t *testing.T) {
			block, err := rc2.NewCipher(unhex(t, vector.key), vector.bits)
			if err != nil {
				t.Fatal(err)
			}
			out := make([]byte, block.BlockSize())
			block.Encrypt(out, unhex(t, vector.plain))
			if !bytes.Equal(out, unhex(t, vector.want)) {
				t.Fatalf("RFC2268 mismatch: %x", out)
			}
			block.Decrypt(out, out)
			if !bytes.Equal(out, unhex(t, vector.plain)) {
				t.Fatal("RFC2268 decrypt mismatch")
			}
		})
	}
	for _, bits := range []int{-1024, -1, 0, 1025, int(^uint(0) >> 1)} {
		if block, err := rc2.NewCipher(make([]byte, 16), bits); err == nil || block != nil {
			t.Fatal("invalid effective bits accepted", bits)
		}
	}
	for _, bits := range []int{1, 8, 128, 1024} {
		for _, size := range []int{1, 16, 128} {
			block, err := rc2.NewCipher(make([]byte, size), bits)
			if err != nil {
				t.Fatal(err)
			}
			plain := bytes.Repeat([]byte{0x96}, 8)
			out := append([]byte(nil), plain...)
			block.Encrypt(out, out)
			block.Decrypt(out, out)
			if !bytes.Equal(out, plain) {
				t.Fatal("valid RC2 boundary failed", size, bits)
			}
		}
	}
}
