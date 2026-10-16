package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"testing"
)

// Independent test-only original-state ChaCha20 oracle; production rounds stay
// in golang.org/x/crypto. This lays out the 64-bit counter explicitly rather
// than reusing the production IETF-nonce mapping.
func originalChaChaBlock(key, nonce []byte, counter uint64) [64]byte {
	state := [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	for i := range 8 {
		state[i+4] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12], state[13] = uint32(counter), uint32(counter>>32)
	state[14], state[15] = binary.LittleEndian.Uint32(nonce), binary.LittleEndian.Uint32(nonce[4:])
	x := state
	quarter := func(a, b, c, d int) {
		x[a] += x[b]
		x[d] = bits.RotateLeft32(x[d]^x[a], 16)
		x[c] += x[d]
		x[b] = bits.RotateLeft32(x[b]^x[c], 12)
		x[a] += x[b]
		x[d] = bits.RotateLeft32(x[d]^x[a], 8)
		x[c] += x[d]
		x[b] = bits.RotateLeft32(x[b]^x[c], 7)
	}
	for range 10 {
		quarter(0, 4, 8, 12)
		quarter(1, 5, 9, 13)
		quarter(2, 6, 10, 14)
		quarter(3, 7, 11, 15)
		quarter(0, 5, 10, 15)
		quarter(1, 6, 11, 12)
		quarter(2, 7, 8, 13)
		quarter(3, 4, 9, 14)
	}
	var out [64]byte
	for i := range x {
		binary.LittleEndian.PutUint32(out[i*4:], x[i]+state[i])
	}
	return out
}

func TestForkChaChaOriginalCounterCarry(t *testing.T) {
	key, nonce := bytes.Repeat([]byte{0x5a}, 32), []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, start := range []uint64{0, 1<<32 - 1, 1 << 32, 1<<48 + 31} {
		stream := newLegacyARX(CipherType_CHACHA20, key, nonce)
		stream.counter = start
		var expected []byte
		for offset := range 3 {
			block := originalChaChaBlock(key, nonce, start+uint64(offset))
			expected = append(expected, block[:]...)
		}
		got, zeros := make([]byte, len(expected)), make([]byte, len(expected))
		for _, part := range [][2]int{{0, 1}, {1, 63}, {63, 129}, {129, 192}} {
			stream.XORKeyStream(got[part[0]:part[1]], zeros[part[0]:part[1]])
		}
		if !bytes.Equal(got, expected) {
			t.Fatal("original 64-bit counter/nonce mapping changed", start)
		}
	}
}

func TestForkSalsaECRYPTFragmentedVector(t *testing.T) {
	// ECRYPT verified set6 vector, also retained in Go x/crypto salsa20 tests.
	key, _ := hex.DecodeString("0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d")
	nonce, _ := hex.DecodeString("0d74db42a91077de")
	want, _ := hex.DecodeString("c349b6a51a3ec9b712eaed3f90d8bcee69b7628645f251a996f55260c62ef31fd6c6b0aea94e136c9d984ad2df3578f78e457527b03a0450580dd874f63b1ab9")
	stream := newLegacyARX(CipherType_SALSA20, key, nonce)
	got, zeros := make([]byte, 131072), make([]byte, 131072)
	for pos := 0; pos < len(got); {
		end := min(pos+137, len(got))
		stream.XORKeyStream(got[pos:end], zeros[pos:end])
		pos = end
	}
	var folded [64]byte
	for i, value := range got {
		folded[i%64] ^= value
	}
	if !bytes.Equal(folded[:], want) {
		t.Fatal("fragmented Salsa20 ECRYPT vector mismatch")
	}
}

func TestForkARXCounterExhaustion(t *testing.T) {
	for _, method := range []CipherType{CipherType_SALSA20, CipherType_CHACHA20} {
		stream := newLegacyARX(method, make([]byte, 32), make([]byte, 8))
		stream.counter = ^uint64(0)
		stream.XORKeyStream(make([]byte, 1), make([]byte, 1))
		stream.XORKeyStream(make([]byte, 63), make([]byte, 63)) // Remaining final block is usable.
		stream.XORKeyStream(nil, nil)
		func() {
			defer func() {
				if recover() == nil {
					t.Error("counter reused after exhaustion", method)
				}
			}()
			stream.XORKeyStream(make([]byte, 1), make([]byte, 1))
		}()
		stream = newLegacyARX(method, make([]byte, 32), make([]byte, 8))
		stream.counter = ^uint64(0)
		out := bytes.Repeat([]byte{0xa5}, 65)
		func() {
			defer func() {
				if recover() == nil {
					t.Error("overlong write accepted at final counter", method)
				}
			}()
			stream.XORKeyStream(out, make([]byte, 65))
		}()
		if !bytes.Equal(out, bytes.Repeat([]byte{0xa5}, 65)) || stream.counter != ^uint64(0) {
			t.Fatal("exhausted write partially changed output or state", method)
		}
	}
}

func TestForkTableCacheBoundToAccountKey(t *testing.T) {
	c := newLegacyStreamCipher(CipherType_TABLE, 16, 0, "first-password")
	original := c.table
	other := passwordToCipherKey([]byte("other-password"), 16)
	stream, err := c.stream(other, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var got [256]byte
	for i := range got {
		got[i] = byte(i)
	}
	stream.XORKeyStream(got[:], got[:])
	if got != makeLegacyTable(other).encode || c.table != original {
		t.Fatal("alternate key poisoned account-bound table")
	}
	stream, err = c.stream(c.tableKey, nil, false)
	if err != nil || stream.(tableStream).table != &original.encode {
		t.Fatal("per-account table was rebuilt or changed", err)
	}
}

func TestForkUnknownLegacyMethodNotSubstituted(t *testing.T) {
	c := newLegacyStreamCipher(CipherType(999), 16, 16, "synthetic")
	if _, err := c.NewEncryptionWriter(make([]byte, 16), make([]byte, 16), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown legacy method silently substituted")
	}
}
