package shadowsocks

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
)

// Stream state/framing only: cipher rounds stay in the existing Go crypto
// library. Original ChaCha uses a 64-bit counter and 8-byte nonce, not IETF's
// 32-bit counter/12-byte nonce. State word13 carries the original counter's high
// half; we supply it in IETF nonce[0:4] and split calls at each low-word wrap.
type legacyARX struct {
	method    CipherType
	key       [32]byte
	nonce     [8]byte
	counter   uint64
	cache     [64]byte
	used      int
	exhausted bool
}

func newLegacyARX(method CipherType, key, nonce []byte) *legacyARX {
	s := &legacyARX{method: method, used: 64}
	copy(s.key[:], key)
	copy(s.nonce[:], nonce)
	return s
}

func (s *legacyARX) xorBlocks(dst, src []byte) {
	if s.method == CipherType_SALSA20 {
		var counter [16]byte
		copy(counter[:8], s.nonce[:])
		binary.LittleEndian.PutUint64(counter[8:], s.counter)
		salsa.XORKeyStream(dst, src, &counter, &s.key)
	} else {
		var nonce [12]byte
		binary.LittleEndian.PutUint32(nonce[:4], uint32(s.counter>>32))
		copy(nonce[4:], s.nonce[:])
		stream, _ := chacha20.NewUnauthenticatedCipher(s.key[:], nonce[:])
		stream.SetCounter(uint32(s.counter))
		stream.XORKeyStream(dst, src)
	}
	s.counter += uint64(len(src) / 64)
	if s.counter == 0 && len(src) != 0 {
		s.exhausted = true
	}
}

func (s *legacyARX) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("legacy ARX: output smaller than input")
	}
	remaining := len(src) - (64 - s.used)
	if remaining > 0 {
		needed := uint64(remaining / 64)
		if remaining%64 != 0 {
			needed++
		}
		if s.exhausted || needed-1 > ^uint64(0)-s.counter {
			panic("legacy ARX: counter exhausted")
		}
	}
	for len(src) != 0 {
		if s.used < 64 {
			n := min(len(src), 64-s.used)
			for i, value := range src[:n] {
				dst[i] = value ^ s.cache[s.used+i]
			}
			s.used += n
			dst, src = dst[n:], src[n:]
			continue
		}
		if len(src) < 64 {
			var zero [64]byte
			s.xorBlocks(s.cache[:], zero[:])
			s.used = 0
			continue
		}
		blocks := uint64(len(src) / 64)
		if s.method == CipherType_CHACHA20 {
			blocks = min(blocks, 1<<32-uint64(uint32(s.counter)))
		}
		n := int(blocks) * 64
		s.xorBlocks(dst[:n], src[:n])
		dst, src = dst[n:], src[n:]
	}
}
