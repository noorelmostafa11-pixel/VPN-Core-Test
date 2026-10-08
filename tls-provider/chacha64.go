// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
package main

import (
	"encoding/binary"
	"math/bits"
)

// Original ChaCha20 uses a 64-bit block counter and an 8-byte nonce.
// An IETF nonce conversion would truncate that counter after 256 GiB.
type chacha64Stream struct {
	state     [16]uint32
	block     [64]byte
	used      int
	exhausted bool
}

func newChaCha64(key, nonce []byte) *chacha64Stream {
	s := &chacha64Stream{used: 64}
	s.state[0], s.state[1], s.state[2], s.state[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s.state[i+4] = binary.LittleEndian.Uint32(key[i*4:])
	}
	s.state[14], s.state[15] = binary.LittleEndian.Uint32(nonce), binary.LittleEndian.Uint32(nonce[4:])
	return s
}

func chachaQuarter(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 16)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 12)
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 8)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 7)
}

func (s *chacha64Stream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ChaCha20 output length")
	}
	for i, b := range src {
		if s.used == 64 {
			if s.exhausted {
				panic("ChaCha20 counter exhausted")
			}
			x := s.state
			for round := 0; round < 10; round++ {
				chachaQuarter(&x, 0, 4, 8, 12)
				chachaQuarter(&x, 1, 5, 9, 13)
				chachaQuarter(&x, 2, 6, 10, 14)
				chachaQuarter(&x, 3, 7, 11, 15)
				chachaQuarter(&x, 0, 5, 10, 15)
				chachaQuarter(&x, 1, 6, 11, 12)
				chachaQuarter(&x, 2, 7, 8, 13)
				chachaQuarter(&x, 3, 4, 9, 14)
			}
			for j := range x {
				binary.LittleEndian.PutUint32(s.block[j*4:], x[j]+s.state[j])
			}
			s.state[12]++
			if s.state[12] == 0 {
				s.state[13]++
				s.exhausted = s.state[13] == 0
			}
			s.used = 0
		}
		dst[i] = b ^ s.block[s.used]
		s.used++
	}
}
