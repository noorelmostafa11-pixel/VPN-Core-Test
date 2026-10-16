package shadowsocks

import (
	"encoding/binary"
	"sort"
)

// Per-account immutable permutations, never a global/password-indexed cache and
// never rebuilt for every UDP packet. Historical table is obfuscation, not AEAD.
type legacyTable struct{ encode, decode [256]byte }

func makeLegacyTable(key []byte) *legacyTable {
	a := binary.LittleEndian.Uint64(key)
	order := make([]int, 256)
	for i := range order {
		order[i] = i
	}
	for pass := 1; pass < 1024; pass++ {
		sort.SliceStable(order, func(i, j int) bool {
			return a%uint64(order[i]+pass) < a%uint64(order[j]+pass)
		})
	}
	table := new(legacyTable)
	for i, value := range order {
		table.encode[i] = byte(value)
		table.decode[value] = byte(i)
	}
	return table
}

type tableStream struct{ table *[256]byte }

func (s tableStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("table: output smaller than input")
	}
	for i, value := range src {
		dst[i] = s.table[value]
	}
}

type plainStream struct{}

func (plainStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("plain: output smaller than input")
	}
	copy(dst, src)
}
