package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestOriginalChaChaCounterCarry(t *testing.T) {
	key, nonce := make([]byte, 32), make([]byte, 8)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i)
	}
	s := newChaCha64(key, nonce)
	s.state[12] = 0xffffffff
	// Independent PyCryptodome oracle, seek=(2^32-1)*64, then two blocks.
	want, _ := hex.DecodeString("a2b8d04b13877b4a7013cb9031e4b70836e9705a9691bd18f8fca48502eacdcae0b8faaeef6c5dfee436afd8268aa6385dabb2855761127a3946b50d649f9a4b2fcab2c09a960545c6f57e9269ebc22b4ed12782e66dc4cb612536f5cdbed4bcba16af8a92140bf4ded4808af8eee82bd0f18fbb64f073c2a547bc2372528f36")
	got := make([]byte, len(want))
	s.XORKeyStream(got[:17], make([]byte, 17))
	s.XORKeyStream(got[17:65], make([]byte, 48))
	s.XORKeyStream(got[65:], make([]byte, len(got)-65))
	if !bytes.Equal(got, want) {
		t.Fatal("original ChaCha20 counter/chunk continuity")
	}
}
