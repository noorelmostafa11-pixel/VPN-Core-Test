package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPortableAESKnownVectors(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	encrypted, err := cryptoAES(key, nonce, make([]byte, 16), nil, false, false)
	if err != nil || hex.EncodeToString(encrypted) != "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf" {
		t.Fatal("NIST GCM vector", err)
	}
	plain, err := cryptoAES(key, nonce, encrypted, nil, true, false)
	if err != nil || !bytes.Equal(plain, make([]byte, 16)) {
		t.Fatal("GCM decrypt", err)
	}
	encrypted[0] ^= 1
	if _, err = cryptoAES(key, nonce, encrypted, nil, true, false); err == nil {
		t.Fatal("tamper accepted")
	}
	encrypted, err = cryptoAES(key, nil, make([]byte, 16), nil, false, true)
	if err != nil || hex.EncodeToString(encrypted) != "66e94bd4ef8a2c3b884cfa59ca342b2e" {
		t.Fatal("ECB vector", err)
	}
	for _, n := range []int{0, 1, 11, 13} {
		if _, err = cryptoAES(key, make([]byte, n), nil, nil, false, false); err == nil {
			t.Fatal("nonce accepted", n)
		}
	}
	if _, err = cryptoAES(key, nil, make([]byte, 15), nil, false, true); err == nil {
		t.Fatal("unaligned ECB accepted")
	}
}
