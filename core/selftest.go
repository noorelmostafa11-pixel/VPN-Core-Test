package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func SelfTest() error {
	h := sha256.Sum224([]byte("abc"))
	if hex.EncodeToString(h[:]) != "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" {
		return errors.New("SHA224 vector failed")
	}
	for _, method := range []string{"aes-128-gcm", "chacha20-ietf-poly1305"} {
		n := 32
		if method == "aes-128-gcm" {
			n = 16
		}
		a, e := cipherAEAD(method, make([]byte, n))
		if e != nil {
			return e
		}
		nonce := make([]byte, a.NonceSize())
		b := a.Seal(nil, nonce, []byte("independent core"), nil)
		out, e := a.Open(nil, nonce, b, nil)
		if e != nil || string(out) != "independent core" {
			return errors.New("AEAD roundtrip")
		}
	}
	return nil
}
