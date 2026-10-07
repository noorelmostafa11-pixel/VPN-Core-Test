// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Standard-library primitives for the same project-owned C++ protocols on POSIX.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"unsafe"
)

func cryptoDigest(kind int, in []byte) ([]byte, error) {
	switch kind {
	case 1:
		b := md5.Sum(in)
		return b[:], nil
	case 2:
		b := sha1.Sum(in)
		return b[:], nil
	case 3:
		b := sha256.Sum256(in)
		return b[:], nil
	case 4:
		b := sha512.Sum384(in)
		return b[:], nil
	case 5:
		b := sha512.Sum512(in)
		return b[:], nil
	}
	return nil, errors.New("unknown digest")
}
func cryptoAES(key, nonce, in, aad []byte, decrypt, ecb bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if ecb {
		if len(in)%aes.BlockSize != 0 {
			return nil, errors.New("block size")
		}
		out := make([]byte, len(in))
		for i := 0; i < len(in); i += aes.BlockSize {
			if decrypt {
				block.Decrypt(out[i:i+aes.BlockSize], in[i:i+aes.BlockSize])
			} else {
				block.Encrypt(out[i:i+aes.BlockSize], in[i:i+aes.BlockSize])
			}
		}
		return out, nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("nonce size")
	}
	if decrypt {
		return gcm.Open(nil, nonce, in, aad)
	}
	return gcm.Seal(nil, nonce, in, aad), nil
}

// Borrow C-owned buffers only for the duration of the call; retain no pointers.
func cryptoBuffer(p *C.char, n C.int, limit int) ([]byte, bool) {
	if n < 0 || int(n) > limit || (n > 0 && p == nil) {
		return nil, false
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n)), true
}

//export vpn_crypto_random
func vpn_crypto_random(out *C.char, n C.int) C.int {
	b, ok := cryptoBuffer(out, n, bufferLimit)
	if !ok {
		return -1
	}
	if _, err := rand.Read(b); err != nil {
		return -1
	}
	return 0
}

//export vpn_crypto_digest
func vpn_crypto_digest(kind C.int, in *C.char, n C.int, out *C.char, capacity C.int) C.int {
	b, ok := cryptoBuffer(in, n, bufferLimit)
	if !ok {
		return -1
	}
	dst, ok := cryptoBuffer(out, capacity, 64)
	if !ok {
		return -1
	}
	result, err := cryptoDigest(int(kind), b)
	if err != nil || len(result) > len(dst) {
		return -1
	}
	return C.int(copy(dst, result))
}

//export vpn_crypto_aes
func vpn_crypto_aes(key *C.char, nk C.int, nonce *C.char, nn C.int, in *C.char, n C.int, aad *C.char, na C.int, decrypt C.int, ecb C.int, out *C.char, capacity C.int) C.int {
	k, ok := cryptoBuffer(key, nk, 32)
	if !ok {
		return -1
	}
	iv, ok := cryptoBuffer(nonce, nn, 16)
	if !ok {
		return -1
	}
	b, ok := cryptoBuffer(in, n, bufferLimit)
	if !ok {
		return -1
	}
	a, ok := cryptoBuffer(aad, na, bufferLimit)
	if !ok {
		return -1
	}
	dst, ok := cryptoBuffer(out, capacity, bufferLimit+32)
	if !ok {
		return -1
	}
	if (decrypt != 0 && decrypt != 1) || (ecb != 0 && ecb != 1) {
		return -1
	}
	result, err := cryptoAES(k, iv, b, a, decrypt == 1, ecb == 1)
	if err != nil || len(result) > len(dst) {
		return -1
	}
	return C.int(copy(dst, result))
}
