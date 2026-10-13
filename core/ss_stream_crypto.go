package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/cryptobin/cipher/camellia"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/cryptobin/cipher/idea"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/cryptobin/cipher/rc2"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/cryptobin/cipher/seed"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/gocrypto/blowfish"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/gocrypto/cast5"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core/thirdparty/gocrypto/salsa20/salsa"
	"golang.org/x/crypto/chacha20"
	"sort"
	"strings"
)

type salsaStream struct {
	key   [32]byte
	nonce [16]byte
	block [64]byte
	used  int
}

func (s *salsaStream) XORKeyStream(dst, src []byte) {
	for i, b := range src {
		if s.used == 64 {
			var zero [64]byte
			salsa.XORKeyStream(s.block[:], zero[:], &s.nonce, &s.key)
			for j := 8; j < 16; j++ {
				s.nonce[j]++
				if s.nonce[j] != 0 {
					break
				}
			}
			s.used = 0
		}
		dst[i] = b ^ s.block[s.used]
		s.used++
	}
}

type tableStream struct{ table [256]byte }

func (s *tableStream) XORKeyStream(dst, src []byte) {
	for i, b := range src {
		dst[i] = s.table[b]
	}
}

func ssStreamCipher(method string, key, iv []byte, decrypt bool) (cipher.Stream, error) {
	if method == "table" {
		if len(key) != 16 || len(iv) != 0 {
			return nil, errors.New("table key")
		}
		a := binary.LittleEndian.Uint64(key)
		order := make([]int, 256)
		for i := range order {
			order[i] = i
		}
		for i := uint64(1); i < 1024; i++ {
			sort.SliceStable(order, func(x, y int) bool { return a%uint64(order[x]+int(i)) < a%uint64(order[y]+int(i)) })
		}
		s := &tableStream{}
		for i, b := range order {
			if decrypt {
				s.table[b] = byte(i)
			} else {
				s.table[i] = byte(b)
			}
		}
		return s, nil
	}
	if method == "rc4" || method == "rc4-md5" {
		if len(key) != 16 || (method == "rc4" && len(iv) != 0) || (method == "rc4-md5" && len(iv) != 16) {
			return nil, errors.New("RC4 parameters")
		}
		if method == "rc4-md5" {
			material := append(append([]byte{}, key...), iv...)
			sum := md5.Sum(material)
			key = sum[:]
		}
		return rc4.NewCipher(key)
	}
	if method == "salsa20" {
		if len(key) != 32 || len(iv) != 8 {
			return nil, errors.New("Salsa20 parameters")
		}
		s := &salsaStream{used: 64}
		copy(s.key[:], key)
		copy(s.nonce[:], iv)
		return s, nil
	}
	if method == "chacha20" || method == "chacha20-ietf" {
		if len(key) != 32 || (method == "chacha20" && len(iv) != 8) || (method == "chacha20-ietf" && len(iv) != 12) {
			return nil, errors.New("ChaCha20 parameters")
		}
		if len(iv) == 8 {
			return newChaCha64(key, iv), nil
		}
		return chacha20.NewUnauthenticatedCipher(key, iv)
	}
	var block cipher.Block
	var err error
	switch {
	case strings.HasPrefix(method, "aes-"):
		block, err = aes.NewCipher(key)
	case strings.HasPrefix(method, "camellia-"):
		block, err = camellia.NewCipher(key)
	case method == "bf-cfb":
		block, err = blowfish.NewCipher(key)
	case method == "cast5-cfb":
		block, err = cast5.NewCipher(key)
	case method == "des-cfb":
		block, err = des.NewCipher(key)
	case method == "idea-cfb":
		block, err = idea.NewCipher(key)
	case method == "rc2-cfb":
		block, err = rc2.NewCipher(key, len(key)*8)
	case method == "seed-cfb":
		block, err = seed.NewCipher(key)
	default:
		return nil, errors.New("unknown stream cipher")
	}
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New("stream IV length")
	}
	if strings.HasSuffix(method, "-ctr") {
		return cipher.NewCTR(block, iv), nil
	}
	if strings.HasSuffix(method, "-ofb") {
		return cipher.NewOFB(block, iv), nil
	}
	if !strings.HasSuffix(method, "-cfb") {
		return nil, errors.New("stream mode")
	}
	if decrypt {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}
