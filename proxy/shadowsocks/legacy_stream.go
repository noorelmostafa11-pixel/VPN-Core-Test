package shadowsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/chacha20"
)

// legacyStreamCipher is unauthenticated historical Shadowsocks compatibility.
// It is never selected implicitly and cannot share a listener with other users.
type legacyStreamCipher struct {
	keyBytes int32
	ivBytes  int32
	method   CipherType
	tableKey []byte
	table    *legacyTable
}

func newLegacyStreamCipher(method CipherType, keyBytes, ivBytes int32, password string) *legacyStreamCipher {
	c := &legacyStreamCipher{method: method, keyBytes: keyBytes, ivBytes: ivBytes}
	if method == CipherType_TABLE {
		c.tableKey = passwordToCipherKey([]byte(password), keyBytes)
		c.table = makeLegacyTable(c.tableKey)
	}
	return c
}

func (c *legacyStreamCipher) KeySize() int32 { return c.keyBytes }

func (c *legacyStreamCipher) IVSize() int32 { return c.ivBytes }

func (*legacyStreamCipher) IsAEAD() bool { return false }

func (c *legacyStreamCipher) stream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	if len(key) != int(c.keyBytes) || len(iv) != int(c.ivBytes) {
		return nil, errors.New("invalid legacy key or IV length")
	}
	switch c.method {
	case CipherType_NONE:
		return plainStream{}, nil
	case CipherType_TABLE:
		table := c.table
		if !bytes.Equal(key, c.tableKey) {
			// Direct Cipher callers may use another key. Never mutate or reuse
			// the account-bound permutation for a different password.
			table = makeLegacyTable(key)
		}
		if decrypt {
			return tableStream{&table.decode}, nil
		}
		return tableStream{&table.encode}, nil
	case CipherType_RC4:
		return rc4.NewCipher(key)
	case CipherType_RC4_MD5:
		var material [32]byte
		copy(material[:16], key)
		copy(material[16:], iv)
		sum := md5.Sum(material[:])
		return rc4.NewCipher(sum[:])
	case CipherType_SALSA20, CipherType_CHACHA20:
		return newLegacyARX(c.method, key, iv), nil
	case CipherType_CHACHA20_IETF:
		return chacha20.NewUnauthenticatedCipher(key, iv)
	}
	var block cipher.Block
	var err error
	switch c.method {
	case CipherType_BLOWFISH_CFB:
		block, err = blowfish.NewCipher(key)
	case CipherType_CAST5_CFB:
		block, err = cast5.NewCipher(key)
	case CipherType_DES_CFB:
		block, err = des.NewCipher(key)
	case CipherType_AES_128_CFB, CipherType_AES_192_CFB, CipherType_AES_256_CFB,
		CipherType_AES_128_CTR, CipherType_AES_192_CTR, CipherType_AES_256_CTR,
		CipherType_AES_128_OFB, CipherType_AES_192_OFB, CipherType_AES_256_OFB:
		block, err = aes.NewCipher(key)
	default:
		return nil, errors.New("unsupported legacy cipher")
	}
	if err != nil {
		return nil, err
	}
	switch c.method {
	case CipherType_AES_128_CTR, CipherType_AES_192_CTR, CipherType_AES_256_CTR:
		return cipher.NewCTR(block, iv), nil
	case CipherType_AES_128_OFB, CipherType_AES_192_OFB, CipherType_AES_256_OFB:
		return cipher.NewOFB(block, iv), nil
	default:
		if decrypt {
			return cipher.NewCFBDecrypter(block, iv), nil
		}
		return cipher.NewCFBEncrypter(block, iv), nil
	}
}

func (c *legacyStreamCipher) NewEncryptionWriter(key, iv []byte, writer io.Writer) (buf.Writer, error) {
	stream, err := c.stream(key, iv, false)
	if err != nil {
		return nil, err
	}
	return crypto.NewCryptionWriter(stream, writer), nil
}

func (c *legacyStreamCipher) NewDecryptionReader(key, iv []byte, reader io.Reader) (buf.Reader, error) {
	stream, err := c.stream(key, iv, true)
	if err != nil {
		return nil, err
	}
	return buf.NewReader(crypto.NewCryptionReader(stream, reader)), nil
}

func (c *legacyStreamCipher) packet(key []byte, packet *buf.Buffer, decrypt bool) error {
	ivSize := c.IVSize()
	if packet.Len() <= ivSize {
		return errors.New("insufficient legacy packet data")
	}
	stream, err := c.stream(key, packet.BytesTo(ivSize), decrypt)
	if err != nil {
		return err
	}
	data := packet.BytesFrom(ivSize)
	stream.XORKeyStream(data, data)
	if decrypt {
		packet.Advance(ivSize)
	}
	return nil
}

func (c *legacyStreamCipher) EncodePacket(key []byte, packet *buf.Buffer) error {
	return c.packet(key, packet, false)
}

func (c *legacyStreamCipher) DecodePacket(key []byte, packet *buf.Buffer) error {
	return c.packet(key, packet, true)
}
