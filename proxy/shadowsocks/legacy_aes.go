package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

// legacyAESCipher is unauthenticated historical Shadowsocks compatibility.
// It is never selected implicitly and cannot share a listener with other users.
type legacyAESCipher struct {
	keyBytes int32
	method   CipherType
}

func (c *legacyAESCipher) KeySize() int32 { return c.keyBytes }

func (*legacyAESCipher) IVSize() int32 { return aes.BlockSize }

func (*legacyAESCipher) IsAEAD() bool { return false }

func (c *legacyAESCipher) stream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	if len(key) != int(c.keyBytes) || len(iv) != aes.BlockSize {
		return nil, errors.New("invalid legacy AES key or IV length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch c.method {
	case CipherType_AES_128_CFB, CipherType_AES_192_CFB, CipherType_AES_256_CFB:
		if decrypt {
			return cipher.NewCFBDecrypter(block, iv), nil
		}
		return cipher.NewCFBEncrypter(block, iv), nil
	case CipherType_AES_128_CTR, CipherType_AES_192_CTR, CipherType_AES_256_CTR:
		return cipher.NewCTR(block, iv), nil
	case CipherType_AES_128_OFB, CipherType_AES_192_OFB, CipherType_AES_256_OFB:
		return cipher.NewOFB(block, iv), nil
	default:
		return nil, errors.New("unsupported legacy AES mode")
	}
}

func (c *legacyAESCipher) NewEncryptionWriter(key, iv []byte, writer io.Writer) (buf.Writer, error) {
	stream, err := c.stream(key, iv, false)
	if err != nil {
		return nil, err
	}
	return crypto.NewCryptionWriter(stream, writer), nil
}

func (c *legacyAESCipher) NewDecryptionReader(key, iv []byte, reader io.Reader) (buf.Reader, error) {
	stream, err := c.stream(key, iv, true)
	if err != nil {
		return nil, err
	}
	return buf.NewReader(crypto.NewCryptionReader(stream, reader)), nil
}

func (c *legacyAESCipher) packet(key []byte, packet *buf.Buffer, decrypt bool) error {
	ivSize := c.IVSize()
	if packet.Len() <= ivSize {
		return errors.New("insufficient legacy AES packet data")
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

func (c *legacyAESCipher) EncodePacket(key []byte, packet *buf.Buffer) error {
	return c.packet(key, packet, false)
}

func (c *legacyAESCipher) DecodePacket(key []byte, packet *buf.Buffer) error {
	return c.packet(key, packet, true)
}
