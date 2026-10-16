package shadowsocks

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type initialBufferReader struct{ data buf.MultiBuffer }

func (r initialBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.data, nil
}

func (r initialBufferReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.data, nil
}

func TestForkInitialPayloadDoesNotCloseAEAD(t *testing.T) {
	for _, method := range []CipherType{CipherType_AES_128_GCM, CipherType_AES_192_GCM, CipherType_AES_256_GCM, CipherType_CHACHA20_POLY1305, CipherType_XCHACHA20_POLY1305} {
		t.Run(method.String(), func(t *testing.T) {
			account, err := (&Account{CipherType: method, Password: "synthetic"}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			memory := account.(*MemoryAccount)
			var wire bytes.Buffer
			writer, err := memory.Cipher.NewEncryptionWriter(memory.Key, make([]byte, memory.Cipher.IVSize()), &wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, empty := range []buf.MultiBuffer{nil, {buf.New()}} {
				if err := buf.CopyOnceTimeout(initialBufferReader{empty}, initialPayloadWriter{writer}, time.Second); err != nil || wire.Len() != 0 {
					t.Fatal("empty initial payload emitted an AEAD end marker", err)
				}
			}
			body := buf.New()
			body.WriteString("application bytes")
			if err := buf.CopyOnceTimeout(initialBufferReader{buf.MultiBuffer{body}}, initialPayloadWriter{writer}, time.Second); err != nil {
				t.Fatal(err)
			}
			reader, err := memory.Cipher.NewDecryptionReader(memory.Key, make([]byte, memory.Cipher.IVSize()), &wire)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
			if err != nil || string(plain) != "application bytes" {
				t.Fatal("real initial application payload changed", err)
			}
		})
	}
}
