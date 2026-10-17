package http

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	gonet "net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/reality"
	"golang.org/x/net/http2"
)

// A stdlib cryptographic oracle, independent of goreality.Server's intentionally
// absent ALPN. Authenticate the captured ClientHello and sign its ephemeral
// certificate using REALITY's HMAC, then actually negotiate h2 or HTTP/1.1.
func realityALPNCertificate(t *testing.T, raw gonet.Conn, config *reality.Config) ([]byte, gotls.Certificate, error) {
	t.Helper()
	var prefix, hello []byte
	for {
		if len(hello) >= 4 {
			length := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
			if len(hello) == 4+length {
				break
			}
			if len(hello) > 4+length {
				return nil, gotls.Certificate{}, errors.New("oracle unexpected trailing handshake")
			}
		}
		header := make([]byte, 5)
		if _, err := io.ReadFull(raw, header); err != nil {
			return nil, gotls.Certificate{}, err
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || size == 0 || size > 16384 || len(hello)+size > 65536 {
			return nil, gotls.Certificate{}, errors.New("oracle invalid TLS record")
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(raw, body); err != nil {
			return nil, gotls.Certificate{}, err
		}
		prefix = append(prefix, header...)
		prefix = append(prefix, body...)
		hello = append(hello, body...)
	}
	if len(hello) < 75 || hello[0] != 1 || hello[38] != 32 {
		return nil, gotls.Certificate{}, errors.New("oracle invalid ClientHello")
	}
	pos := 71
	pos += 2 + int(binary.BigEndian.Uint16(hello[pos:]))
	if pos >= len(hello) {
		return nil, gotls.Certificate{}, io.ErrUnexpectedEOF
	}
	pos += 1 + int(hello[pos])
	if pos+2 > len(hello) || int(binary.BigEndian.Uint16(hello[pos:])) != len(hello)-pos-2 {
		return nil, gotls.Certificate{}, io.ErrUnexpectedEOF
	}
	pos += 2
	var share []byte
	for pos+4 <= len(hello) {
		kind, size := binary.BigEndian.Uint16(hello[pos:]), int(binary.BigEndian.Uint16(hello[pos+2:]))
		pos += 4
		if size > len(hello)-pos {
			return nil, gotls.Certificate{}, io.ErrUnexpectedEOF
		}
		body := hello[pos : pos+size]
		pos += size
		if kind != 51 || len(body) < 2 {
			continue
		}
		for offset := 2; offset+4 <= len(body); {
			group, length := binary.BigEndian.Uint16(body[offset:]), int(binary.BigEndian.Uint16(body[offset+2:]))
			offset += 4
			if length > len(body)-offset {
				return nil, gotls.Certificate{}, io.ErrUnexpectedEOF
			}
			if group == 29 && length == 32 {
				share = body[offset : offset+length]
				break
			}
			if group == 4588 && length == 1216 && share == nil {
				share = body[offset+length-32 : offset+length]
			}
			offset += length
		}
	}
	private, err := ecdh.X25519().NewPrivateKey(config.PrivateKey)
	if err != nil {
		return nil, gotls.Certificate{}, err
	}
	public, err := ecdh.X25519().NewPublicKey(share)
	if err != nil {
		return nil, gotls.Certificate{}, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, gotls.Certificate{}, err
	}
	auth, err := hkdf.Key(sha256.New, shared, hello[6:26], "REALITY", 32)
	if err != nil {
		return nil, gotls.Certificate{}, err
	}
	aad := bytes.Clone(hello)
	clear(aad[39:71])
	block, _ := aes.NewCipher(auth)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, hello[26:38], hello[39:71], aad)
	if err != nil || len(plain) != 16 || !bytes.Equal(plain[8:], config.ShortIds[0]) || time.Since(time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)).Abs() > time.Minute {
		return nil, gotls.Certificate{}, errors.New("oracle REALITY authentication failed")
	}
	signerPublic, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, gotls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signerPublic, signer)
	if err != nil {
		return nil, gotls.Certificate{}, err
	}
	mac := hmac.New(sha512.New, auth)
	mac.Write(signerPublic)
	copy(der[len(der)-ed25519.SignatureSize:], mac.Sum(nil))
	return prefix, gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer}, nil
}

type replayHelloConn struct {
	gonet.Conn
	reader io.Reader
}

func (c *replayHelloConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func TestForkHTTP2RealityActuallyNegotiatedALPN(t *testing.T) {
	for _, protocol := range []string{"h2", "http/1.1"} {
		t.Run(protocol, func(t *testing.T) {
			f := localReality(t, true)
			listener, err := gonet.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var active gonet.Conn
			joined := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				defer close(joined)
				raw, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				mu.Lock()
				active = raw
				mu.Unlock()
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(8 * time.Second))
				prefix, certificate, err := realityALPNCertificate(t, raw, f.server)
				if err != nil {
					result <- err
					return
				}
				config := &gotls.Config{MinVersion: gotls.VersionTLS13, Certificates: []gotls.Certificate{certificate}, NextProtos: []string{protocol}, CurvePreferences: []gotls.CurveID{gotls.X25519}}
				config.GetConfigForClient = func(info *gotls.ClientHelloInfo) (*gotls.Config, error) {
					// Pinned REALITY uses Ed25519 independently of browser signature
					// advertisement. Match it only AFTER the oracle authenticates.
					info.SignatureSchemes[0] = gotls.Ed25519
					return nil, nil
				}
				secure := gotls.Server(&replayHelloConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(prefix), raw)}, config)
				if err := secure.Handshake(); err != nil {
					result <- err
					return
				}
				if secure.ConnectionState().NegotiatedProtocol != protocol {
					result <- errors.New("oracle did not actually negotiate requested ALPN")
					return
				}
				if protocol == "http/1.1" {
					n, err := secure.Read(make([]byte, 1))
					if n != 0 || err == nil {
						result <- errors.New("H2 client sent application data after non-H2 ALPN")
						return
					}
				} else {
					(&http2.Server{}).ServeConn(secure, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("authenticated-h2")) })})
				}
				result <- nil
			}()
			t.Cleanup(func() {
				listener.Close()
				mu.Lock()
				if active != nil {
					active.Close()
				}
				mu.Unlock()
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Error("REALITY ALPN oracle did not join")
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := Dial(ctx, net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*gonet.TCPAddr).Port)), f.settings(true))
			if protocol == "http/1.1" {
				if err == nil {
					conn.Close()
					t.Fatal("REALITY accepted actual HTTP/1.1 ALPN")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				data, err := io.ReadAll(conn)
				conn.Close()
				if err != nil || string(data) != "authenticated-h2" {
					t.Fatal("actual h2 ALPN failed", err)
				}
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("ALPN oracle did not finish")
			}
		})
	}
}
