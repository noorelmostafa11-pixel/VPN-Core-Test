// Independent standard-library TLS server used only by ECH integration tests.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func echConfig(key []byte) []byte {
	name := []byte("public.test")
	body := []byte{42, 0, 32, 0, 32}
	body = append(body, key...)
	body = append(body, 0, 4, 0, 1, 0, 1, 64, byte(len(name)))
	body = append(body, name...)
	body = append(body, 0, 0)
	out := []byte{0xfe, 0x0d, byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func main() {
	certPath := flag.String("cert", "", "test certificate")
	keyPath := flag.String("key", "", "test private key")
	target := flag.String("target", "", "carrier oracle")
	retry := flag.Bool("retry", false, "require P256 HelloRetryRequest")
	reject := flag.Bool("reject", false, "disable ECH acceptance")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		panic(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	config := echConfig(key.PublicKey().Bytes())
	list := append([]byte{byte(len(config) >> 8), byte(len(config))}, config...)
	options := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	if *retry {
		options.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	if !*reject {
		options.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"port": listener.Addr().(*net.TCPAddr).Port, "ech": base64.StdEncoding.EncodeToString(list)})
	var accepted atomic.Int64
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
			conn := tls.Server(raw, options)
			if conn.Handshake() != nil {
				return
			}
			state := conn.ConnectionState()
			if !state.ECHAccepted || state.ServerName != "localhost" {
				return
			}
			accepted.Add(1)
			if *target != "" {
				remote, err := net.DialTimeout("tcp", *target, 3*time.Second)
				if err != nil {
					return
				}
				defer remote.Close()
				go func() { _, _ = io.Copy(remote, conn) }()
				_, _ = io.Copy(conn, remote)
				_ = conn.CloseWrite()
				return
			}
			request := make([]byte, 18)
			if _, err := io.ReadFull(conn, request); err != nil {
				return
			}
			id, _ := hex.DecodeString("12345678123445679234567812345678")
			if request[0] != 0 || !bytes.Equal(request[1:17], id) || request[17] != 0 {
				return
			}
			command := make([]byte, 4)
			if _, err := io.ReadFull(conn, command); err != nil || command[0] != 1 {
				return
			}
			n := 4
			if command[3] == 2 {
				var length [1]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				n = int(length[0])
			} else if command[3] == 3 {
				n = 16
			}
			host := make([]byte, n)
			if _, err := io.ReadFull(conn, host); err != nil {
				return
			}
			_, _ = conn.Write(append([]byte{0, 0}, []byte("SERVER-FIRST: independent peer\n")...))
			buffer := make([]byte, 16384)
			for {
				n, err := conn.Read(buffer)
				if n > 0 {
					offset := 0
					for offset < n {
						written, e := conn.Write(buffer[offset:n])
						if e != nil {
							return
						}
						offset += written
					}
				}
				if err != nil {
					_ = conn.CloseWrite()
					return
				}
			}
		}()
	}
}
