// Independent QUIC stream server, forwarding to the Python protocol oracle.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

type fixtureConfig struct{ Target, Cert, Key, Cipher, Secret, Header string }
type fixturePackets struct {
	net.PacketConn
	auth   cipher.AEAD
	header string
	mu     sync.Mutex
}

func (p *fixturePackets) SetReadBuffer(n int) error {
	return p.PacketConn.(*net.UDPConn).SetReadBuffer(n)
}
func (p *fixturePackets) SetWriteBuffer(n int) error {
	return p.PacketConn.(*net.UDPConn).SetWriteBuffer(n)
}
func (p *fixturePackets) SyscallConn() (syscall.RawConn, error) {
	return p.PacketConn.(*net.UDPConn).SyscallConn()
}
func (p *fixturePackets) ReadFrom(out []byte) (int, net.Addr, error) {
	b := make([]byte, 65536)
	for {
		n, address, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		data := b[:n]
		if p.header == "srtp" {
			if len(data) < 4 || data[0] != 0xb5 || data[1] != 0xe8 {
				continue
			}
			data = data[4:]
		}
		if p.auth != nil {
			size := p.auth.NonceSize()
			if len(data) < size+16 {
				continue
			}
			data, err = p.auth.Open(nil, data[:size], data[size:], nil)
			if err != nil {
				continue
			}
		}
		return copy(out, data), address, nil
	}
}
func (p *fixturePackets) WriteTo(data []byte, address net.Addr) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	packet := data
	if p.auth != nil {
		nonce := make([]byte, p.auth.NonceSize())
		_, _ = rand.Read(nonce)
		packet = p.auth.Seal(nonce, nonce, data, nil)
	}
	if p.header == "srtp" {
		packet = append([]byte{0xb5, 0xe8, 0, 7}, packet...)
	}
	_, err := p.PacketConn.WriteTo(packet, address)
	return len(data), err
}
func main() {
	path := flag.String("config", "", "fixture config")
	flag.Parse()
	data, err := os.ReadFile(*path)
	if err != nil {
		panic(err)
	}
	var cfg fixtureConfig
	if json.Unmarshal(data, &cfg) != nil {
		panic("fixture config")
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		panic(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	p := &fixturePackets{PacketConn: udp, header: cfg.Header}
	key := sha256.Sum256([]byte(cfg.Secret + "xray-quic-salt"))
	if cfg.Cipher == "aes-128-gcm" {
		block, _ := aes.NewCipher(key[:16])
		p.auth, _ = cipher.NewGCM(block)
	}
	if cfg.Cipher == "chacha20-poly1305" {
		p.auth, _ = chacha20poly1305.New(key[:])
	}
	server, err := quic.Listen(p, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13}, &quic.Config{})
	if err != nil {
		panic(err)
	}
	fmt.Println(udp.LocalAddr().String())
	for {
		conn, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer conn.CloseWithError(0, "")
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					target, err := net.Dial("tcp", cfg.Target)
					if err != nil {
						stream.CancelRead(1)
						stream.CancelWrite(1)
						return
					}
					defer target.Close()
					go func() { _, _ = io.Copy(target, stream); _ = target.(*net.TCPConn).CloseWrite() }()
					_, _ = io.Copy(stream, target)
					_ = stream.Close()
				}()
			}
		}()
	}
}
