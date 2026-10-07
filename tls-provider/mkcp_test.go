package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Independent segment encoder. Invalid authenticated packets and a terminal
// command arriving before its final data must not deliver bytes or early EOF.
func TestMKCPAuthenticationConversationAndOrderedEOF(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	seed := "synthetic-negative-seed"
	raw, err := dialMKCP(context.Background(), peer.LocalAddr().String(), kcpOptions{Seed: &seed, TTI: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := raw
	key := sha256.Sum256([]byte(seed))
	block, _ := aes.NewCipher(key[:16])
	aead, _ := cipher.NewGCM(block)
	send := func(conv uint16, cmd byte, body []byte, corrupt bool) {
		packet := make([]byte, 4)
		binary.BigEndian.PutUint16(packet, conv)
		packet[2] = cmd
		packet = append(packet, body...)
		nonce := make([]byte, aead.NonceSize())
		_, _ = rand.Read(nonce)
		wire := aead.Seal(nonce, nonce, packet, nil)
		if corrupt {
			wire[len(wire)-1] ^= 1
		}
		if _, err := peer.WriteTo(wire, c.socket.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	result := make(chan string, 1)
	go func() {
		b := make([]byte, 32)
		n, e := c.Read(b)
		if e != nil {
			result <- "ERROR " + e.Error()
		} else {
			result <- string(b[:n])
		}
	}()
	terminal := make([]byte, 12)
	binary.BigEndian.PutUint32(terminal, 1)
	send(c.conv, 2, terminal, false)
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[12:], 5)
	data = append(data, []byte("hello")...)
	send(c.conv^1, 1, data, false)
	send(c.conv, 1, data, true)
	select {
	case got := <-result:
		t.Fatalf("early result: %s", got)
	case <-time.After(40 * time.Millisecond):
	}
	send(c.conv, 1, data, false)
	select {
	case got := <-result:
		if got != "hello" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("valid packet lost")
	}
	b := make([]byte, 1)
	if n, e := c.Read(b); n != 0 || !errors.Is(e, io.EOF) {
		t.Fatalf("terminal result: %d %v", n, e)
	}
}

func TestMKCPReadDeadline(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, err := dialMKCP(context.Background(), peer.LocalAddr().String(), kcpOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err = c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}
