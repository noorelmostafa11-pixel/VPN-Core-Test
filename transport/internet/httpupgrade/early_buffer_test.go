package httpupgrade

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPUpgradePreservesBufferedApplicationBytes(t *testing.T) {
	client, raw := net.Pipe()
	defer client.Close()
	defer raw.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	// Headers and early bytes arrive in one read. The remaining tunnel data
	// exceeds the handshake byte limit, which must apply only to the header.
	prefix := bytes.Repeat([]byte{0x51}, 256)
	rest := bytes.Repeat([]byte{0, 255, 0x5a}, 20001)
	body := append(bytes.Clone(prefix), rest...)
	done := make(chan error, 1)
	go func() {
		conn, err := (&server{config: &Config{Path: "/edge"}}).upgrade(raw)
		if err != nil {
			done <- err
			return
		}
		got := make([]byte, len(body))
		_, err = io.ReadFull(conn, got)
		if err == nil && !bytes.Equal(got, body) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = conn.Write(got)
		}
		done <- err
	}()
	request := []byte("GET /edge HTTP/1.1\r\nHost: front.example.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if _, err := client.Write(append(request, prefix...)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != 101 {
		t.Fatal("upgrade response", err)
	}
	if _, err := client.Write(rest); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(body))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, body) {
		t.Fatal("early or post-limit application bytes lost", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPUpgradeClientReadAfterUnbufferedResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	server.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(server, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err == nil {
			_, err = server.Write([]byte("application"))
		}
		done <- err
	}()
	conn := &ConnRF{Conn: client, First: true}
	first := make([]byte, 1)
	if n, err := conn.Read(first); n != 1 || err != nil || first[0] != 'a' {
		t.Fatal("first application read returned no data", n, err)
	}
	rest := make([]byte, len("pplication"))
	if _, err := io.ReadFull(conn, rest); err != nil || string(rest) != "pplication" {
		t.Fatal("read-ahead bytes lost", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
