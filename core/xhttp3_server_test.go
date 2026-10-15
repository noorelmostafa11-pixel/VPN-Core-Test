package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestXHTTP3ServerProtocolsModesTCPUDPAndClose(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up", "auto"} {
		for _, protocol := range []string{"vless", "vmess", "trojan", "ss"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				cfg, server := carrierServerFixture(t, protocol, "xhttp", true, 0, mode, "h3")
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				target := echoPeer(t)
				for cycle := 0; cycle < 4; cycle++ {
					conn, err := client.DialContext(client.ctx, "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					body := bytes.Repeat([]byte{byte(71 + cycle)}, 200001)
					if _, err := conn.Write(body); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(body))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(body, got) {
						t.Fatal("HTTP3 protocol payload", err)
					}
					conn.Close()
				}
				if protocol != "ss" {
					host, port, _ := splitProtocolTarget(udpEchoPeer(t))
					packets, err := client.dialPacket(client.ctx, host, port)
					if err != nil {
						t.Fatal(err)
					}
					checkHysteriaUDP(t, packets)
					packets.Close()
				}
				client.Close()
				server.Close()
				if client.Stats().Active != 0 || server.Stats().Active != 0 {
					t.Fatal("HTTP3 retained owner admission")
				}
			})
		}
	}
}

func TestXHTTP3HeadersAdmissionTimeoutAndIncompleteUniJoin(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	cfg.MaxConnections, cfg.ConnectTimeout = 3, 400*time.Millisecond
	server, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	cert, key := testServerCertificate(t)
	addr, err := server.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, CertFile: cert, KeyFile: key, Transport: &ServerTransportConfig{Type: "xhttp", HTTPVersion: "h3"}})
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := os.ReadFile(cert)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr.String(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	var streams []*quic.Stream
	for i := 0; i < 3; i++ {
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// A partial HEADERS frame stalls before any application handler.
		stream.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := stream.Write([]byte{1, 10, 0}); err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
	}
	var b [1]byte
	_, err = streams[2].Read(b[:])
	var reset *quic.StreamError
	if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(http3.ErrCodeExcessiveLoad) {
		t.Fatal("pre-header request admission did not reject overload", err, server.Stats())
	}
	for _, stream := range streams[:2] {
		_, err := stream.Read(b[:])
		if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(http3.ErrCodeRequestIncomplete) {
			t.Fatal("incomplete HEADERS did not expire at setup timeout", err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for server.Stats().Active > 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.Stats().Active != 1 || conn.Context().Err() != nil {
		t.Fatal("header failures leaked admission or closed the reusable parent", server.Stats())
	}
	uni, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	uni.Write([]byte{0}) // Control-stream type, with an incomplete first frame.
	done := make(chan struct{})
	go func() { server.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP3 incomplete control/request workers retained the owner")
	}
	if server.Stats().Active != 0 {
		t.Fatal("HTTP3 owner retained admission")
	}
	for _, spec := range []ServerConfig{
		{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Transport: &ServerTransportConfig{Type: "xhttp", HTTPVersion: "h3"}},
		{Protocol: "ss", Listen: "127.0.0.1:0", Cipher: "aes-256-gcm", Password: "synthetic", CertFile: cert, KeyFile: key, Transport: &ServerTransportConfig{Type: "xhttp", HTTPVersion: "h3"}},
	} {
		if _, err := compileServer(spec); err == nil {
			t.Fatal("HTTP3 accepted missing TLS or colliding native SS UDP")
		}
	}
}
