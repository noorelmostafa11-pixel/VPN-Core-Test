package udp_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/testing/servers/udp"
)

func TestForkUDPCloseJoinsReader(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		for range 16 {
			server := &udp.Server{MsgProcessor: func(msg []byte) []byte { return msg }}
			dest, err := server.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			if exchange {
				conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)})
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				body := bytes.Repeat([]byte{0x5a}, 1024)
				if _, err := conn.Write(body); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				reply := make([]byte, 2048)
				n, err := conn.Read(reply)
				conn.Close()
				if err != nil || !bytes.Equal(reply[:n], body) {
					t.Fatal("fixture echo changed", err)
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- server.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("fixture reader did not join on Close")
			}
		}
	}
}
