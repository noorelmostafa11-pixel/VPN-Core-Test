package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const vmServerTestID = "12345678-1234-4567-9234-567812345678"

func vmServerFixture(t *testing.T, method string, alter int, secure bool) (Config, *Engine) {
	t.Helper()
	server := testServerEngine(t)
	spec := ServerConfig{Protocol: "vmess", Listen: "127.0.0.1:0", UUIDs: []string{vmServerTestID}}
	if alter > 0 {
		spec.Options = map[string]string{"alter-id": itoa(alter)}
	}
	if secure {
		spec.CertFile, spec.KeyFile = testServerCertificate(t)
	}
	addr, err := server.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	query := "encryption=" + method + "&alterId=" + itoa(alter)
	if secure {
		query += "&security=tls"
	}
	cfg, err := ParseURI("vmess://" + vmServerTestID + "@" + addr.String() + "?" + query)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = spec.CertFile
	return cfg, server
}
func TestVMessServerMethodsTCPUDPAndRepeatedClose(t *testing.T) {
	for _, alter := range []int{0, 2} {
		for _, method := range []string{"aes-128-gcm", "chacha20-poly1305", "aes-128-cfb", "none", "zero"} {
			t.Run(method+"/"+itoa(alter), func(t *testing.T) {
				cfg, server := vmServerFixture(t, method, alter, false)
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				target := echoPeer(t)
				for cycle := 0; cycle < 16; cycle++ {
					conn, err := client.DialContext(context.Background(), "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					payloadCheck(t, conn)
				}
				h, p, _ := splitProtocolTarget(udpEchoPeer(t))
				for cycle := 0; cycle < 3; cycle++ {
					s, err := client.dialPacket(client.ctx, h, p)
					if err != nil {
						t.Fatal(err)
					}
					s.SetDeadline(time.Now().Add(5 * time.Second))
					for _, size := range []int{1, 1400, 32000, 60000} {
						body := bytes.Repeat([]byte{31}, size)
						if err = s.WritePacket(body); err != nil {
							t.Fatal(err)
						}
						got, err := s.ReadPacket()
						if err != nil || !bytes.Equal(body, got.Payload) {
							t.Fatal("UDP", size, err)
						}
					}
					s.Close()
				}
				live, err := client.DialContext(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				defer live.Close()
				writeAll(live, []byte("owner"))
				live.SetReadDeadline(time.Now().Add(time.Second))
				if _, err = io.ReadFull(live, make([]byte, 5)); err != nil {
					t.Fatal(err)
				}
				server.Close()
				if _, err = live.Read(make([]byte, 1)); err == nil {
					t.Fatal("owner loss ignored")
				}
				client.Close()
				if server.Stats().Active != 0 || client.Stats().Active != 0 {
					t.Fatal("leaked flows")
				}
			})
		}
	}
}
func TestVMessServerTLSConcurrentPayload(t *testing.T) {
	cfg, _ := vmServerFixture(t, "aes-128-gcm", 0, true)
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := echoPeer(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := client.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			body := bytes.Repeat([]byte("large TLS payload"), 12000)
			if err = writeAll(c, body); err != nil {
				t.Error(err)
				return
			}
			got := make([]byte, len(body))
			if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, body) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
func TestVMessServerHeaderAuthenticationReplayAndMalformed(t *testing.T) {
	auth, err := newVMServerAuth(ServerConfig{Protocol: "vmess", UUIDs: []string{vmServerTestID}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := ParseURI("vmess://" + vmServerTestID + "@127.0.0.1:443?encryption=aes-128-gcm")
	address, _ := Address("target.test", 443)
	proto := newProtocol(cfg, false)
	wire, err := proto.open(address)
	if err != nil {
		t.Fatal(err)
	}
	parse := func(wire []byte) error {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { defer server.Close(); _, _, _, err := vmServerHeader(server, auth); done <- err }()
		client.SetDeadline(time.Now().Add(time.Second))
		writeAll(client, wire)
		client.Close()
		return <-done
	}
	if err = parse(wire); err != nil {
		t.Fatal(err)
	}
	if err = parse(wire); err == nil || !strings.Contains(err.Error(), "REPLAY") {
		t.Fatal("replay accepted", err)
	}
	for _, mode := range []string{"auth", "length", "header"} {
		p := newProtocol(cfg, false)
		bad, _ := p.open(address)
		switch mode {
		case "auth":
			bad[0] ^= 1
		case "length":
			bad[17] ^= 1
		case "header":
			bad[len(bad)-1] ^= 1
		}
		if err = parse(bad); err == nil {
			t.Fatal("malformed accepted", mode)
		}
	}
	if err := auth.replay([]byte("capacity")); err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.replays = map[[32]byte]time.Time{}
	for i := 0; i < 8192; i++ {
		var id [32]byte
		binary.BigEndian.PutUint32(id[:], uint32(i))
		auth.replays[id] = time.Now().Add(time.Minute)
	}
	auth.mu.Unlock()
	if err := auth.replay([]byte("new identity")); err == nil {
		t.Fatal("unbounded replay cache")
	}
}
func TestVMessServerAuthenticationAndProtectionFailures(t *testing.T) {
	for _, mode := range []string{"auth", "protect"} {
		t.Run(mode, func(t *testing.T) {
			base, _ := ParseURI("direct://")
			hooks := Hooks{}
			if mode == "protect" {
				hooks.Protect = func(context.Context, int64) error { return errors.New("denied") }
			}
			server, err := NewEngine(context.Background(), base, hooks)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			addr, err := server.StartServer(ServerConfig{Protocol: "vmess", Listen: "127.0.0.1:0", UUIDs: []string{vmServerTestID}})
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := ParseURI("vmess://" + vmServerTestID + "@" + addr.String() + "?encryption=aes-128-gcm")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "auth" {
				cfg.UUID[0] ^= 1
			}
			h, p, _ := splitProtocolTarget(echoPeer(t))
			c, err := Dial(context.Background(), cfg, h, p)
			if err == nil {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				err = writeAll(c, []byte("must not relay"))
				if err == nil {
					_, err = c.Read(make([]byte, 1))
				}
			}
			if err == nil {
				t.Fatal("rejection relayed payload")
			}
		})
	}
}
func TestVMessServerValidation(t *testing.T) {
	for _, options := range []map[string]string{{"alter-id": "65"}, {"unknown": "1"}, {"alter-id": "-1"}} {
		if _, err := newVMServerAuth(ServerConfig{Protocol: "vmess", UUIDs: []string{vmServerTestID}, Options: options}); err == nil {
			t.Fatal("invalid options")
		}
	}
	if _, err := newVMServerAuth(ServerConfig{Protocol: "vmess", UUIDs: []string{vmServerTestID, vmServerTestID}}); err == nil {
		t.Fatal("duplicate user")
	}
}

func TestVMessServerTimestampBodyIntegrityAndNonceLimit(t *testing.T) {
	a, _ := newVMServerAuth(ServerConfig{Protocol: "vmess", UUIDs: []string{vmServerTestID}})
	// Leave a few seconds beyond the boundary so a second rollover during
	// scheduling cannot turn the future rejection into a valid timestamp.
	for _, age := range []int64{-125, 125} {
		plain := join(wide(uint64(time.Now().Unix()+age)), []byte{1, 2, 3, 4})
		plain = binary.BigEndian.AppendUint32(plain, crc32.ChecksumIEEE(plain))
		var id [16]byte
		a.users[0].auth.Encrypt(id[:], plain)
		if _, _, _, err := a.identify(id); err == nil {
			t.Fatal("stale/future VMess auth accepted")
		}
	}
	key, iv := randomBytes(16), randomBytes(16)
	for _, security := range []byte{1, 3, 4, 5} {
		for _, options := range []byte{1, 5, 13, 29} {
			if options&16 != 0 && security != 3 && security != 4 {
				continue
			}
			var wire bytes.Buffer
			out, err := newVMServerBody(&wire, key, iv, key, iv, options, security, true)
			if err != nil {
				t.Fatal(err)
			}
			in, err := newVMServerBody(&wire, key, iv, key, iv, options, security, false)
			if err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte("boundaries"), 1500)
			if err := out.write(body); err != nil {
				t.Fatal(err)
			}
			got, err := in.read()
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("VMess body", security, options, err)
			}
			if err := out.write(nil); err != nil {
				t.Fatal(err)
			}
			if _, err := in.read(); err != io.EOF {
				t.Fatal("VMess EOF not verified", err)
			}
			if security == 3 || security == 4 {
				out.sequence, in.sequence = 65536, 65536
				if err := out.write(body); err == nil {
					t.Fatal("VMess write nonce reused")
				}
				if _, err := in.read(); err == nil {
					t.Fatal("VMess read nonce reused")
				}
			}
		}
	}
	for _, security := range []byte{1, 3, 4} {
		var wire bytes.Buffer
		out, _ := newVMServerBody(&wire, key, iv, key, iv, 1, security, true)
		out.write([]byte("authenticated body"))
		data := wire.Bytes()
		data[len(data)-1] ^= 1
		in, _ := newVMServerBody(&wire, key, iv, key, iv, 1, security, false)
		if _, err := in.read(); err == nil {
			t.Fatal("corrupt VMess body accepted", security)
		}
	}
}
