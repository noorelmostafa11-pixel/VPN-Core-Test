package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"testing"
	"time"
)

// A destination-less, padded MUX header exercises all legal header sizes,
// including the short requests absent from the normal TCP client path.
func vmMuxTestHeader(cfg Config, padding int) (*protocol, []byte) {
	p := newProtocol(cfg, false)
	random := randomBytes(33)
	p.upIV, p.upKey, p.response = random[:16], random[16:32], random[32]
	p.downKey, p.downIV = shaBytes(p.upKey)[:16], shaBytes(p.upIV)[:16]
	p.upAEAD, _ = cipherAEAD("aes-128-gcm", p.upKey)
	header := join([]byte{1}, p.upIV, p.upKey, []byte{p.response, 1, byte(padding<<4) | 3, 0, 3}, randomBytes(padding))
	header = append(header, fnv32(header)...)
	command := md5Bytes(join(cfg.UUID[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")))
	auth := join(wide(uint64(time.Now().Unix())), randomBytes(4))
	auth = binary.BigEndian.AppendUint32(auth, crc32.ChecksumIEEE(auth))
	auth, _ = aesECB(vmessKDF(command, []byte("AES Auth ID Encryption"))[:16], auth, false)
	nonce := randomBytes(8)
	seal := func(label, ivlabel string, data []byte) []byte {
		a, _ := cipherAEAD("aes-128-gcm", vmessKDF(command, []byte(label), auth, nonce)[:16])
		return a.Seal(nil, vmessKDF(command, []byte(ivlabel), auth, nonce)[:12], data, auth)
	}
	return p, join(auth, seal("VMess Header AEAD Key_Length", "VMess Header AEAD Nonce_Length", word(len(header))), nonce,
		seal("VMess Header AEAD Key", "VMess Header AEAD Nonce", header))
}

func TestVMessMuxAllHeaderPaddingAndUDPFullCone(t *testing.T) {
	cfg, server := vmServerFixture(t, "aes-128-gcm", 0, false)
	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	a, _ := Address("127.0.0.1", first.LocalAddr().(*net.UDPAddr).Port)
	b, _ := Address("127.0.0.1", second.LocalAddr().(*net.UDPAddr).Port)
	for padding := 0; padding < 16; padding++ {
		raw, err := net.Dial("tcp", net.JoinHostPort(cfg.Host, itoa(cfg.Port)))
		if err != nil {
			t.Fatal(err)
		}
		p, header := vmMuxTestHeader(cfg, padding)
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		if err = writeAll(raw, header); err != nil {
			t.Fatal(err)
		}
		c := &protocolConn{Conn: raw, p: p}
		for i, address := range [][]byte{a, b} {
			status := byte(1)
			if i > 0 {
				status = 2
			}
			body := bytes.Repeat([]byte{byte(padding)}, 1400)
			wire, _ := encodeMuxFrame(muxFrame{id: 0, status: status, options: 1, network: 2, address: address, body: body})
			if err = writeAll(c, wire); err != nil {
				t.Fatal(err)
			}
			peer := first
			if i > 0 {
				peer = second
			}
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 2000)
			n, source, err := peer.ReadFromUDP(buf)
			if err != nil || !bytes.Equal(buf[:n], body) {
				t.Fatal("MUX upload", padding, i, err)
			}
			if i == 0 {
				// A different destination may send a reply through the same cone.
				if _, err = second.WriteToUDP(body, source); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = peer.WriteToUDP(body, source); err != nil {
					t.Fatal(err)
				}
			}
			got, err := readMuxFrame(c)
			if err != nil || got.id != 0 || got.status != 2 || !bytes.Equal(got.address, b) || !bytes.Equal(got.body, body) {
				t.Fatal("MUX download", padding, i, err)
			}
		}
		c.Close()
	}
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("MUX UDP leaked budget")
	}
}

func plainMuxTestPeer(t *testing.T, e *Engine) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	if !e.spawn(func() { defer close(done); e.serveMux(a) }) {
		t.Fatal("MUX owner stopped")
	}
	t.Cleanup(func() { b.Close(); e.Close(); <-done })
	b.SetDeadline(time.Now().Add(8 * time.Second))
	return b
}

func TestMuxConcurrentTCPBackpressureAndOwnerClose(t *testing.T) {
	e := testServerEngine(t)
	c := plainMuxTestPeer(t, e)
	h, port, _ := splitProtocolTarget(echoPeer(t))
	a, _ := Address(h, port)
	body := bytes.Repeat([]byte("multiplexed payload\x00\xff"), 16000)
	done := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(body); offset += 16000 {
			for id := 0; id < 8; id++ {
				f := muxFrame{id: uint16(id), status: 2, options: 1, body: body[offset:min(offset+16000, len(body))]}
				if offset == 0 {
					f.status, f.network, f.address = 1, 1, a
				}
				wire, _ := encodeMuxFrame(f)
				if err := writeAll(c, wire); err != nil {
					done <- err
					return
				}
			}
		}
		done <- nil
	}()
	got := make([][]byte, 8)
	count := 0
	for count < 8*len(body) {
		f, err := readMuxFrame(c)
		if err != nil || f.status != 2 || f.id >= 8 {
			t.Fatal("MUX TCP response", f.id, f.status, err)
		}
		got[f.id] = append(got[f.id], f.body...)
		count += len(f.body)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, data := range got {
		if !bytes.Equal(data, body) {
			t.Fatal("MUX TCP bytes corrupted")
		}
	}
	e.Close()
	if e.Stats().Active != 0 {
		t.Fatal("MUX TCP leaked budget")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("owner close left parent alive")
	}
}

func TestMuxAdmissionFailureIsolationAndMalformedFrames(t *testing.T) {
	e := testServerEngine(t)
	// Occupy the entire shared budget. The parent must answer End/Error, then
	// remain usable once slots become available rather than reconnecting it.
	for i := 0; i < e.config.MaxConnections; i++ {
		if !e.acquire() {
			t.Fatal("admission setup")
		}
	}
	c := plainMuxTestPeer(t, e)
	h, p, _ := splitProtocolTarget(echoPeer(t))
	a, _ := Address(h, p)
	f := muxFrame{id: 7, status: 1, network: 1, address: a, options: 1, body: []byte("accepted after limit")}
	wire, _ := encodeMuxFrame(f)
	if err := writeAll(c, wire); err != nil {
		t.Fatal(err)
	}
	reply, err := readMuxFrame(c)
	if err != nil || reply.status != 3 || reply.options != 2 {
		t.Fatal("MUX admission", err)
	}
	for i := 0; i < e.config.MaxConnections; i++ {
		e.release()
	}
	f.id++
	wire, _ = encodeMuxFrame(f)
	if err = writeAll(c, wire); err != nil {
		t.Fatal(err)
	}
	reply, err = readMuxFrame(c)
	if err != nil || reply.id != f.id || !bytes.Equal(reply.body, f.body) {
		t.Fatal("MUX isolation", err)
	}
	for _, invalid := range [][]byte{{0, 3, 0, 0, 1}, {2, 1}, {0, 4, 0, 0, 0, 0}, {0, 4, 0, 0, 2, 4}, {0, 4, 0, 0, 1, 0}, {0, 4, 0, 0, 2, 1, 255, 255}} {
		if _, err := readMuxFrame(bytes.NewReader(invalid)); err == nil {
			t.Fatal("invalid MUX accepted", invalid)
		}
	}
}

func TestMuxProtectionDenial(t *testing.T) {
	cfg, _ := ParseURI("direct://")
	e, err := NewEngine(context.Background(), cfg, Hooks{Protect: func(context.Context, int64) error { return io.ErrClosedPipe }})
	if err != nil {
		t.Fatal(err)
	}
	c := plainMuxTestPeer(t, e)
	h, p, _ := splitProtocolTarget(echoPeer(t))
	a, _ := Address(h, p)
	for _, network := range []byte{1, 2} {
		wire, _ := encodeMuxFrame(muxFrame{id: uint16(network), status: 1, options: 1, network: network, address: a, body: []byte("must fail")})
		if err := writeAll(c, wire); err != nil {
			t.Fatal(err)
		}
		f, err := readMuxFrame(c)
		if err != nil || f.status != 3 || f.options != 2 {
			t.Fatal("MUX protection failure", err, f)
		}
	}
}

func TestMuxParentIdleAndPartialFrameOwnerClose(t *testing.T) {
	for _, partial := range []bool{false, true} {
		e := testServerEngine(t)
		e.config.IdleTimeout = 100 * time.Millisecond
		c := plainMuxTestPeer(t, e)
		if partial {
			if err := writeAll(c, []byte{0, 100, 0}); err != nil {
				t.Fatal(err)
			}
			e.Close()
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("idle/owner kept MUX parent alive")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("client deadline masked failure to expire parent", err)
		}
	}
}
