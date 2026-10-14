package core

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func encryptionTestKeys(t *testing.T, kemLast bool, count int) (private, public []string) {
	t.Helper()
	for index := 0; index < count; index++ {
		var secret, pub []byte
		if kemLast && index == count-1 {
			key, err := mlkem.GenerateKey768()
			if err != nil {
				t.Fatal(err)
			}
			secret, pub = key.Bytes(), key.EncapsulationKey().Bytes()
		} else {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			secret, pub = key.Bytes(), key.PublicKey().Bytes()
		}
		private = append(private, base64.RawURLEncoding.EncodeToString(secret))
		public = append(public, base64.RawURLEncoding.EncodeToString(pub))
	}
	return
}

func encryptionServerFixture(t *testing.T, mode, rtt string, tlsOuter, visionFlow, kemLast bool, count int, hooks ...Hooks) (Config, *Engine) {
	t.Helper()
	private, public := encryptionTestKeys(t, kemLast, count)
	h := Hooks{}
	if len(hooks) != 0 {
		h = hooks[0]
	}
	base, _ := ParseURI("direct://")
	server, err := NewEngine(context.Background(), base, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Options: map[string]string{
		"decryption": "mlkem768x25519plus." + mode + ".60-60s.100-75-75." + strings.Join(private, ".")}}
	security := "none"
	if tlsOuter {
		spec.CertFile, spec.KeyFile = testServerCertificate(t)
		security = "tls"
	}
	flow := ""
	if visionFlow {
		flow = vlessVisionFlow
		spec.Options["flow"] = flow
	}
	a, err := server.StartServer(spec)
	if err != nil {
		t.Fatal(err)
	}
	encryption := "mlkem768x25519plus." + mode + "." + rtt + ".100-75-75." + strings.Join(public, ".")
	cfg, err := ParseURI("vless://" + visionServerTestUUID + "@" + a.String() + "?security=" + security + "&sni=127.0.0.1&fp=native&flow=" + flow + "&encryption=" + url.QueryEscape(encryption))
	if err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = spec.CertFile
	return cfg, server
}

func TestVLESSEncryptionServerModesKeysTCPUDPAndClose(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, variant := range []struct {
			rtt              string
			tls, vision, kem bool
			count            int
		}{
			{"1rtt", false, false, false, 1}, {"0rtt", false, false, true, 3},
			{"0rtt", true, true, false, 1}, {"0rtt", false, true, true, 2},
		} {
			t.Run(mode+"/"+variant.rtt+"/"+strings.Join([]string{boolText(variant.tls), boolText(variant.vision), boolText(variant.kem)}, "/"), func(t *testing.T) {
				cfg, server := encryptionServerFixture(t, mode, variant.rtt, variant.tls, variant.vision, variant.kem, variant.count)
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				target := echoPeer(t)
				for cycle := 0; cycle < 8; cycle++ {
					c, err := client.DialContext(client.ctx, "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					payloadCheck(t, c)
				}
				h, port, _ := splitProtocolTarget(udpEchoPeer(t))
				for cycle := 0; cycle < 4; cycle++ {
					p, err := client.dialPacket(client.ctx, h, port)
					if err != nil {
						t.Fatal(err)
					}
					checkHysteriaUDP(t, p)
					p.Close()
				}
				server.Close()
				client.Close()
				if server.Stats().Active != 0 || client.Stats().Active != 0 {
					t.Fatal("encryption owner retained admission")
				}
			})
		}
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestVLESSEncryptionVisionVerifiedInnerTLS(t *testing.T) {
	cert, key := testServerCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	root := x509.NewCertPool()
	pem, _ := os.ReadFile(cert)
	root.AppendCertsFromPEM(pem)
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, outer := range []bool{false, true} {
			t.Run(mode+"/outer="+boolText(outer), func(t *testing.T) {
				listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					for cycle := 0; cycle < 4; cycle++ {
						c, err := listener.Accept()
						if err != nil {
							return
						}
						c.SetDeadline(time.Now().Add(5 * time.Second))
						io.Copy(c, c)
						c.Close()
					}
				}()
				defer func() { listener.Close(); <-done }()
				cfg, server := encryptionServerFixture(t, mode, "0rtt", outer, true, false, 1)
				client, err := NewEngine(context.Background(), cfg, Hooks{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				for cycle := 0; cycle < 4; cycle++ {
					c, err := client.DialContext(client.ctx, "tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					inner := tls.Client(c, &tls.Config{RootCAs: root, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
					inner.SetDeadline(time.Now().Add(5 * time.Second))
					if err = inner.Handshake(); err != nil {
						inner.Close()
						t.Fatal(err)
					}
					body := bytes.Repeat([]byte{byte(cycle + 1)}, 200001)
					if err = writeAll(inner, body); err != nil {
						inner.Close()
						t.Fatal(err)
					}
					got := make([]byte, len(body))
					_, err = io.ReadFull(inner, got)
					inner.Close()
					if err != nil || !bytes.Equal(body, got) {
						t.Fatal("inner encrypted Vision payload", err)
					}
				}
				server.Close()
				client.Close()
				if server.Stats().Active != 0 {
					t.Fatal("encrypted Vision owner retained budget")
				}
			})
		}
	}
}

func TestVLESSEncryptionTicketBoundsReplayExpiryAndConcurrentAdmission(t *testing.T) {
	private, _ := encryptionTestKeys(t, false, 1)
	s, err := compileVLESSDecryption("mlkem768x25519plus.native.60-60s." + private[0])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pfs := bytes.Repeat([]byte{9}, 64)
	id, err := s.issueTicket(pfs, now)
	if err != nil {
		t.Fatal(err)
	}
	nfs := bytes.Repeat([]byte{1}, 32)
	var wg sync.WaitGroup
	admitted := make(chan []byte, 32)
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := s.resumeTicket(id[:], nfs, now); err == nil {
				admitted <- got
			}
		}()
	}
	wg.Wait()
	close(admitted)
	if len(admitted) != 1 {
		t.Fatal("ticket replay admitted more than once", len(admitted))
	}
	for got := range admitted {
		if !bytes.Equal(got, pfs) {
			t.Fatal("ticket secret corrupted")
		}
		got[0] = 0
	}
	for index := 1; index < 8192; index++ {
		binary.BigEndian.PutUint64(nfs, uint64(index+1))
		if _, err = s.resumeTicket(id[:], nfs, now); err != nil {
			t.Fatal(err)
		}
	}
	binary.BigEndian.PutUint64(nfs, 99999)
	if _, err = s.resumeTicket(id[:], nfs, now); err == nil {
		t.Fatal("live replay state evicted")
	}
	for len(s.tickets) < 1024 {
		if _, err = s.issueTicket(pfs, now); err != nil {
			t.Fatal(err)
		}
	}
	id2, err := s.issueTicket(pfs, now)
	if err != nil || binary.BigEndian.Uint16(id2[:2]) != 0 || len(s.tickets) != 1024 {
		t.Fatal("ticket capacity not bounded", err)
	}
	if _, err = s.resumeTicket(id[:], nfs, now.Add(61*time.Second)); err == nil {
		t.Fatal("expired ticket admitted")
	}
	if len(s.tickets) != 0 || len(s.replay) != 0 {
		t.Fatal("expired state retained")
	}
	if _, err = s.issueTicket(pfs, now.Add(61*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestVLESSEncryptionMalformedConfigAndProtection(t *testing.T) {
	private, _ := encryptionTestKeys(t, false, 1)
	for _, text := range []string{"", "none", "mlkem768x25519plus.native.0s", "mlkem768x25519plus.bad.0s." + private[0], "mlkem768x25519plus.native.65536s." + private[0], "mlkem768x25519plus.native.-1s." + private[0], "mlkem768x25519plus.native.20-10s." + private[0], "mlkem768x25519plus.native.0s.100-34-75." + private[0], "mlkem768x25519plus.native.0s." + strings.Join([]string{private[0], private[0]}, "."), "mlkem768x25519plus.native.0s." + private[0] + ".100-75-75"} {
		if _, err := compileVLESSDecryption(text); err == nil {
			t.Fatal("bad decryption accepted", text[:min(50, len(text))])
		}
	}
	cfg, server := encryptionServerFixture(t, "native", "1rtt", false, false, false, 1, Hooks{Protect: func(context.Context, int64) error { return errors.New("denied") }})
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c, err := client.DialContext(client.ctx, "tcp", echoPeer(t))
	if err == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("blocked"))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("protected server attempted unprotected route")
	}
	server.Close()
	client.Close()
	if server.Stats().Active != 0 {
		t.Fatal("protected owner retained budget")
	}
}

func TestVLESSEncryptionHandshakePaddingCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := encryptionSession{wire: a, paddingContext: ctx, deadline: time.Now().Add(time.Minute)}
	done := make(chan error, 1)
	go func() { done <- s.sendPadding(nil, []int{0}, []time.Duration{30 * time.Second}) }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled padding waiter retained")
	}
}

func TestVLESSEncryptionTicketsIsolatedBetweenListenersAndParallelPayloads(t *testing.T) {
	private, public := encryptionTestKeys(t, false, 1)
	server := testServerEngine(t)
	spec := ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Options: map[string]string{"decryption": "mlkem768x25519plus.native.60-60s.100-75-75." + private[0]}}
	var clients []*Engine
	for index := 0; index < 2; index++ {
		a, err := server.StartServer(spec)
		if err != nil {
			t.Fatal(err)
		}
		encryption := "mlkem768x25519plus.native.0rtt.100-75-75." + public[0]
		cfg, err := ParseURI("vless://" + visionServerTestUUID + "@" + a.String() + "?security=none&encryption=" + url.QueryEscape(encryption))
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewEngine(context.Background(), cfg, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		clients = append(clients, client)
		target := echoPeer(t)
		c, err := client.DialContext(client.ctx, "tcp", target)
		if err != nil {
			t.Fatal("ticket crossed listener", err)
		}
		payloadCheck(t, c)
		var wg sync.WaitGroup
		for worker := 0; worker < 16; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := client.DialContext(client.ctx, "tcp", target)
				if err != nil {
					t.Error(err)
					return
				}
				payloadCheck(t, c)
			}()
		}
		wg.Wait()
	}
	server.Close()
	for _, client := range clients {
		client.Close()
		if client.Stats().Active != 0 {
			t.Fatal("parallel client retained budget")
		}
	}
	if server.Stats().Active != 0 {
		t.Fatal("parallel server retained budget")
	}
}

func TestVLESSEncryptionAuthenticatedHelloRejectionAndOwnerLoss(t *testing.T) {
	private, public := encryptionTestKeys(t, false, 2)
	state, err := compileVLESSDecryption("mlkem768x25519plus.native.60-60s." + strings.Join(private, "."))
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := parseEncryption("mlkem768x25519plus.native.1rtt." + strings.Join(public, "."))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"commitment", "length_tag", "short_pfs"} {
		session := encryptionSession{config: clientCfg}
		iv, nfs, relays, err := session.clientPrefix()
		if err != nil {
			t.Fatal(err)
		}
		auth, _ := newRecordAEAD(iv, nfs)
		length, _ := auth.seal(encLength(1), nil)
		if bad == "commitment" {
			relays[32] ^= 1
		}
		if bad == "length_tag" {
			length[len(length)-1] ^= 1
		}
		a, b := net.Pipe()
		deadline := time.Now().Add(time.Second)
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
		done := make(chan error, 1)
		go func() {
			defer b.Close()
			_, err := state.handshake(context.Background(), b, deadline)
			done <- err
		}()
		writeAll(a, join(iv, relays, length))
		a.Close()
		if err := <-done; err == nil {
			t.Fatal("bad encrypted hello admitted", bad)
		}
	}
	cfg, server := encryptionServerFixture(t, "native", "1rtt", false, false, false, 1)
	c, err := net.Dial("tcp", net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	writeAll(c, []byte{1})
	deadline := time.Now().Add(time.Second)
	for server.Stats().Active == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { server.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owner loss did not wake encrypted handshake")
	}
	if server.Stats().Active != 0 {
		t.Fatal("incomplete handshake retained budget")
	}
}

func TestVLESSEncryptionRecordRekeyTamperAndHalfClose(t *testing.T) {
	for _, aes := range []bool{true, false} {
		t.Run("AES="+boolText(aes), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			key := bytes.Repeat([]byte{7}, 96)
			up, _ := encryptionAEAD([]byte("context"), key, aes)
			down, _ := encryptionAEAD([]byte("context"), key, aes)
			for i := range up.nonce {
				up.nonce[i] = 255
				down.nonce[i] = 255
			}
			writer := &vlessEncryptionConn{Conn: a, writeCipher: up, united: key, useAES: aes}
			reader := &vlessEncryptionConn{Conn: b, readCipher: down, united: key, useAES: aes}
			body := bytes.Repeat([]byte{9}, 20001)
			done := make(chan error, 1)
			go func() { _, err := writer.Write(body); done <- err }()
			got := make([]byte, len(body))
			if _, err := io.ReadFull(reader, got); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, body) || nonceFull(writer.writeCipher) || nonceFull(reader.readCipher) {
				t.Fatal("rekey payload corrupted")
			}
			if err := writer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte{1}); err != io.ErrClosedPipe {
				t.Fatal("half close permitted new write", err)
			}
		})
	}
	for _, bad := range []string{"header", "tag"} {
		a, b := net.Pipe()
		key := bytes.Repeat([]byte{4}, 32)
		up, _ := newRecordAEAD([]byte("tamper"), key)
		down, _ := newRecordAEAD([]byte("tamper"), key)
		header := []byte{23, 3, 3, 0, 19}
		wire, _ := up.seal([]byte{1, 2, 3}, header)
		if bad == "header" {
			header[0] = 22
		} else {
			wire[len(wire)-1] ^= 1
		}
		done := make(chan struct{})
		go func() { defer close(done); writeAll(a, join(header, wire)); a.Close() }()
		reader := &vlessEncryptionConn{Conn: b, readCipher: down}
		if _, err := reader.Read(make([]byte, 3)); err == nil {
			t.Fatal("tampered record accepted", bad)
		}
		b.Close()
		<-done
	}
}

func TestVLESSEncryptionServerNegotiatesChaChaResume(t *testing.T) {
	private, public := encryptionTestKeys(t, false, 1)
	s, err := compileVLESSDecryption("mlkem768x25519plus.random.60-60s." + private[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEncryption("mlkem768x25519plus.random.0rtt." + public[0])
	if err != nil {
		t.Fatal(err)
	}
	pfs := bytes.Repeat([]byte{7}, 64)
	ticket, err := s.issueTicket(pfs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	helper := encryptionSession{config: cfg}
	iv, nfs, relays, err := helper.clientPrefix()
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := encryptionAEAD(iv, nfs, false)
	length, _ := auth.seal(encLength(32), nil)
	ticketWire, _ := auth.seal(ticket[:], nil)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	deadline := time.Now().Add(3 * time.Second)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	done := make(chan error, 1)
	go func() {
		c, err := s.handshake(context.Background(), b, deadline)
		if err == nil {
			if c.useAES {
				err = errors.New("ChaCha hello selected AES")
			} else {
				body := make([]byte, 20001)
				_, err = io.ReadFull(c, body)
				if err == nil {
					err = writeAll(c, body)
				}
			}
		}
		done <- err
	}()
	if err = writeAll(a, join(iv, relays, length, ticketWire)); err != nil {
		t.Fatal(err)
	}
	random, err := readN(a, 16)
	if err != nil {
		t.Fatal(err)
	}
	united := join(pfs, nfs)
	up, _ := encryptionAEAD(ticketWire, united, false)
	down, _ := encryptionAEAD(random, united, false)
	in, _ := keyCTR(united, random)
	out, _ := keyCTR(united, iv)
	c := &vlessEncryptionConn{Conn: a, readCipher: down, writeCipher: up, inCTR: in, outCTR: out, united: united, useAES: false}
	body := bytes.Repeat([]byte{9}, 20001)
	if err = writeAll(c, body); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(body))
	if _, err = io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, got) {
		t.Fatal("negotiated ChaCha payload corrupted")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVLESSEncryptionDirectHeaderMasksEveryFragmentBoundary(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 96)
	iv := bytes.Repeat([]byte{7}, 16)
	plain := join([]byte{23, 3, 3, 0, 71}, bytes.Repeat([]byte{11}, 71), []byte{23, 3, 3, 0x23, 0x29}, bytes.Repeat([]byte{13}, 9001))
	for split := 1; split < 80; split++ {
		out, _ := keyCTR(key, iv)
		in, _ := keyCTR(key, iv)
		writeState, readState := encryptionHeaderMask{}, encryptionHeaderMask{}
		wire := append([]byte(nil), plain...)
		for offset := 0; offset < len(wire); {
			n := min(split, len(wire)-offset)
			if err := writeState.transform(wire[offset:offset+n], out, false); err != nil {
				t.Fatal(err)
			}
			offset += n
		}
		if bytes.Equal(wire[:5], plain[:5]) || !bytes.Equal(wire[5:76], plain[5:76]) {
			t.Fatal("header mask changed record body")
		}
		for offset := 0; offset < len(wire); {
			n := min(81-split, len(wire)-offset)
			if err := readState.transform(wire[offset:offset+n], in, true); err != nil {
				t.Fatal(err)
			}
			offset += n
		}
		if !bytes.Equal(wire, plain) || writeState.used != 0 || writeState.remaining != 0 || readState.used != 0 || readState.remaining != 0 {
			t.Fatal("fragmented mask lost record boundary", split)
		}
	}
}

func TestVLESSEncryptionVisionPeelsOnlyRecordLayer(t *testing.T) {
	for _, randomMode := range []bool{false, true} {
		t.Run("random="+boolText(randomMode), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			deadline := time.Now().Add(3 * time.Second)
			a.SetDeadline(deadline)
			b.SetDeadline(deadline)
			key := bytes.Repeat([]byte{3}, 96)
			up, _ := newRecordAEAD([]byte("direction"), key)
			down, _ := newRecordAEAD([]byte("direction"), key)
			out, _ := keyCTR(key, bytes.Repeat([]byte{1}, 16))
			in, _ := keyCTR(key, bytes.Repeat([]byte{1}, 16))
			peer := &vlessEncryptionConn{Conn: a, writeCipher: up, outCTR: out, united: key, randomMode: randomMode, useAES: true}
			incoming := &vlessEncryptionConn{Conn: b, readCipher: down, inCTR: in, united: key, randomMode: randomMode, useAES: true}
			if !randomMode {
				peer.outCTR = nil
				incoming.inCTR = nil
			}
			id, _ := uuidBytes(visionServerTestUUID)
			reader := newVisionServerConn(&directConn{Conn: incoming, raw: incoming.directTransport()}, id)
			reader.tls13.Store(true)
			first := join([]byte{23, 3, 3, 0, 71}, bytes.Repeat([]byte{7}, 71))
			second := join([]byte{23, 3, 3, 0x23, 0x29}, bytes.Repeat([]byte{9}, 9001))
			done := make(chan error, 1)
			go func() {
				err := writeAll(peer, reader.decoder.frame(2, first, true))
				if err == nil {
					err = writeAll(peer.directTransport(), second)
				}
				done <- err
			}()
			got := make([]byte, len(first)+len(second))
			if _, err := io.ReadFull(reader, got); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, join(first, second)) {
				t.Fatal("encrypted/direct tail or outer transport lost")
			}
		})
	}
}
