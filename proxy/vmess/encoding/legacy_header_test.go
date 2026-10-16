package encoding

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"testing"
	"testing/iotest"
	"time"

	"github.com/xtls/xray-core/common/bitmask"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessaead "github.com/xtls/xray-core/proxy/vmess/aead"
)

func headerUser(t *testing.T, alter uint32, body bool) *protocol.MemoryUser {
	t.Helper()
	a, err := (&vmess.Account{Id: "00000000-0000-4000-8000-000000000001", AlterId: alter, AllowLegacyBody: body}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: "test", Account: a}
}

func headerServer(t *testing.T, user *protocol.MemoryUser) (*vmess.TimedUserValidator, *SessionHistory) {
	t.Helper()
	v := vmess.NewTimedUserValidator()
	if err := v.Add(user); err != nil {
		t.Fatal(err)
	}
	h := NewSessionHistory()
	t.Cleanup(func() { h.Close() })
	return v, h
}

// Independent standard-library wire oracle: no fork header/ID/CFB helpers.
func oracleAlterID(user *protocol.MemoryUser, count int) []byte {
	id := append([]byte(nil), user.Account.(*vmess.MemoryAccount).ID.Bytes()...)
	for range count {
		next := md5.Sum(append(id, []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81")...))
		id = append([]byte(nil), next[:]...)
	}
	return id
}

func oracleLegacyWire(user *protocol.MemoryUser, stamp int64, selection int, plain []byte) []byte {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(stamp))
	h := hmac.New(md5.New, oracleAlterID(user, selection))
	h.Write(timestamp[:])
	command := md5.Sum(append(append([]byte(nil), user.Account.(*vmess.MemoryAccount).ID.Bytes()...), []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	iv := md5.Sum(bytes.Repeat(timestamp[:], 4))
	block, _ := aes.NewCipher(command[:])
	wire := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(wire, plain)
	return append(h.Sum(nil), wire...)
}

func oraclePlain(key, iv []byte, security byte, option byte, command byte) []byte {
	plain := append([]byte{1}, iv...)
	plain = append(plain, key...)
	plain = append(plain, 0x7d, option, security, 0, command)
	if command != 3 {
		plain = append(plain, 1, 0xbb, 1, 127, 0, 0, 1)
	}
	return oracleChecksum(plain)
}

func oracleChecksum(plain []byte) []byte {
	sum := fnv.New32a()
	sum.Write(plain)
	return append(plain, sum.Sum(nil)...)
}

func TestForkVMessLegacyHeaderIndependentWire(t *testing.T) {
	u := headerUser(t, 64, true)
	for _, selection := range []int{0, 1, 16, 64} {
		v, h := headerServer(t, u)
		plain := oraclePlain(legacyKey, legacyIV, 3, 1, 1)
		wire := oracleLegacyWire(u, time.Now().Unix(), selection, plain)
		s := NewServerSession(v, h)
		request, err := s.DecodeRequestHeader(iotest.OneByteReader(bytes.NewReader(wire)), false)
		if err != nil || request.Port != 443 || request.Address.String() != "127.0.0.1" || !s.legacyHeader || !bytes.Equal(s.requestBodyKey[:], legacyKey) {
			t.Fatal("independent legacy frame rejected", selection, err)
		}
	}
	// Decode the actual client wire independently, including its random padding.
	c := NewClientSessionWithAccount(context.Background(), 0, u.Account.(*vmess.MemoryAccount))
	request := &protocol.RequestHeader{User: u, Security: protocol.SecurityType_AES128_GCM, Option: 1, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 443}
	var wire bytes.Buffer
	before := time.Now().Unix()
	if err := c.EncodeRequestHeader(request, &wire); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()
	matched := false
	for stamp := before; stamp <= after; stamp++ {
		for selection := 1; selection <= 64; selection++ {
			candidate := oracleLegacyWire(u, stamp, selection, nil)
			if !bytes.Equal(wire.Bytes()[:16], candidate) {
				continue
			}
			var ts [8]byte
			binary.BigEndian.PutUint64(ts[:], uint64(stamp))
			iv := md5.Sum(bytes.Repeat(ts[:], 4))
			command := md5.Sum(append(append([]byte(nil), u.Account.(*vmess.MemoryAccount).ID.Bytes()...), []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
			block, _ := aes.NewCipher(command[:])
			plain := make([]byte, wire.Len()-16)
			cipher.NewCFBDecrypter(block, iv[:]).XORKeyStream(plain, wire.Bytes()[16:])
			if len(plain) != 49+int(plain[35]>>4) || !bytes.Equal(plain[1:17], c.requestBodyIV[:]) || !bytes.Equal(plain[17:33], c.requestBodyKey[:]) || plain[0] != 1 || plain[34] != 1 || plain[35]&15 != 3 || !bytes.Equal(plain[38:45], []byte{1, 0xbb, 1, 127, 0, 0, 1}) || !bytes.Equal(oracleChecksum(append([]byte(nil), plain[:len(plain)-4]...)), plain) {
				t.Fatal("client wire differs from independent plaintext/checksum oracle")
			}
			matched = true
		}
	}
	if !matched || c.responseBodyKey != md5.Sum(c.requestBodyKey[:]) || c.responseBodyIV != md5.Sum(c.requestBodyIV[:]) {
		t.Fatal("legacy selection or response derivation mismatch")
	}
}

func TestForkVMessLegacyHeaderGuardsAndReplay(t *testing.T) {
	u := headerUser(t, 16, true)
	v, h := headerServer(t, u)
	stamp := time.Now().Unix()
	plain := oraclePlain(legacyKey, legacyIV, 3, 1, 1)
	wire := oracleLegacyWire(u, stamp, 16, plain)
	for cut := 0; cut < len(wire); cut++ {
		if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(wire[:cut]), false); err == nil {
			t.Fatal("truncated request accepted", cut)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"version":          func(p []byte) { p[0] = 2 },
		"reserved":         func(p []byte) { p[36] = 1 },
		"command":          func(p []byte) { p[37] = 4 },
		"option":           func(p []byte) { p[34] = 0x80 },
		"padding":          func(p []byte) { p[34] = 9 },
		"unframed-gcm":     func(p []byte) { p[34] = 0 },
		"unknown-security": func(p []byte) { p[35] = 15 },
		"wire-zero":        func(p []byte) { p[35] = 6 },
		"address":          func(p []byte) { p[40] = 15 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte(nil), plain[:len(plain)-4]...)
			mutate(bad)
			bad = oracleChecksum(bad)
			if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(oracleLegacyWire(u, stamp, 16, bad)), false); err == nil {
				t.Fatal("malformed authenticated header accepted")
			}
		})
	}
	bad := append([]byte(nil), plain...)
	bad[len(bad)-1] ^= 1
	if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(oracleLegacyWire(u, stamp, 16, bad)), false); err == nil {
		t.Fatal("bad checksum accepted")
	}
	if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(wire), false); err != nil {
		t.Fatal("malformed attempts poisoned valid session", err)
	}
	if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(wire), false); err == nil {
		t.Fatal("legacy replay accepted")
	}
	// The same HMAC timestamp must allow a different, valid connection key.
	key := append([]byte(nil), legacyKey...)
	key[0]++
	second := oracleLegacyWire(u, stamp, 16, oraclePlain(key, legacyIV, 3, 1, 1))
	if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(second), false); err != nil {
		t.Fatal("legitimate concurrent timestamp rejected", err)
	}
	for _, target := range []*protocol.MemoryUser{headerUser(t, 0, true), headerUser(t, 1, true)} {
		validator, history := headerServer(t, target)
		if _, err := NewServerSession(validator, history).DecodeRequestHeader(bytes.NewReader(wire), false); err == nil {
			t.Fatal("legacy header accepted without matching alter IDs")
		}
	}
	validator, history := headerServer(t, headerUser(t, 16, false))
	cfb := oracleLegacyWire(u, stamp, 16, oraclePlain(legacyKey, legacyIV, 1, 1, 1))
	if _, err := NewServerSession(validator, history).DecodeRequestHeader(bytes.NewReader(cfb), false); err == nil {
		t.Fatal("header opt-in bypassed body opt-in")
	}
	// Enabling legacy support must not turn a replayed modern AuthID into a fallback.
	c := NewClientSession(context.Background(), 0)
	modern := headerUser(t, 0, false)
	var aead bytes.Buffer
	if err := c.EncodeRequestHeader(&protocol.RequestHeader{User: modern, Security: protocol.SecurityType_AES128_GCM, Option: 1, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 443}, &aead); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), aead.Bytes()...)
	if _, err := NewServerSession(v, h).DecodeRequestHeader(&aead, false); err != nil {
		t.Fatal("modern header rejected on mixed user", err)
	}
	if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(first), false); err == nil {
		t.Fatal("modern replay bypassed through legacy fallback")
	}
	for _, stamp := range []int64{-1, time.Now().Unix() - 300, time.Now().Unix() + 300} {
		auth := vmessaead.CreateAuthID(u.Account.(*vmess.MemoryAccount).ID.CmdKey(), stamp)
		if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(auth[:]), false); err == nil {
			t.Fatal("invalid modern timestamp bypassed", stamp)
		}
	}
	// Tampering after a valid modern AuthID must not invoke legacy parsing.
	var damaged bytes.Buffer
	fresh := NewClientSession(context.Background(), 0)
	if err := fresh.EncodeRequestHeader(&protocol.RequestHeader{User: modern, Security: protocol.SecurityType_AES128_GCM, Option: 1, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 443}, &damaged); err != nil {
		t.Fatal(err)
	}
	corrupted := append([]byte(nil), damaged.Bytes()...)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(corrupted), false); err == nil {
		t.Fatal("modern header authentication bypassed")
	}
	// Session mode is immutable: callers cannot switch a modern session to legacy
	// in EncodeRequestHeader while another task is already reading a response.
	if err := NewClientSession(context.Background(), 0).EncodeRequestHeader(&protocol.RequestHeader{User: u, Security: protocol.SecurityType_AES128_GCM}, io.Discard); err == nil {
		t.Fatal("late legacy mode switch accepted")
	}
}

func TestForkVMessLegacyHeaderBodyMatrix(t *testing.T) {
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE, protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305} {
		optionSet := []bitmask.Byte{1, 5, 13}
		if security == protocol.SecurityType_AES128_GCM || security == protocol.SecurityType_CHACHA20_POLY1305 {
			optionSet = append(optionSet, 17, 21, 29)
		}
		for _, options := range optionSet {
			for _, command := range []protocol.RequestCommand{protocol.RequestCommandTCP, protocol.RequestCommandUDP, protocol.RequestCommandMux} {
				t.Run(fmt.Sprintf("%d/%d/%d", security, options, command), func(t *testing.T) {
					u := headerUser(t, 16, true)
					v, h := headerServer(t, u)
					c := NewClientSessionWithAccount(context.Background(), 0, u.Account.(*vmess.MemoryAccount))
					request := &protocol.RequestHeader{User: u, Security: security, Option: options, Command: command, Address: net.LocalHostIP, Port: 443}
					var up, down bytes.Buffer
					if err := c.EncodeRequestHeader(request, &up); err != nil {
						t.Fatal(err)
					}
					s := NewServerSession(v, h)
					decoded, err := s.DecodeRequestHeader(&up, false)
					if err != nil {
						t.Fatal(err)
					}
					s.EncodeResponseHeader(&protocol.ResponseHeader{}, &down)
					if _, err := c.DecodeResponseHeader(&down); err != nil {
						t.Fatal(err)
					}
					uw, err := c.EncodeRequestBody(request, &up)
					if err != nil {
						t.Fatal(err)
					}
					dw, err := s.EncodeResponseBody(decoded, &down)
					if err != nil {
						t.Fatal(err)
					}
					ur, err := s.DecodeRequestBody(decoded, &up)
					if err != nil {
						t.Fatal(err)
					}
					dr, err := c.DecodeResponseBody(request, &down)
					if err != nil {
						t.Fatal(err)
					}
					packets := [][]byte{bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)}
					if command == protocol.RequestCommandUDP {
						packets = [][]byte{[]byte("a"), bytes.Repeat([]byte{0xff}, 1400), bytes.Repeat([]byte{0x55}, 3800)}
					}
					for _, writer := range []buf.Writer{uw, dw} {
						for _, packet := range packets {
							writeLegacyBody(t, writer, packet)
						}
						if err := writer.WriteMultiBuffer(nil); err != nil {
							t.Fatal(err)
						}
					}
					for _, reader := range []buf.Reader{ur, dr} {
						if command != protocol.RequestCommandUDP {
							got, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
							if err != nil || !bytes.Equal(got, packets[0]) {
								t.Fatal("stream mismatch", err)
							}
						} else {
							var got [][]byte
							for {
								mb, err := reader.ReadMultiBuffer()
								for _, b := range mb {
									got = append(got, append([]byte(nil), b.Bytes()...))
								}
								buf.ReleaseMulti(mb)
								if err == io.EOF {
									break
								}
								if err != nil {
									t.Fatal(err)
								}
							}
							if len(got) != len(packets) {
								t.Fatal("UDP boundaries changed")
							}
							for i := range got {
								if !bytes.Equal(got[i], packets[i]) {
									t.Fatal("UDP mismatch")
								}
							}
						}
					}
				})
			}
		}
	}
}

func TestForkVMessLegacyResponseCFBContinuity(t *testing.T) {
	u := headerUser(t, 1, true)
	v, h := headerServer(t, u)
	s := NewServerSession(v, h)
	plain := oraclePlain(legacyKey, legacyIV, 1, 1, 1)
	request, err := s.DecodeRequestHeader(bytes.NewReader(oracleLegacyWire(u, time.Now().Unix(), 1, plain)), false)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	s.EncodeResponseHeader(&protocol.ResponseHeader{}, &wire)
	w, err := s.EncodeResponseBody(request, &wire)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("CFB state continues after the four response header bytes")
	writeLegacyBody(t, w, data)
	key, iv := md5.Sum(legacyKey), md5.Sum(legacyIV)
	block, _ := aes.NewCipher(key[:])
	clear := make([]byte, wire.Len())
	cipher.NewCFBDecrypter(block, iv[:]).XORKeyStream(clear, wire.Bytes())
	sum := fnv.New32a()
	sum.Write(data)
	want := []byte{0x7d, 0, 0, 0, 0, byte(4 + len(data))}
	want = append(want, sum.Sum(nil)...)
	want = append(want, data...)
	if !bytes.Equal(clear, want) {
		t.Fatal("response cipher reset or double encryption")
	}
	// Independently encrypt a response and give it to the real client decoder.
	c := NewClientSession(context.Background(), 0)
	c.legacyHeader = true
	c.responseHeader = 0x7d
	c.responseBodyKey = key
	c.responseBodyIV = iv
	independent := make([]byte, len(want))
	cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(independent, want)
	raw := iotest.OneByteReader(bytes.NewReader(independent))
	if _, err := c.DecodeResponseHeader(raw); err != nil {
		t.Fatal(err)
	}
	r, err := c.DecodeResponseBody(request, raw)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(&buf.BufferedReader{Reader: r}, got); err != nil || !bytes.Equal(got, data) {
		t.Fatal("independent response continuity failed", err)
	}
	for cut := range 4 {
		if _, err := c.DecodeResponseHeader(bytes.NewReader(independent[:cut])); err == nil {
			t.Fatal("truncated legacy response accepted")
		}
	}
	bad := append([]byte(nil), independent...)
	bad[0] ^= 1
	if _, err := c.DecodeResponseHeader(bytes.NewReader(bad)); err == nil {
		t.Fatal("wrong response nonce accepted")
	}
}
