package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

const visionServerTestUUID = "12345678-1234-4567-9234-567812345678"

func visionServerFixture(t *testing.T) (Config, *Engine) {
	t.Helper()
	cert, key := testServerCertificate(t)
	e := testServerEngine(t)
	a, err := e.StartServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, CertFile: cert, KeyFile: key, Options: map[string]string{"flow": vlessVisionFlow}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseURI("vless://" + visionServerTestUUID + "@" + a.String() + "?security=tls&sni=127.0.0.1&fp=native&flow=" + vlessVisionFlow)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = cert
	return cfg, e
}

func TestVisionServerRepeatedTCPUDPAndOwnerClose(t *testing.T) {
	cfg, server := visionServerFixture(t)
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for cycle := 0; cycle < 16; cycle++ {
		c, err := client.DialContext(context.Background(), "tcp", echoPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		payloadCheck(t, c)
	}
	h, port, _ := splitProtocolTarget(udpEchoPeer(t))
	for cycle := 0; cycle < 8; cycle++ {
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
		t.Fatal("Vision TCP/UDP owner retained budget")
	}
}

func TestVisionServerRealInnerTLS13(t *testing.T) {
	cfg, server := visionServerFixture(t)
	cert, key := testServerCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for cycle := 0; cycle < 8; cycle++ {
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
	client, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	root := x509.NewCertPool()
	pem, _ := os.ReadFile(cert)
	if !root.AppendCertsFromPEM(pem) {
		t.Fatal("inner trust")
	}
	for cycle := 0; cycle < 8; cycle++ {
		c, err := client.DialContext(context.Background(), "tcp", listener.Addr().String())
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
			t.Fatal("inner TLS payload", err)
		}
	}
	server.Close()
	client.Close()
	if server.Stats().Active != 0 {
		t.Fatal("inner TLS owner retained budget")
	}
}

func TestVLESSServerAddonValidationAndFlowPolicy(t *testing.T) {
	flow := append([]byte{10, byte(len(vlessVisionFlow))}, vlessVisionFlow...)
	for _, bad := range [][]byte{{10, 255}, {0}, {8, 1}, {10, 1, 255}, {10, 128}, append(append([]byte(nil), flow...), flow...), {19}, bytes.Repeat([]byte{128}, 10)} {
		if _, err := vlessAddonFlow(bad); err == nil {
			t.Fatal("malformed addons accepted", bad)
		}
	}
	valid := append([]byte{24, 1, 26, 0}, flow...)
	if got, err := vlessAddonFlow(valid); err != nil || got != vlessVisionFlow {
		t.Fatal("bounded unknown protobuf fields", got, err)
	}
	for _, options := range []map[string]string{{"flow": "unknown"}, {"unknown": "1"}, {"flow": vlessVisionFlow}} {
		if _, err := compileServer(ServerConfig{Protocol: "vless", Listen: "127.0.0.1:0", UUIDs: []string{visionServerTestUUID}, Options: options}); err == nil {
			t.Fatal("invalid flow/transport config accepted")
		}
	}
	cfg, server := visionServerFixture(t)
	cfg.Flow = ""
	c, err := Dial(context.Background(), cfg, "127.0.0.1", 1)
	if err == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("Vision listener accepted missing TCP flow")
	}
	server.Close()
	if server.Stats().Active != 0 {
		t.Fatal("flow rejection retained budget")
	}
}

type visionCaptureConn struct {
	net.Conn
	mu         sync.Mutex
	output     bytes.Buffer
	input      io.Reader
	halfCloses int
}

func (c *visionCaptureConn) Read(b []byte) (int, error) { return c.input.Read(b) }
func (c *visionCaptureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.Write(b)
}
func (c *visionCaptureConn) CloseWrite() error { c.halfCloses++; return nil }

func visionTestServerHello() []byte {
	body := make([]byte, 39)
	body[0], body[4], body[5] = 2, 3, 3
	body = append(body, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	body[3] = byte(len(body) - 4)
	return shadowRecord(22, body)
}

func TestVisionServerFragmentedDirectBoundariesAndHalfClose(t *testing.T) {
	id, _ := uuidBytes(visionServerTestUUID)
	outer, raw := &visionCaptureConn{}, &visionCaptureConn{}
	c := newVisionServerConn(&directConn{Conn: outer, raw: raw}, id)
	hello := visionTestServerHello()
	for _, b := range hello {
		if _, err := c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if !c.tls13.Load() || c.writeRaw {
		t.Fatal("direct before a complete application record")
	}
	app := shadowRecord(23, bytes.Repeat([]byte{7}, 17))
	for i, b := range app {
		c.Write([]byte{b})
		if c.writeRaw != (i == len(app)-1) {
			t.Fatal("direct transition crossed a fragmented TLS record")
		}
	}
	v := vision{c: Config{UUID: id, Transport: "raw"}, enabled: true, prefix: true, needHeader: true}
	got, err := v.decode(outer.output.Bytes())
	if err != nil || !v.direct || !bytes.Equal(got, append(hello, app...)) {
		t.Fatal("padding/transition bytes lost", err)
	}
	if _, err = c.Write(app); err != nil || !bytes.Equal(raw.output.Bytes(), app) {
		t.Fatal("raw downlink not selected", err)
	}
	if err = c.CloseWrite(); err != nil || outer.halfCloses != 0 || raw.halfCloses != 1 {
		t.Fatal("outer TLS close-notify sent into direct data", err)
	}
	if _, err = c.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("write after half-close")
	}
}

func TestVisionServerRejectsUnverifiedDirectUplink(t *testing.T) {
	id, _ := uuidBytes(visionServerTestUUID)
	v := vision{c: Config{UUID: id}}
	for _, authorized := range []bool{false, true} {
		outer := &visionCaptureConn{input: bytes.NewReader(v.frame(2, []byte("transition"), true))}
		raw := &visionCaptureConn{input: bytes.NewReader([]byte("raw data"))}
		c := newVisionServerConn(&directConn{Conn: outer, raw: raw}, id)
		c.tls13.Store(authorized)
		body := make([]byte, 32)
		n, err := c.Read(body)
		if !authorized {
			if err == nil || c.direct.Load() {
				t.Fatal("unverified direct accepted")
			}
			continue
		}
		if err != nil || string(body[:n]) != "transition" || !c.direct.Load() {
			t.Fatal("authorized transition", err)
		}
		n, err = c.Read(body)
		if err != nil || string(body[:n]) != "raw data" {
			t.Fatal("raw uplink bytes lost", err)
		}
	}
}

func TestVisionMuxRejectsTCPAllowsUDPAndJoins(t *testing.T) {
	e := testServerEngine(t)
	a, b := net.Pipe()
	done := make(chan struct{})
	if !e.spawn(func() { defer close(done); e.serveMuxPolicy(a, true) }) {
		t.Fatal("owner stopped")
	}
	defer func() { b.Close(); e.Close(); <-done }()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	host, port, _ := splitProtocolTarget(udpEchoPeer(t))
	address, _ := Address(host, port)
	for _, network := range []byte{1, 2} {
		wire, _ := encodeMuxFrame(muxFrame{id: uint16(network), status: 1, network: network, options: 1, address: address, body: []byte("allowed UDP")})
		if err := writeAll(b, wire); err != nil {
			t.Fatal(err)
		}
		got, err := readMuxFrame(b)
		if err != nil {
			t.Fatal(err)
		}
		if network == 1 && (got.status != 3 || got.options != 2) {
			t.Fatal("TCP multiplex bypassed Vision flow policy")
		}
		if network == 2 && !bytes.Equal(got.body, []byte("allowed UDP")) {
			t.Fatal("UDP multiplex rejected")
		}
	}
	b.Close()
	e.Close()
	<-done
	if e.Stats().Active != 0 {
		t.Fatal("Vision MUX owner retained budget")
	}
}
