package http

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/http2"
)

type realityFixture struct {
	server, client *reality.Config
	fallback       atomic.Int32
}

func localReality(t *testing.T, h2 bool) *realityFixture {
	t.Helper()
	return localRealityTarget(t, h2, true)
}

func localRealityTarget(t *testing.T, h2, warm bool) *realityFixture {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &realityFixture{}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.fallback.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	target.EnableHTTP2 = h2
	target.TLS = &gotls.Config{MinVersion: gotls.VersionTLS13, CurvePreferences: []gotls.CurveID{gotls.X25519}}
	target.Config.ReadHeaderTimeout = 2 * time.Second
	target.StartTLS()
	t.Cleanup(target.Close)
	f.server = &reality.Config{Type: "tcp", Dest: target.Listener.Addr().String(), ServerNames: []string{"reality.example"}, PrivateKey: key.Bytes(), ShortIds: [][]byte{{1, 2, 3, 4, 5, 6, 7, 8}}}
	f.client = &reality.Config{ServerName: "reality.example", Fingerprint: "chrome", PublicKey: key.PublicKey().Bytes(), ShortId: []byte{1, 2, 3, 4, 5, 6, 7, 8}, SpiderX: "/"}
	if !warm {
		return f
	}
	// Run the real pinned target detector and wait for it; never seed fake results
	// or retry an application handshake to mask detector/startup races.
	goreality.DetectPostHandshakeRecordsLens(f.server.GetREALITYConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		ready := true
		for alpn := range 3 {
			value, ok := goreality.GlobalPostHandshakeRecordsLens.Load(f.server.Dest + " reality.example " + strconv.Itoa(alpn))
			_, complete := value.([]int)
			ready = ready && ok && complete
		}
		if ready {
			return f
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("local REALITY target detection did not complete")
		}
	}
}

func (f *realityFixture) settings(client bool) *internet.MemoryStreamConfig {
	security := f.server
	if client {
		security = f.client
	}
	return &internet.MemoryStreamConfig{ProtocolName: "http", ProtocolSettings: &Config{Host: []string{"tunnel.example"}, Path: "/reality%20path?key=value", Method: "PATCH"}, SecurityType: "reality", SecuritySettings: security}
}

type referenceRealityStateConn struct {
	gonet.Conn
	state gotls.ConnectionState
}

func (c *referenceRealityStateConn) ConnectionState() gotls.ConnectionState { return c.state }

// This peer uses the pinned REALITY API and x/net's H2 server directly, not
// this package's listener or its transport request handler.
func realityReferencePeer(t *testing.T, f *realityFixture, handler http.Handler) (net.Destination, <-chan error) {
	t.Helper()
	listener, err := gonet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	done := make(chan error, 1)
	joined := make(chan struct{})
	var mu sync.Mutex
	var active gonet.Conn
	go func() {
		defer close(joined)
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		mu.Lock()
		active = raw
		mu.Unlock()
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(8 * time.Second))
		secure, err := goreality.Server(ctx, raw, f.server.GetREALITYConfig())
		if err != nil {
			done <- err
			return
		}
		if !secure.ConnectionState().HandshakeComplete {
			done <- errors.New("independent REALITY peer handshake incomplete")
			return
		}
		state := secure.ConnectionState()
		wrapped := &referenceRealityStateConn{Conn: secure, state: gotls.ConnectionState{Version: state.Version, HandshakeComplete: state.HandshakeComplete, CipherSuite: state.CipherSuite, NegotiatedProtocol: state.NegotiatedProtocol}}
		(&http2.Server{}).ServeConn(wrapped, &http2.ServeConnOpts{Context: ctx, Handler: handler})
		done <- nil
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mu.Lock()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("independent REALITY peer did not join")
		}
	})
	return net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*gonet.TCPAddr).Port)), done
}

func TestForkHTTP2RealityClientIndependentPeer(t *testing.T) {
	f := localReality(t, true)
	payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
	greeting := []byte("REALITY independent server-first\n")
	finished := make(chan error, 1)
	dest, _ := realityReferencePeer(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "PATCH" || r.Host != "tunnel.example" || r.URL.EscapedPath() != "/reality%20path" || r.URL.RawQuery != "key=value" || r.TLS == nil || !r.TLS.HandshakeComplete {
			finished <- errors.New("independent HTTP2/REALITY metadata mismatch")
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		w.Write(greeting)
		w.(http.Flusher).Flush()
		got, err := io.ReadAll(r.Body)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("independent HTTP2/REALITY upload mismatch")
		}
		if err == nil {
			_, err = w.Write(got)
		}
		finished <- err
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := Dial(ctx, dest, f.settings(true))
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*clientConn)
	t.Cleanup(func() {
		c.Close()
		select {
		case <-c.workerDone:
		case <-time.After(5 * time.Second):
			t.Error("REALITY client response worker did not join")
		}
	})
	c.SetDeadline(time.Now().Add(8 * time.Second))
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, greeting) {
		t.Fatal("REALITY server-first failed", err)
	}
	for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
		if n, err := c.Write(piece); err != nil || n != len(piece) {
			t.Fatal("REALITY upload failed", n, err)
		}
	}
	c.CloseWrite()
	got, err = io.ReadAll(c)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("REALITY half-close/download failed", len(got), err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("independent REALITY exchange did not finish")
	}
	if f.fallback.Load() != 0 {
		t.Fatal("application bytes reached REALITY fallback target")
	}
}

func TestForkHTTP2RealityServerIndependentPeer(t *testing.T) {
	// First connection after a genuinely cold target, without fixture warmup.
	f := localRealityTarget(t, true, false)
	payload := bytes.Repeat([]byte{0, 0xff, 0x5a}, 40001)
	greeting := []byte("REALITY listener server-first\n")
	finished := make(chan error, 1)
	listener, err := Listen(context.Background(), net.LocalHostIP, tcp.PickPort(), f.settings(false), func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			stream := conn.(*serverConn)
			state := stream.request.TLS
			// Pinned REALITY leaves ALPN empty after authenticating the SNI.
			// Expose that actual state, never a fabricated h2 negotiation.
			if state == nil || !state.HandshakeComplete || state.Version != gotls.VersionTLS13 || state.NegotiatedProtocol != "" || state.ServerName != "reality.example" {
				t.Errorf("unexpected REALITY TLS state: %+v", state)
				finished <- errors.New("actual REALITY state not exposed to H2")
				return
			}
			conn.SetDeadline(time.Now().Add(8 * time.Second))
			_, err := conn.Write(greeting)
			var got []byte
			if err == nil {
				got, err = io.ReadAll(conn)
			}
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("REALITY server upload mismatch")
			}
			if err == nil {
				_, err = conn.Write(got)
			}
			finished <- err
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	raw, err := gonet.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	secure, err := reality.UClient(raw, f.client, ctx, net.TCPDestination(net.LocalHostIP, 443))
	if err != nil {
		t.Fatal(err)
	}
	client, err := (&http2.Transport{DisableCompression: true}).NewClientConn(secure)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	body, upload := io.Pipe()
	defer body.Close()
	defer upload.Close()
	req, _ := http.NewRequestWithContext(ctx, "PATCH", "https://tunnel.example/reality%20path?key=value", body)
	response, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ProtoMajor != 2 {
		t.Fatal("REALITY server rejected independent H2 peer")
	}
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(response.Body, got); err != nil || !bytes.Equal(got, greeting) {
		t.Fatal("REALITY server-first failed", err)
	}
	for _, piece := range [][]byte{payload[:1], payload[1:65], payload[65:8193], payload[8193:]} {
		if n, err := upload.Write(piece); err != nil || n != len(piece) {
			t.Fatal("independent REALITY upload failed", n, err)
		}
	}
	upload.Close()
	got, err = io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("independent REALITY download failed", len(got), err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if f.fallback.Load() != 0 {
		t.Fatal("application bytes reached REALITY fallback target")
	}
}

func TestForkHTTP2RealityClientAuthenticationAndALPN(t *testing.T) {
	for _, fault := range []string{"public-key", "short-id", "server-name"} {
		t.Run(fault, func(t *testing.T) {
			f := localReality(t, true)
			switch fault {
			case "public-key":
				key, _ := ecdh.X25519().GenerateKey(rand.Reader)
				f.client.PublicKey = key.PublicKey().Bytes()
			case "short-id":
				f.client.ShortId = make([]byte, 8)
			case "server-name":
				f.client.ServerName = "wrong.example"
			}
			var accepted atomic.Int32
			dest, _ := realityReferencePeer(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accepted.Add(1) }))
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if conn, err := Dial(ctx, dest, f.settings(true)); err == nil {
				conn.Close()
				t.Fatal("invalid REALITY authentication/ALPN accepted", fault)
			}
			if accepted.Load() != 0 || f.fallback.Load() != 0 {
				t.Fatal("invalid REALITY connection sent application request")
			}
		})
	}
}

func TestForkHTTP2RealityALPNBoundary(t *testing.T) {
	for _, protocol := range []string{"", "h2", "http/1.1", "h3", "other"} {
		want := protocol == "" || protocol == "h2"
		if realityHTTP2ALPN(protocol) != want {
			t.Fatal("REALITY ALPN boundary mismatch", protocol)
		}
	}
}

func TestForkHTTP2RealityClientCancellation(t *testing.T) {
	f := localReality(t, true)
	listener, err := gonet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := Dial(ctx, net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*gonet.TCPAddr).Port)), f.settings(true))
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Receiving a ClientHello proves the handshake is actually stalled.
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(raw, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled REALITY handshake accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("REALITY handshake ignored cancellation")
	}
}

func silentRealityTarget(t *testing.T) (gonet.Listener, <-chan struct{}) {
	t.Helper()
	target, err := gonet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var targets []gonet.Conn
	joined := make(chan struct{})
	accepted := make(chan struct{}, 16)
	go func() {
		defer close(joined)
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			targets = append(targets, conn)
			mu.Unlock()
			accepted <- struct{}{}
		}
	}()
	t.Cleanup(func() {
		target.Close()
		<-joined
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range targets {
			conn.Close()
		}
	})
	return target, accepted
}

func TestForkHTTP2RealityListenerStalledTargetCancellation(t *testing.T) {
	target, _ := silentRealityTarget(t)
	f := localReality(t, true)
	settings := f.settings(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := Listen(ctx, net.LocalHostIP, tcp.PickPort(), settings, func(conn stat.Connection) { t.Error("stalled target reached application handler"); conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	l := listener.(*Listener)
	t.Cleanup(func() { l.Close() })
	started := make(chan struct{})
	dial := l.realityConfig.DialContext
	l.realityConfig.DialContext = func(ctx context.Context, network, address string) (gonet.Conn, error) {
		// Inject a silent target into the actual handshake, after real startup
		// detection. Keep the production target deadline/cancellation wrapper.
		conn, err := dial(ctx, network, target.Addr().String())
		close(started) // actual per-handshake target, not the upstream detector
		return conn, err
	}
	raw, err := gonet.DialTimeout("tcp", l.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("fault schedule did not reach the silent target")
	}
	cancel()
	select {
	case <-l.done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener retained handshake blocked on target")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.connections) != 0 || len(l.streams) != 0 {
		t.Fatal("canceled REALITY listener retained connections")
	}
}

func TestForkHTTP2RealityStartupCancellation(t *testing.T) {
	target, accepted := silentRealityTarget(t)
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}, SecurityType: "reality", SecuritySettings: &reality.Config{Type: "tcp", Dest: target.Addr().String(), ServerNames: []string{"reality.example"}, PrivateKey: bytes.Repeat([]byte{1}, 32), ShortIds: [][]byte{make([]byte, 8)}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := tcp.PickPort()
	done := make(chan error, 1)
	go func() {
		listener, err := Listen(ctx, net.LocalHostIP, port, settings, nil)
		if listener != nil {
			listener.Close()
		}
		done <- err
	}()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("startup fault did not reach silent target")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("startup cancellation lost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target initialization ignored cancellation")
	}
	rebound, err := gonet.Listen("tcp4", gonet.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal("canceled startup retained listening socket", err)
	}
	rebound.Close()
}

func TestForkHTTP2RealityRejectsHTTP1Preface(t *testing.T) {
	f := localReality(t, true)
	var accepted atomic.Int32
	l, err := Listen(context.Background(), net.LocalHostIP, tcp.PickPort(), f.settings(false), func(conn stat.Connection) { accepted.Add(1); conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := gonet.DialTimeout("tcp", l.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	secure, err := reality.UClient(raw, f.client, ctx, net.TCPDestination(net.LocalHostIP, 443))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secure.Write([]byte("PATCH /reality HTTP/1.1\r\nHost: tunnel.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, secure)
	if timeout, ok := err.(gonet.Error); ok && timeout.Timeout() {
		t.Fatal("non-H2 preface was not rejected promptly")
	}
	if accepted.Load() != 0 || f.fallback.Load() != 0 {
		t.Fatal("HTTP/1.1 reached application or fallback after REALITY authentication")
	}
}

func TestForkHTTP2RealityMissingSettingsNoDowngrade(t *testing.T) {
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}, SecurityType: "reality"}
	if conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, 1), settings); err == nil {
		conn.Close()
		t.Fatal("missing REALITY config became plaintext")
	}
	if listener, err := Listen(context.Background(), net.LocalHostIP, tcp.PickPort(), settings, nil); err == nil {
		listener.Close()
		t.Fatal("missing REALITY config became plaintext listener")
	}
}
