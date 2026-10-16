package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
)

func legacyRequest(address net.Address) *protocol.RequestHeader {
	return &protocol.RequestHeader{Version: 4, Command: protocol.RequestCommandTCP, Address: address, Port: 443, User: &protocol.MemoryUser{Account: &Account{Username: "id"}}}
}

type fragmentWriter struct{ bytes.Buffer }

func (w *fragmentWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}

func TestForkSocks4GoldenAndFragmentedReply(t *testing.T) {
	for _, test := range []struct {
		address net.Address
		wire    []byte
	}{
		{net.LocalHostIP, []byte{4, 1, 1, 187, 127, 0, 0, 1, 'i', 'd', 0}},
		{net.DomainAddress("example.invalid"), append([]byte{4, 1, 1, 187, 0, 0, 0, 1, 'i', 'd', 0}, append([]byte("example.invalid"), 0)...)},
	} {
		var writer fragmentWriter
		reader := iotest.OneByteReader(bytes.NewReader(append([]byte{0, 90, 0, 0, 0, 0, 0, 0}, []byte("server-first")...)))
		response, err := ClientHandshake(legacyRequest(test.address), reader, &writer)
		if err != nil || response != nil || !bytes.Equal(writer.Bytes(), test.wire) {
			t.Fatal("incorrect wire request or fragmented response", err, writer.Bytes())
		}
		body, err := io.ReadAll(reader)
		if err != nil || string(body) != "server-first" {
			t.Fatal("handshake consumed server-first data", err)
		}
	}
}

func TestForkSocks4BoundsAndRejections(t *testing.T) {
	for size := range 8 {
		var writer bytes.Buffer
		if _, err := ClientHandshake(legacyRequest(net.LocalHostIP), bytes.NewReader([]byte{0, 90, 0, 0, 0, 0, 0, 0}[:size]), &writer); err == nil {
			t.Fatal("truncated response accepted", size)
		}
	}
	for _, reply := range [][]byte{{4, 90, 0, 0, 0, 0, 0, 0}, {0, 91, 0, 0, 0, 0, 0, 0}, {0, 92, 0, 0, 0, 0, 0, 0}, {0, 93, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 255, 0, 0, 0, 0, 0, 0}} {
		if _, err := ClientHandshake(legacyRequest(net.LocalHostIP), bytes.NewReader(reply), io.Discard); err == nil {
			t.Fatal("invalid/rejected response accepted", reply)
		}
	}
	for _, modify := range []func(*protocol.RequestHeader){
		func(r *protocol.RequestHeader) { r.Command = protocol.RequestCommandUDP },
		func(r *protocol.RequestHeader) { r.Command = protocol.RequestCommandMux },
		func(r *protocol.RequestHeader) { r.Address = net.ParseAddress("::1") },
		func(r *protocol.RequestHeader) { r.Address = net.ParseAddress("0.0.0.1") },
		func(r *protocol.RequestHeader) { r.Address = nil },
		func(r *protocol.RequestHeader) { r.Port = 0 },
		func(r *protocol.RequestHeader) { r.Address = net.DomainAddress("bad\x00name") },
		func(r *protocol.RequestHeader) { r.Address = net.DomainAddress(strings.Repeat("a", 256)) },
		func(r *protocol.RequestHeader) { r.User.Account = &Account{Password: "not-auth"} },
		func(r *protocol.RequestHeader) { r.User.Account = &Account{Username: "bad\x00id"} },
		func(r *protocol.RequestHeader) { r.User.Account = nil },
	} {
		request := legacyRequest(net.LocalHostIP)
		modify(request)
		var writer bytes.Buffer
		if _, err := ClientHandshake(request, bytes.NewReader(make([]byte, 8)), &writer); err == nil || writer.Len() != 0 {
			t.Fatal("invalid legacy request wrote a header", err)
		}
	}
	for _, destination := range []net.Destination{net.UDPDestination(net.LocalHostIP, 443), net.TCPDestination(net.ParseAddress("::1"), 443)} {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: destination}})
		// A nil dialer/policy manager proves rejection occurs before network use.
		if err := (&Client{version: ClientVersion_SOCKS4}).Process(ctx, nil, nil); err == nil {
			t.Fatal("unsupported target reached the dialer")
		}
	}
}

func TestForkSocks4LocalIPv4Resolution(t *testing.T) {
	wantErr := errors.New("synthetic DNS failure")
	for _, test := range []struct {
		ips   []net.IPAddr
		err   error
		valid bool
	}{
		{[]net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil, true},
		{[]net.IPAddr{{IP: net.ParseIP("::1")}}, nil, false},
		{nil, nil, false},
		{nil, wantErr, false},
	} {
		address, err := resolveLegacyIPv4(context.Background(), "example.invalid", func(ctx context.Context, domain string) ([]net.IPAddr, error) {
			if domain != "example.invalid" {
				t.Fatal("DNS name changed")
			}
			return test.ips, test.err
		})
		if (err == nil) != test.valid || (test.valid && address.String() != "127.0.0.1") {
			t.Fatal("IPv4 resolver selection mismatch", address, err)
		}
		if test.err != nil && !errors.Is(err, wantErr) {
			t.Fatal("DNS failure lost", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolveLegacyIPv4(ctx, "example.invalid", func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("canceled DNS lookup started")
		return nil, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context ignored", err)
	}
}

func TestForkSocks4RuntimeConfigGuards(t *testing.T) {
	if _, err := NewClient(context.Background(), &ClientConfig{Version: ClientVersion(99)}); err == nil {
		t.Fatal("unknown protobuf version accepted")
	}
	for _, version := range []ClientVersion{ClientVersion_SOCKS4, ClientVersion_SOCKS4A} {
		for _, account := range []*Account{{Password: "not-auth"}, {Username: "bad\x00id"}, {Username: strings.Repeat("u", 256)}} {
			config := &ClientConfig{Version: version, Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: 1080, User: &protocol.User{Account: serial.ToTypedMessage(account)}}}
			if _, err := NewClient(context.Background(), config); err == nil {
				t.Fatal("protobuf account bypassed legacy guards")
			}
		}
	}
}
