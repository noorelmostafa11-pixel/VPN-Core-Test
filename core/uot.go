package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const uotV2Host = "sp.v2.udp-over-tcp.arpa"

type uotPackets struct {
	net.Conn
	address []byte
	connect bool
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func (s *uotPackets) WritePacket(body []byte) error {
	if len(body) > 65507 {
		return errors.New("UDP_DATAGRAM_LENGTH")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	header := word(len(body))
	if !s.connect {
		address := append([]byte(nil), s.address...)
		switch address[0] {
		case 1:
			address[0] = 0
		case 4:
			address[0] = 1
		case 3:
			address[0] = 2
		}
		header = append(address, header...)
	}
	return writeAll(s.Conn, append(header, body...))
}
func (s *uotPackets) ReadPacket() (Datagram, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var address []byte
	if s.connect {
		address = s.address
	}
	if !s.connect {
		var kind [1]byte
		if _, err := io.ReadFull(s.Conn, kind[:]); err != nil {
			return Datagram{}, err
		}
		switch kind[0] {
		case 0:
			kind[0] = 1
		case 1:
			kind[0] = 4
		case 2:
			kind[0] = 3
		default:
			return Datagram{}, errors.New("UDP_ADDRESS")
		}
		var err error
		address, err = readAddress(io.MultiReader(bytes.NewReader(kind[:]), s.Conn))
		if err != nil {
			return Datagram{}, err
		}
	}
	var length [2]byte
	if _, err := io.ReadFull(s.Conn, length[:]); err != nil {
		return Datagram{}, err
	}
	n := getWord(length[:], 0)
	if n > 65507 {
		return Datagram{}, errors.New("UDP_DATAGRAM_LENGTH")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(s.Conn, body)
	return Datagram{Address: address, Payload: body}, err
}
func dialAnyTLSPacket(ctx context.Context, c Config, host string, port int) (PacketStream, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	address, err := Address(host, port)
	if err != nil {
		return nil, err
	}
	client, owner, err := getAnyTLS(ctx, c)
	if err != nil {
		return nil, err
	}
	magic, _ := Address(uotV2Host, 443)
	// UDP metadata precedes SYNACK in reference implementations. Include it
	// with the destination instead of waiting for an ACK before sending it.
	initial := append(magic, append([]byte{1}, address...)...)
	stream, err := client.open(ctx, initial)
	if err != nil {
		owner.Close()
		return nil, err
	}
	conn := &hyLeaseConn{Conn: stream, owner: owner}
	return &uotPackets{Conn: conn, address: address, connect: true}, nil
}
func (e *Engine) serveUOT(stream net.Conn) {
	stream.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
	var mode [1]byte
	if _, err := io.ReadFull(stream, mode[:]); err != nil || mode[0] > 1 {
		return
	}
	address, err := readAddress(stream)
	if err != nil {
		return
	}
	host, port := "", 0
	if mode[0] == 1 {
		host, port, err = decodeAddress(address)
		if err != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	bridge := &packetBridge{e: e, ctx: ctx, cancel: cancel, peers: map[string]*bridgePeer{}, queue: make(chan bridgeResult, 64)}
	defer bridge.Close()
	if mode[0] == 1 {
		if _, err = bridge.peer(net.JoinHostPort(host, itoa(port))); err != nil {
			return
		}
	}
	client := &uotPackets{Conn: stream, address: address, connect: mode[0] == 1}
	stream.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, addr, err := bridge.ReadFrom(buf)
			if err != nil {
				stream.Close()
				return
			}
			h, p, err := splitProtocolTarget(addr)
			if err != nil {
				stream.Close()
				return
			}
			if !client.connect {
				client.address, _ = Address(h, p)
			}
			stream.SetWriteDeadline(time.Now().Add(e.config.IdleTimeout))
			if client.WritePacket(buf[:n]) != nil {
				stream.Close()
				return
			}
		}
	}()
	for {
		stream.SetReadDeadline(time.Now().Add(e.config.IdleTimeout))
		packet, err := client.ReadPacket()
		if err != nil {
			break
		}
		h, p, err := decodeAddress(packet.Address)
		if err != nil {
			break
		}
		if _, err = bridge.WriteTo(packet.Payload, net.JoinHostPort(h, itoa(p))); err != nil {
			break
		}
	}
	cancel()
	bridge.Close()
	stream.Close()
	<-done
}
