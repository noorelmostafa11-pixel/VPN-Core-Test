//go:build netstack

package main

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestPacketCopyPreservesSplitViewsAndRetry(t *testing.T) {
	for _, size := range []int{0, 1, 512, 32768, 65487} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		var data buffer.Buffer
		for start := 0; start < size; start += 193 {
			end := start + 193
			if end > size {
				end = size
			}
			data.Append(buffer.NewViewWithData(payload[start:end]))
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 64, Payload: data})
		transport := p.TransportHeader().Push(8)
		network := p.NetworkHeader().Push(40)
		for i := range transport {
			transport[i] = byte(i + 1)
		}
		for i := range network {
			network[i] = byte(i + 70)
		}
		expected := append(append(append([]byte(nil), network...), transport...), payload...)
		short := bytes.Repeat([]byte{0xa5}, len(expected)-1)
		if n := copyTunPacket(p, short); n != -3 || !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
			t.Fatalf("undersized retry size=%d n=%d", size, n)
		}
		out := bytes.Repeat([]byte{0xcc}, len(expected)+17)
		if n := copyTunPacket(p, out); n != len(expected) || !bytes.Equal(out[:n], expected) || !bytes.Equal(out[n:], bytes.Repeat([]byte{0xcc}, 17)) {
			t.Fatalf("split/header/headroom copy size=%d n=%d", size, n)
		}
		p.DecRef()
	}
}

func TestLinkCongestionIsCountedWithoutChangingSemantics(t *testing.T) {
	l := &tunLink{Endpoint: channel.New(2, 1500, "")}
	defer l.Close()
	for i := 0; i < 5; i++ {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{byte(i)})})
		var packets stack.PacketBufferList
		packets.PushBack(p)
		n, err := l.WritePackets(packets)
		p.DecRef()
		want := 1
		if i >= 2 {
			want = 0
		}
		if err != nil || n != want {
			t.Fatalf("changed queue behavior: %d %v", n, err)
		}
	}
	if n := l.unqueued.Load(); n != 3 {
		t.Fatalf("unqueued packets: %d", n)
	}
	for i := 0; i < 2; i++ {
		p := l.Read()
		if p == nil {
			t.Fatal("queued packet lost")
		}
		out := make([]byte, 1)
		if copyTunPacket(p, out) != 1 || out[0] != byte(i) {
			t.Fatal("queue order changed")
		}
		p.DecRef()
	}
}
