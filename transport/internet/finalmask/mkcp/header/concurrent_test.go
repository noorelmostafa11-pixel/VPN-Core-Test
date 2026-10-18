package header

import (
	"encoding/binary"
	"sync"
	"testing"
)

func TestConcurrentSRTPSequence(t *testing.T) {
	conn, err := NewConnServer(&Config{ID: int32(SRTP)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const workers, packets = 32, 128
	sequences := make(chan uint16, workers*packets)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range packets {
				packet := make([]byte, 4)
				conn.WriteTo(packet, nil)
				sequences <- binary.BigEndian.Uint16(packet[2:])
			}
		}()
	}
	wg.Wait()
	close(sequences)
	seen := map[uint16]bool{}
	for sequence := range sequences {
		if sequence == 0 || seen[sequence] {
			t.Fatalf("lost or repeated sequence: %d", sequence)
		}
		seen[sequence] = true
	}
	if len(seen) != workers*packets {
		t.Fatal("packets missing")
	}
}
