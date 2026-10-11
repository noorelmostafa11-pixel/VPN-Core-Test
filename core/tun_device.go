//go:build linux || windows || darwin || freebsd || openbsd

package core

import (
	"errors"
	"golang.zx2c4.com/wireguard/tun"
	"io"
	"sync"
)

type nativeDevice struct {
	device          tun.Device
	buffers         [][]byte
	sizes           []int
	pending, index  int
	readMu, writeMu sync.Mutex
	writeBuffer     []byte
}

func wrapDevice(d tun.Device) *nativeDevice {
	batch := d.BatchSize()
	mtu, _ := d.MTU()
	if mtu < 1280 {
		mtu = 1500
	}
	n := &nativeDevice{device: d, buffers: make([][]byte, batch), sizes: make([]int, batch), writeBuffer: make([]byte, 65536+16)}
	for i := range n.buffers {
		n.buffers[i] = make([]byte, mtu+256+16)
	}
	go func() {
		for range d.Events() {
		}
	}()
	return n
}

func (d *nativeDevice) ReadPacket(b []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	for d.pending == 0 {
		n, e := d.device.Read(d.buffers, d.sizes, 16)
		if e != nil {
			return 0, e
		}
		d.pending = n
		d.index = 0
	}
	size := d.sizes[d.index]
	if size > len(b) {
		return 0, io.ErrShortBuffer
	}
	copy(b, d.buffers[d.index][16:16+size])
	d.index++
	d.pending--
	return size, nil
}
func (d *nativeDevice) WritePacket(b []byte) error {
	if len(b) > 65535 {
		return errors.New("TUN_PACKET_SIZE")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	copy(d.writeBuffer[16:], b)
	n, e := d.device.Write([][]byte{d.writeBuffer[:len(b)+16]}, 16)
	if e == nil && !nativeWriteComplete(n, len(b), d.device.BatchSize()) {
		return errors.New("TUN_WRITE_COUNT")
	}
	return e
}
func (d *nativeDevice) Close() error          { return d.device.Close() }
func (d *nativeDevice) Name() (string, error) { return d.device.Name() }

// OpenTUN creates a native OS device. Routes/addresses belong to the host,
// which can protect the upstream before forwarding system traffic into it.
func OpenTUN(name string, mtu int) (PacketDevice, string, error) {
	d, e := tun.CreateTUN(name, mtu)
	if e != nil {
		return nil, "", e
	}
	n, e := d.Name()
	if e != nil {
		d.Close()
		return nil, "", e
	}
	return wrapDevice(d), n, nil
}
