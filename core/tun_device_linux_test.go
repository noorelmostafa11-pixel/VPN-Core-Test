//go:build linux

package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLinuxNativeDevice(t *testing.T) {
	if os.Getenv("VPN_CORE_TEST_NATIVE_TUN") != "1" {
		t.Skip("set VPN_CORE_TEST_NATIVE_TUN=1 with CAP_NET_ADMIN")
	}
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	e, err := NewEngine(context.Background(), cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	device, name, err := OpenTUN("vpg"+itoa(os.Getpid()), 1500)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := e.StartTUN(device, 1500)
	if err != nil {
		device.Close()
		t.Fatal(err)
	}
	defer tun.Close()
	for _, args := range [][]string{{"addr", "add", "10.248.231.1/30", "dev", name}, {"-6", "addr", "add", "fd77:231::1/126", "dev", name, "nodad"}, {"link", "set", "dev", name, "up"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated device: %v %s", err, output)
		}
	}
	for _, address := range []string{"10.248.231.2:443", "[fd77:231::2]:443"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+address, func(t *testing.T) {
				conn, err := net.DialTimeout(network, address, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				size := 128 * 1024 // exercises segmentation and offload conversion
				if network == "udp" {
					size = 1200
				}
				payload := bytes.Repeat([]byte{0x5a}, size)
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, b); err != nil || !bytes.Equal(b, payload) {
					t.Fatalf("native device data: %v; tunnel: %v; stats: %+v", err, tun.Err(), e.Stats())
				}
			})
		}
	}
}
