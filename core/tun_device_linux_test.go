//go:build linux

package core

import (
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
	for _, args := range [][]string{{"addr", "add", "10.248.231.1/30", "dev", name}, {"link", "set", "dev", name, "up"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated device: %v %s", err, output)
		}
	}
	conn, err := net.DialTimeout("tcp", "10.248.231.2:443", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("actual-linux-tun-packet-forwarding")
	conn.Write(payload)
	b := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, b); err != nil || string(b) != string(payload) {
		t.Fatalf("native device data: %v", err)
	}
}
