//go:build windows

package core

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in test creates an isolated /30 adapter and exchanges real OS TCP
// traffic with an independent VLESS peer. No default route or DNS is changed.
func TestWindowsNativeDevice(t *testing.T) {
	if os.Getenv("VPN_CORE_TEST_NATIVE_TUN") != "1" {
		t.Skip("set VPN_CORE_TEST_NATIVE_TUN=1 with administrator rights and signed wintun.dll")
	}
	uri, stop := vlessOracle(t)
	defer stop()
	cfg, _ := ParseURI(uri)
	engine, e := NewEngine(context.Background(), cfg, Hooks{})
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	name := "vpn-go-test-" + itoa(os.Getpid())
	device, name, e := OpenTUN(name, 1500)
	if e != nil {
		t.Fatal(e)
	}
	tunnel, e := engine.StartTUN(device, 1500)
	if e != nil {
		device.Close()
		t.Fatal(e)
	}
	defer tunnel.Close()
	if os.Getenv("VPN_CORE_TEST_POLICY_PLAN") == "1" {
		output, err := exec.Command("powershell", "-NoProfile", "-File", filepath.Join("scripts", "Set-Windows-Tunnel.ps1"), "-Mode", "Plan", "-TunName", name, "-UpstreamIPv4", "192.0.2.10").CombinedOutput()
		if err != nil {
			t.Fatalf("read-only Windows policy plan: %v %s", err, output)
		}
		var plan struct {
			Schema, Phase      string
			Routes, Rules, DNS []json.RawMessage
		}
		if err = json.Unmarshal(output, &plan); err != nil || plan.Schema != "vpn-windows-session-v1" || plan.Phase != "Plan" || len(plan.Routes) != 3 || len(plan.Rules) != 4 || len(plan.DNS) < 2 {
			t.Fatalf("invalid Windows policy plan: %v", err)
		}
	}
	output, e := exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+name, "source=static", "address=10.248.231.1", "mask=255.255.255.252", "gateway=none", "store=active").CombinedOutput()
	if e != nil {
		t.Fatalf("isolated interface address: %v %s", e, output)
	}
	defer exec.Command("netsh", "interface", "ipv4", "delete", "address", "name="+name, "addr=10.248.231.1").Run()
	var conn net.Conn
	for i := 0; i < 30; i++ {
		conn, e = net.DialTimeout("tcp", "10.248.231.2:443", time.Second)
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("actual-wintun-packet-forwarding")
	conn.Write(payload)
	b := make([]byte, len(payload))
	if _, e = io.ReadFull(conn, b); e != nil || string(b) != string(payload) {
		t.Fatalf("native device payload: %v", e)
	}
}
