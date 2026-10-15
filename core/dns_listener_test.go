package core

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestDNSAutomaticDualBindPermissionRecovery(t *testing.T) {
	e := testServerEngine(t)
	var listeners []net.Listener
	var packets net.PacketConn
	denied := &net.OpError{Op: "listen", Net: "udp", Err: os.ErrPermission}
	calls := 0
	addr, err := e.startDNS("127.0.0.1:0", func(network, address string) (net.Listener, error) {
		if len(listeners) != 0 {
			assertDNSListenerReleased(t, e, listeners[len(listeners)-1], nil)
		}
		l, err := net.Listen(network, address)
		if err == nil {
			listeners = append(listeners, l)
		}
		return l, err
	}, func(network, address string) (net.PacketConn, error) {
		calls++
		if calls == 1 {
			return nil, denied
		}
		var err error
		packets, err = net.ListenPacket(network, address)
		return packets, err
	})
	if err != nil || calls < 2 || calls > 8 || packets == nil || addr.String() != packets.LocalAddr().String() {
		t.Fatal("DNS did not recover from an automatically selected UDP-denied port", calls, err)
	}
	e.Close()
	for _, listener := range listeners {
		assertDNSListenerReleased(t, e, listener, nil)
	}
	assertDNSListenerReleased(t, e, nil, packets)
}

func TestDNSDualBindFailureLimits(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		for _, permission := range []bool{false, true} {
			t.Run(itoa(boolInt(fixed))+"/"+itoa(boolInt(permission)), func(t *testing.T) {
				e := testServerEngine(t)
				address := "127.0.0.1:0"
				var reserved net.Listener
				if fixed {
					var err error
					reserved, err = net.Listen("tcp", address)
					if err != nil {
						t.Fatal(err)
					}
					defer reserved.Close()
					address = reserved.Addr().String()
				}
				var listeners []net.Listener
				var held []net.PacketConn
				defer func() {
					for _, packet := range held {
						packet.Close()
					}
				}()
				calls := 0
				denied := &net.OpError{Op: "listen", Net: "udp", Err: os.ErrPermission}
				addr, err := e.startDNS(address, func(network, requested string) (net.Listener, error) {
					if requested != address {
						t.Fatal("requested DNS address changed")
					}
					if len(listeners) != 0 {
						assertDNSListenerReleased(t, e, listeners[len(listeners)-1], nil)
					}
					l := reserved
					var err error
					if l == nil {
						l, err = net.Listen(network, requested)
					}
					if err == nil {
						listeners = append(listeners, l)
					}
					return l, err
				}, func(network, requested string) (net.PacketConn, error) {
					calls++
					if permission {
						return nil, denied
					}
					// Occupy the actual TCP-selected UDP port, then use the real
					// OS bind error. A pre-existing exclusion is also a bind failure.
					packet, err := net.ListenPacket(network, requested)
					if err != nil {
						return nil, err
					}
					held = append(held, packet)
					return net.ListenPacket(network, requested)
				})
				want := 8
				if fixed {
					want = 1
				}
				var opErr *net.OpError
				if addr != nil || calls != want || !errors.As(err, &opErr) || opErr.Net != "udp" || opErr.Op != "listen" {
					t.Fatal("DNS failure was lost or retries exceeded the port policy", calls, err)
				}
				if permission && !errors.Is(err, os.ErrPermission) {
					t.Fatal("UDP permission error was hidden", err)
				}
				for _, listener := range listeners {
					assertDNSListenerReleased(t, e, listener, nil)
				}
			})
		}
	}
}

func TestDNSDualBindOwnerStopAndTCPFailure(t *testing.T) {
	t.Run("tcp-error", func(t *testing.T) {
		e := testServerEngine(t)
		denied := &net.OpError{Op: "listen", Net: "tcp", Err: os.ErrPermission}
		tcpCalls, udpCalls := 0, 0
		addr, err := e.startDNS("127.0.0.1:0", func(string, string) (net.Listener, error) {
			tcpCalls++
			return nil, denied
		}, func(string, string) (net.PacketConn, error) {
			udpCalls++
			return nil, denied
		})
		if addr != nil || err != denied || tcpCalls != 1 || udpCalls != 0 {
			t.Fatal("TCP failure was retried or reached UDP", tcpCalls, udpCalls, err)
		}
	})
	for _, phase := range []string{"before-bind", "tcp-owned", "udp-created", "stop-accepting"} {
		t.Run(phase, func(t *testing.T) {
			e := testServerEngine(t)
			// Establish real paired sockets without making assumptions about
			// cross-transport availability of an automatically chosen port.
			var listener net.Listener
			var packet net.PacketConn
			var err error
			for trial := 0; trial < 8; trial++ {
				listener, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				packet, err = net.ListenPacket("udp", listener.Addr().String())
				if err == nil {
					break
				}
				listener.Close()
			}
			if err != nil {
				t.Fatal("test dual-port reservation", err)
			}
			defer listener.Close()
			defer packet.Close()
			if phase == "before-bind" {
				e.Close()
			}
			tcpCalls, udpCalls := 0, 0
			addr, err := e.startDNS("127.0.0.1:0", func(string, string) (net.Listener, error) {
				tcpCalls++
				if phase == "tcp-owned" {
					e.Close()
				}
				return listener, nil
			}, func(string, string) (net.PacketConn, error) {
				udpCalls++
				if phase == "stop-accepting" {
					e.StopAccepting()
				} else {
					e.Close()
				}
				return packet, nil
			})
			wantTCP, wantUDP := 1, 1
			if phase == "before-bind" {
				wantTCP, wantUDP = 0, 0
			} else if phase == "tcp-owned" {
				wantUDP = 0
			}
			if addr != nil || !errors.Is(err, net.ErrClosed) || tcpCalls != wantTCP || udpCalls != wantUDP {
				t.Fatal("DNS started or retried after owner shutdown", tcpCalls, udpCalls, err)
			}
			if tcpCalls != 0 {
				assertDNSListenerReleased(t, e, listener, nil)
			}
			if udpCalls != 0 {
				assertDNSListenerReleased(t, e, nil, packet)
			}
		})
	}
}

func assertDNSListenerReleased(t *testing.T, e *Engine, listener net.Listener, packet net.PacketConn) {
	t.Helper()
	if listener != nil {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		if c, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
			if c != nil {
				c.Close()
			}
			t.Fatal("DNS retained a failed or stopped TCP listener", err)
		}
	}
	if packet != nil {
		packet.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := packet.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("DNS retained a stopped UDP listener", err)
		}
	}
	e.mu.Lock()
	tracked := (listener != nil && e.closers[listener]) || (packet != nil && e.closers[packet])
	e.mu.Unlock()
	if tracked || e.Stats().Active != 0 {
		t.Fatal("DNS bind retained owner resources or flow admission")
	}
}
