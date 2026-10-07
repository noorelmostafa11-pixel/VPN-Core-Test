package main

import (
	"bytes"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Exercise the same asynchronous queues and HTTP/TLS workers used by the C ABI
// inside a Go executable: the container cannot map the C-shared TSan runtime.
func TestConcurrentHTTPQueues(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		buffer := make([]byte, 701)
		for {
			n, e := r.Body.Read(buffer)
			if n > 0 {
				_, _ = w.Write(buffer[:n])
				w.(http.Flusher).Flush()
			}
			if e != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			s := &xSession{up: newByteQueue(), down: newByteQueue()}
			cfg := xSettings{Server: host, Port: port, Path: "/test", Mode: "stream-one", TLS: settings{Security: "tls", ServerName: host, Fingerprint: []string{"native", "chrome", "firefox"}[i%3], ALPN: []string{"h2"}, CAFile: ca, TimeoutMS: 10000}}
			go s.run(cfg)
			payload := bytes.Repeat([]byte{byte(i), 17, 23, 29}, 75001)
			writeDone := make(chan error, 1)
			go func() {
				for offset := 0; offset < len(payload); offset += 16384 {
					end := min(len(payload), offset+16384)
					if _, e := s.up.Write(payload[offset:end]); e != nil {
						writeDone <- e
						return
					}
				}
				s.up.close(nil)
				writeDone <- nil
			}()
			defer func() {
				s.mu.Lock()
				cancel := s.cancel
				s.mu.Unlock()
				if cancel != nil {
					cancel()
				}
				s.up.close(nil)
				s.down.close(nil)
			}()
			timer := time.AfterFunc(15*time.Second, func() { s.up.close(io.ErrUnexpectedEOF); s.down.close(io.ErrUnexpectedEOF) })
			defer timer.Stop()
			data, e := io.ReadAll(s.down)
			if e != nil || !bytes.Equal(data, payload) {
				t.Errorf("queue %d length=%d error=%v", i, len(data), e)
			}
			if e = <-writeDone; e != nil {
				t.Errorf("write %d: %v", i, e)
			}
		}(i)
	}
	workers.Wait()
}
