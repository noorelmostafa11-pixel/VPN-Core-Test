// Diagnostic-only verified-TLS HTTP1 hop. Never linked into the core or packages.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"
)

type traceBody struct {
	io.ReadCloser
	sum    hash.Hash
	prefix []byte
	count  int
}

func (b *traceBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.sum.Write(p[:n])
	b.count += n
	if len(b.prefix) < 56 {
		b.prefix = append(b.prefix, p[:min(n, 56-len(b.prefix))]...)
	}
	return n, err
}

type packetTrace struct {
	Session string `json:"session_sha256"`
	Seq     string `json:"seq"`
	Bytes   int    `json:"bytes"`
	SHA256  string `json:"sha256"`
	Header  bool   `json:"starts_trojan_header"`
}

func tracePacket(r *http.Request, body *traceBody) packetTrace {
	session := r.Header.Get("Meta-Session")
	if session == "" {
		session = r.URL.Query().Get("Meta-Session")
	}
	if session == "" {
		if cookie, err := r.Cookie("Meta-Session"); err == nil {
			session = cookie.Value
		}
	}
	id := sha256.Sum256([]byte(session))
	seq := r.URL.Query().Get("Meta-Sequence")
	if seq == "" {
		seq = r.Header.Get("Meta-Sequence")
	}
	key := sha256.Sum224([]byte("synthetic-reference-server-password"))
	return packetTrace{Session: hex.EncodeToString(id[:]), Seq: seq, Bytes: body.count,
		SHA256: hex.EncodeToString(body.sum.Sum(nil)), Header: string(body.prefix) == hex.EncodeToString(key[:])}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "loopback diagnostic listener")
	target := flag.String("target", "", "loopback native server URL")
	cert := flag.String("cert", "", "synthetic test CA/certificate")
	key := flag.String("key", "", "synthetic test key")
	flag.Parse()
	u, err := url.Parse(*target)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		log.Fatal("diagnostic target must be loopback HTTPS")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || host != "127.0.0.1" {
		log.Fatal("diagnostic listener must be IPv4 loopback")
	}
	pem, err := os.ReadFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		log.Fatal("invalid synthetic CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 8192, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport, proxy.FlushInterval = transport, -1
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(502) }
	var output sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			proxy.ServeHTTP(w, r)
			return
		}
		if r.ContentLength < 0 || r.ContentLength > 1048576 {
			w.WriteHeader(413)
			return
		}
		body := &traceBody{ReadCloser: r.Body, sum: sha256.New()}
		r.Body = body
		proxy.ServeHTTP(w, r)
		output.Lock()
		json.NewEncoder(os.Stdout).Encode(tracePacket(r, body))
		output.Unlock()
	})
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Printf("{\"listen\":%q}\n", ln.Addr().String())
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
		MaxHeaderBytes: 8192, TLSConfig: &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}}
	log.Fatal(server.ServeTLS(ln, *cert, *key))
}
