// Independent TLS 1.3 oracle: close the send direction, then drain uploads.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	cert := flag.String("cert", "", "fixture certificate")
	key := flag.String("key", "", "fixture key")
	ready := flag.String("ready", "", "port JSON")
	result := flag.String("result", "", "oracle result JSON")
	flag.Parse()
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		panic(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	b, _ := json.Marshal(map[string]int{"port": l.Addr().(*net.TCPAddr).Port})
	if err = os.WriteFile(*ready, b, 0600); err != nil {
		panic(err)
	}
	raw, err := l.Accept()
	if err != nil {
		panic(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(25 * time.Second))
	s := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err = s.Handshake(); err != nil {
		panic(err)
	}
	h := make([]byte, 18)
	if _, err = io.ReadFull(s, h); err != nil {
		panic(err)
	}
	identity, _ := hex.DecodeString("12345678123445679234567812345678")
	if h[0] != 0 || !bytes.Equal(h[1:17], identity) {
		panic("VLESS identity")
	}
	if h[17] > 0 {
		if _, err = io.CopyN(io.Discard, s, int64(h[17])); err != nil {
			panic(err)
		}
	}
	target := make([]byte, 4)
	if _, err = io.ReadFull(s, target); err != nil {
		panic(err)
	}
	if target[0] != 1 {
		panic("VLESS TCP command")
	}
	count := 4
	switch target[3] {
	case 1:
	case 3:
		count = 16
	default:
		panic("VLESS address type")
	}
	if _, err = io.CopyN(io.Discard, s, int64(count)); err != nil {
		panic(err)
	}
	if _, err = s.Write(append([]byte{0, 0}, []byte("SERVER-FIRST: independent peer\n")...)); err != nil {
		panic(err)
	}
	if err = s.CloseWrite(); err != nil {
		panic(err)
	} // authenticated EOF, upload is still legal
	time.Sleep(150 * time.Millisecond) // force the client's bounded carrier backlog
	digest := sha256.New()
	var received int64
	block:=make([]byte,4096)
	for {
		n,readError:=s.Read(block)
		if n>0{digest.Write(block[:n]);received+=int64(n);time.Sleep(10*time.Millisecond)}
		if readError!=nil{if readError!=io.EOF{err=readError};break}
	}
	status := "PASS"
	if err != nil {
		status = "FAIL"
	}
	b, _ = json.Marshal(map[string]interface{}{"status": status, "bytes": received, "sha256": hex.EncodeToString(digest.Sum(nil)), "tls_version": s.ConnectionState().Version})
	if err = os.WriteFile(*result, b, 0600); err != nil {
		panic(err)
	}
}
