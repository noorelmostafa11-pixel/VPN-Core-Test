// Independent stdlib HTTP server. It relays to a Python protocol/crypto oracle.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	Target, Cert, Key, Path, Mode, SessionPlacement, SessionKey, SeqPlacement, SeqKey, DataPlacement, DataKey, PaddingPlacement, PaddingKey, PaddingHeader, Method, Table string
	SessionLength, PaddingMin, PaddingMax                                                                                                                                 int
	ECH, TLS, H2, H3, Legacy, NoGRPC, Obfs, Split                                                                                                                         bool
	Bad                                                                                                                                                                   string
}
type session struct {
	conn net.Conn
	mu   sync.Mutex
	seq  uint64
}

var cfg config
var sessions sync.Map
var sessionMu sync.Mutex

func fail(w http.ResponseWriter, message string) {
	fmt.Fprintln(os.Stderr, "PEER_VALIDATION:", message)
	http.Error(w, "invalid", 422)
}
func metadata(r *http.Request, placement, key string, index int) (string, error) {
	switch placement {
	case "path":
		tail := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(cfg.Path, "/")+"/")
		parts := strings.Split(tail, "/")
		if index >= len(parts) {
			return "", fmt.Errorf("metadata path")
		}
		return parts[index], nil
	case "query":
		return r.URL.Query().Get(key), nil
	case "header":
		return r.Header.Get(key), nil
	case "cookie":
		c, e := r.Cookie(key)
		if e != nil {
			return "", e
		}
		return c.Value, nil
	}
	return "", fmt.Errorf("placement")
}
func handler(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).EnableFullDuplex()
	if cfg.H3 && r.ProtoMajor != 3 {
		fail(w, "HTTP3 required")
		return
	}
	if cfg.H2 && r.ProtoMajor != 2 {
		fail(w, "HTTP2 required")
		return
	}
	if !cfg.H2 && !cfg.H3 && r.ProtoMajor != 1 {
		fail(w, "HTTP1 required")
		return
	}
	if cfg.Bad == "status" {
		w.WriteHeader(503)
		return
	}
	padding := ""
	place, key, header := cfg.PaddingPlacement, cfg.PaddingKey, cfg.PaddingHeader
	if !cfg.Obfs {
		place, key, header = "queryInHeader", "x_padding", "Referer"
	}
	switch place {
	case "queryInHeader":
		u, e := url.Parse(r.Header.Get(header))
		if e == nil {
			padding = u.Query().Get(key)
		}
	case "header":
		padding = r.Header.Get(header)
	case "query":
		padding = r.URL.Query().Get(key)
	case "cookie":
		c, e := r.Cookie(key)
		if e == nil {
			padding = c.Value
		}
	}
	if cfg.Legacy {
		if r.URL.Path != cfg.Path || r.Method != "PUT" || padding != "" || r.Header.Get("Content-Type") != "" {
			fail(w, "legacy request")
			return
		}
	}
	if !cfg.Legacy && (len(padding) < cfg.PaddingMin || len(padding) > cfg.PaddingMax) {
		fail(w, "padding")
		return
	}
	id := "one-" + r.RemoteAddr
	seq := ""
	var err error
	packet := false
	if cfg.Mode != "stream-one" {
		id, err = metadata(r, cfg.SessionPlacement, cfg.SessionKey, 0)
		if err != nil || id == "" {
			fail(w, "session")
			return
		}
		if cfg.SessionLength > 0 && len(id) != cfg.SessionLength {
			fail(w, "session length")
			return
		}
		if cfg.Table != "" {
			for _, ch := range id {
				if !strings.ContainsRune(cfg.Table, ch) {
					fail(w, "session table")
					return
				}
			}
		}
		index := 0
		if cfg.SessionPlacement == "path" {
			index = 1
		}
		seq, _ = metadata(r, cfg.SeqPlacement, cfg.SeqKey, index)
		packet = seq != ""
	}
	sessionMu.Lock()
	value, ok := sessions.Load(id)
	if !ok {
		conn, e := net.DialTimeout("tcp", cfg.Target, 3*time.Second)
		if e != nil {
			sessionMu.Unlock()
			fail(w, "target")
			return
		}
		value = &session{conn: conn}
		sessions.Store(id, value)
	}
	sessionMu.Unlock()
	s := value.(*session)
	if packet {
		if r.Method != cfg.Method {
			fail(w, "upload method")
			return
		}
		data := []byte{}
		switch cfg.DataPlacement {
		case "body":
			data, err = io.ReadAll(io.LimitReader(r.Body, 1048577))
		case "header", "cookie":
			var encoded strings.Builder
			for i := 0; ; i++ {
				name := fmt.Sprintf("%s-%d", cfg.DataKey, i)
				chunk := ""
				if cfg.DataPlacement == "header" {
					chunk = r.Header.Get(name)
				} else {
					name = fmt.Sprintf("%s_%d", cfg.DataKey, i)
					c, e := r.Cookie(name)
					if e == nil {
						chunk = c.Value
					}
				}
				if chunk == "" {
					break
				}
				encoded.WriteString(chunk)
			}
			data, err = base64.RawURLEncoding.DecodeString(encoded.String())
		}
		if err != nil || len(data) == 0 {
			fail(w, "packet payload")
			return
		}
		sequence, e := strconv.ParseUint(seq, 10, 64)
		s.mu.Lock()
		if e != nil || sequence != s.seq {
			s.mu.Unlock()
			fail(w, "packet order")
			return
		}
		s.seq++
		_, err = s.conn.Write(data)
		s.mu.Unlock()
		if err != nil {
			fail(w, "packet write")
			return
		}
		w.WriteHeader(200)
		return
	}
	upload := r.Method == cfg.Method
	if upload && cfg.Mode != "packet-up" {
		if !cfg.NoGRPC && r.Header.Get("Content-Type") != "application/grpc" {
			fail(w, "upload content type")
			return
		}
		if cfg.NoGRPC && r.Header.Get("Content-Type") != "" {
			fail(w, "suppressed content type")
			return
		}
		go func() { _, _ = io.Copy(s.conn, r.Body) }()
	}
	if cfg.Mode == "stream-up" && upload {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if cfg.Bad == "encoding" {
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.WriteHeader(200)
	w.(http.Flusher).Flush()
	buffer := make([]byte, 16001)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, e := s.conn.Read(buffer)
		if n > 0 {
			if _, err = w.Write(buffer[:n]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		if e != nil {
			return
		}
	}
}
func echConfig(key []byte) []byte {
	name := []byte("public.test")
	body := []byte{42, 0, 32, 0, 32}
	body = append(body, key...)
	body = append(body, 0, 4, 0, 1, 0, 1, 64, byte(len(name)))
	body = append(body, name...)
	body = append(body, 0, 0)
	out := []byte{0xfe, 0x0d, byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func main() {
	path := flag.String("config", "", "fixture config")
	flag.Parse()
	b, e := os.ReadFile(*path)
	if e != nil || json.Unmarshal(b, &cfg) != nil {
		panic("fixture config")
	}
	if cfg.H3 {
		cert, e := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if e != nil {
			panic(e)
		}
		conn, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			panic(e)
		}
		fmt.Println(conn.LocalAddr().String())
		server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, Handler: http.HandlerFunc(handler)}
		_ = server.Serve(conn)
		return
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		panic(e)
	}
	fmt.Println(l.Addr().String())
	server := &http.Server{Handler: http.HandlerFunc(handler), MaxHeaderBytes: 1048576}
	if cfg.TLS {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.ECH {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			config := echConfig(key.PublicKey().Bytes())
			list := append([]byte{byte(len(config) >> 8), byte(len(config))}, config...)
			server.TLSConfig.MinVersion = tls.VersionTLS13
			server.TLSConfig.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}}
			fmt.Println(base64.StdEncoding.EncodeToString(list))
		}
		if cfg.H2 {
			server.TLSConfig.NextProtos = []string{"h2"}
		} else {
			server.TLSConfig.NextProtos = []string{"http/1.1"}
			server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
		if cfg.Split {
			second, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				panic(e)
			}
			fmt.Println("DOWN " + second.Addr().String())
			clone := *server
			go func() { _ = clone.ServeTLS(second, cfg.Cert, cfg.Key) }()
		}
		_ = server.ServeTLS(l, cfg.Cert, cfg.Key)
	} else {
		if cfg.Split {
			second, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				panic(e)
			}
			fmt.Println("DOWN " + second.Addr().String())
			clone := *server
			go func() { _ = clone.Serve(second) }()
		}
		_ = server.Serve(l)
	}
}
