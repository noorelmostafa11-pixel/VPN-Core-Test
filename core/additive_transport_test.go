package core_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

const additiveID = "11111111-2222-4333-8444-555555555555"

func additivePort(t *testing.T) int {
	t.Helper()
	for range 64 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
		l.Close()
		if err != nil {
			continue
		}
		u.Close()
		return port
	}
	t.Fatal("no free TCP/UDP port pair")
	return 0
}

func additiveTCPExchange(t *testing.T, v *core.Instance, target xnet.Destination) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, v, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := bytes.Repeat([]byte{0, 255, 0x5a}, 40001)
	done := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(body); {
			size := min(1473, len(body)-offset)
			n, e := conn.Write(body[offset : offset+size])
			if e != nil {
				done <- e
				return
			}
			if n != size {
				done <- io.ErrShortWrite
				return
			}
			offset += n
		}
		got := make([]byte, len(body))
		_, e := io.ReadFull(conn, got)
		if e == nil && !bytes.Equal(got, body) {
			e = fmt.Errorf("TCP application bytes changed")
		}
		done <- e
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		conn.Close()
		<-done
		t.Fatal("TCP exchange timed out")
	}
}

func additiveNode(t *testing.T, variant string, port int, parameters map[string]string) (*conf.NodeDescription, map[string]any, string) {
	t.Helper()
	node := &conf.NodeDescription{Version: 1, Protocol: variant, Address: "127.0.0.1", Port: uint16(port), Credentials: conf.NodeCredentials{ID: additiveID}, Parameters: parameters}
	settings := map[string]any{"clients": []any{map[string]any{"id": additiveID}}}
	protocol := variant
	if variant == "vless" {
		settings["decryption"] = "none"
	}
	if variant == "vmess" {
		parameters["encryption"] = "aes-128-gcm"
	}
	if variant == "trojan" {
		password := "additive-synthetic-password"
		node.Credentials = conf.NodeCredentials{Password: &password}
		settings = map[string]any{"clients": []any{map[string]any{"password": password}}}
	}
	if variant == "ss" || variant == "ss2022" {
		method, password := "aes-128-gcm", "additive-synthetic-password"
		if variant == "ss2022" {
			method, password = "2022-blake3-aes-128-gcm", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x47}, 16))
		}
		node.Protocol, protocol = "ss", "shadowsocks"
		node.Credentials = conf.NodeCredentials{Method: method, Password: &password}
		settings = map[string]any{"method": method, "password": password, "network": "tcp,udp"}
	}
	return node, settings, protocol
}

func additiveURI(node *conf.NodeDescription) []byte {
	user := url.User(node.Credentials.ID)
	if node.Protocol == "ss" {
		user = url.UserPassword(node.Credentials.Method, *node.Credentials.Password)
	}
	if node.Protocol == "trojan" {
		user = url.User(*node.Credentials.Password)
	}
	query := url.Values{}
	for key, value := range node.Parameters {
		query.Set(key, value)
	}
	return []byte(node.Protocol + "://" + user.String() + "@127.0.0.1:" + strconv.Itoa(int(node.Port)) + "?" + query.Encode())
}

func additiveClient(t *testing.T, node *conf.NodeDescription, format string) *core.Instance {
	t.Helper()
	var v *core.Instance
	var err error
	if format == "go" {
		selection, e := conf.ResolveNode(node)
		if e != nil {
			t.Fatal(e)
		}
		config, e := (&conf.Config{OutboundConfigs: []conf.OutboundDetourConfig{*selection.Outbound}}).Build()
		if e != nil {
			t.Fatal(e)
		}
		v, err = core.New(config)
		if err == nil {
			err = v.Start()
		}
	} else {
		data := additiveURI(node)
		switch format {
		case "node":
			data, err = json.Marshal(node)
		case "subjson":
			data, err = json.Marshal([]*conf.NodeDescription{node})
		case "subscription":
			data = []byte(base64.StdEncoding.EncodeToString(data))
		}
		if err == nil {
			v, err = core.StartInstance(format, data)
		}
	}
	if err != nil {
		if v != nil {
			v.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func additiveServer(t *testing.T, port int, protocol string, settings, stream map[string]any) {
	t.Helper()
	scopeInstance(t, map[string]any{
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings, "streamSettings": stream}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}},
	})
}

// Exercise original server JSON against each new metadata importer, with exact
// fragmented TCP bytes and UDP boundaries through the real four proxy paths.
func TestAddedFourProtocolTransportRuntime(t *testing.T) {
	tcp, udp := scopeEchoTargets(t)
	for _, variant := range []string{"vless", "vmess", "trojan", "ss", "ss2022"} {
		for _, carrier := range []string{"tcp-http", "mkcp", "ws", "httpupgrade", "h2c", "grpc", "quic-bbr", "quic-brutal"} {
			t.Run(variant+"/"+carrier, func(t *testing.T) {
				parameters := map[string]string{"security": "none"}
				stream := map[string]any{}
				switch carrier {
				case "tcp-http":
					parameters["type"], parameters["headerType"], parameters["host"], parameters["path"] = "tcp", "http", "front.example.invalid", "/edge"
					stream = map[string]any{"network": "tcp", "tcpSettings": map[string]any{"header": map[string]any{"type": "http", "request": map[string]any{"path": []string{"/edge"}, "headers": map[string]any{"Host": []string{"front.example.invalid"}}}}}}
				case "mkcp":
					parameters["type"], parameters["headerType"], parameters["seed"], parameters["tti"] = "mkcp", "srtp", "synthetic-seed", "35"
					parameters["mtu"], parameters["cwndMultiplier"], parameters["maxSendingWindow"] = "1350", "2", "2097152"
					stream = map[string]any{"network": "mkcp", "kcpSettings": map[string]any{"mtu": 1350, "tti": 35, "cwndMultiplier": 2, "maxSendingWindow": 2097152}, "finalmask": map[string]any{"udp": []any{map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"value": "synthetic-seed"}}, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"header": "srtp"}}}}}
				case "ws", "httpupgrade":
					parameters["type"], parameters["host"], parameters["path"], parameters["ed"] = carrier, "front.example.invalid", "/edge", "256"
					parameters["headers"] = `{"X-Route":"synthetic","X-Session":"staged"}`
					key := "wsSettings"
					if carrier == "httpupgrade" {
						key = "httpupgradeSettings"
					}
					stream = map[string]any{"network": carrier, key: map[string]any{"host": "front.example.invalid", "path": "/edge"}}
				case "h2c":
					parameters["type"], parameters["host"], parameters["path"], parameters["httpMethod"] = "h2c", "front.example.invalid", "/edge", "PATCH"
					parameters["httpHeaders"], parameters["httpReadIdleTimeout"], parameters["httpHealthCheckTimeout"] = `{"X-Route":"synthetic"}`, "2", "1"
					stream = map[string]any{"network": "h2c", "httpSettings": map[string]any{"host": []string{"front.example.invalid"}, "path": "/edge", "method": "PATCH"}}
				case "grpc":
					parameters["type"], parameters["serviceName"], parameters["grpcUserAgent"] = "grpc", "synthetic", "SyntheticAgent"
					parameters["grpcIdleTimeout"], parameters["grpcHealthCheckTimeout"], parameters["grpcInitialWindowSize"], parameters["grpcPermitWithoutStream"] = "60", "5", "65535", "true"
					stream = map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "synthetic"}}
				case "quic-bbr", "quic-brutal":
					parameters["type"], parameters["security"], parameters["sni"] = "quic", "tls", "additive.example"
					certificate, pin := cert.MustGenerate(nil, cert.DNSNames("additive.example"))
					parameters["pcs"] = hex.EncodeToString(pin[:])
					parameters["quicParams"] = `{"congestion":"bbr","bbrProfile":"conservative","maxIdleTimeout":30,"keepAlivePeriod":5,"maxIncomingStreams":16}`
					if carrier == "quic-brutal" {
						parameters["quicParams"] = `{"congestion":"force-brutal","brutalUp":"2 mbps","brutalDown":"4 mbps","brutalDisableLossCompensation":true}`
					}
					stream = map[string]any{"network": "quic", "security": "tls", "quicSettings": map[string]any{"security": "none"}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate}))}, "key": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: certificate.PrivateKey}))}}}}}
				}
				port := additivePort(t)
				node, settings, protocol := additiveNode(t, variant, port, parameters)
				// Native Shadowsocks UDP is a separate UDP endpoint. A UDP
				// carrier already owns this port; it does not tunnel SS UDP.
				tcpOnly := protocol == "shadowsocks" && (carrier == "mkcp" || carrier == "quic-bbr" || carrier == "quic-brutal")
				if tcpOnly {
					settings["network"] = "tcp"
				}
				additiveServer(t, port, protocol, settings, stream)
				for _, format := range []string{"uri", "node", "go"} {
					t.Run(format, func(t *testing.T) {
						client := additiveClient(t, node, format)
						if tcpOnly {
							additiveTCPExchange(t, client, tcp)
						} else {
							scopeExchange(t, client, tcp, udp)
						}
					})
				}
			})
		}
	}
}

// Distinct HTTP frontends prove the download metadata reaches the download
// connection. Its independent TLS certificate is trusted only by the supplied
// pin; the two peers enforce different methods, authorities and header values.
func TestAddedFourProtocolXHTTPDownloadAndSubscriptions(t *testing.T) {
	tcp, udp := scopeEchoTargets(t)
	for _, variant := range []string{"vless", "vmess", "trojan", "ss", "ss2022"} {
		t.Run(variant, func(t *testing.T) {
			port := additivePort(t)
			parameters := map[string]string{"type": "xhttp", "security": "none", "host": "upload.example.invalid", "path": "/split", "mode": "packet-up"}
			node, settings, protocol := additiveNode(t, variant, port, parameters)
			additiveServer(t, port, protocol, settings, map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/split", "mode": "packet-up", "xPaddingBytes": "16-32"}})
			target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			var uploads, downloads, rejected atomic.Int32
			front := func(download bool) *httptest.Server {
				proxy := httputil.NewSingleHostReverseProxy(target)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					valid := r.Method == "POST" && r.Host == "upload.example.invalid" && r.Header.Get("X-Leg") == "upload"
					if download {
						valid = r.Method == "GET" && r.Host == "download.example.invalid" && r.Header.Get("X-Leg") == "download"
					}
					if !valid {
						rejected.Add(1)
						w.WriteHeader(400)
						return
					}
					if download {
						downloads.Add(1)
					} else {
						uploads.Add(1)
					}
					proxy.ServeHTTP(w, r)
				}))
				if download {
					server.StartTLS()
				} else {
					server.Start()
				}
				t.Cleanup(server.Close)
				return server
			}
			upload, download := front(false), front(true)
			node.Port = uint16(upload.Listener.Addr().(*net.TCPAddr).Port)
			if protocol == "shadowsocks" {
				udpSettings := map[string]any{"method": settings["method"], "password": settings["password"], "network": "udp"}
				additiveServer(t, int(node.Port), protocol, udpSettings, map[string]any{"network": "tcp"})
			}
			pin := sha256.Sum256(download.Certificate().Raw)
			extra := map[string]any{"headers": map[string]string{"X-Leg": "upload"}, "xPaddingBytes": "16-32", "downloadSettings": map[string]any{
				"address": "127.0.0.1", "port": download.Listener.Addr().(*net.TCPAddr).Port, "network": "xhttp", "security": "tls",
				"tlsSettings":   map[string]any{"serverName": "example.com", "pinnedPeerCertSha256": hex.EncodeToString(pin[:]), "fingerprint": "unsafe", "alpn": []string{"http/1.1"}},
				"xhttpSettings": map[string]any{"host": "download.example.invalid", "path": "/split", "mode": "packet-up", "headers": map[string]string{"X-Leg": "download"}, "xPaddingBytes": "16-32", "xmux": map[string]any{"maxConnections": 1}},
			}}
			body, err := json.Marshal(extra)
			if err != nil {
				t.Fatal(err)
			}
			parameters["extra"] = string(body)
			for _, format := range []string{"uri", "node", "go", "subscription", "subjson"} {
				t.Run(format, func(t *testing.T) { scopeExchange(t, additiveClient(t, node, format), tcp, udp) })
			}
			if uploads.Load() < 5 || downloads.Load() < 5 || rejected.Load() != 0 {
				t.Fatalf("upload/download endpoints were not used correctly: %d/%d/%d", uploads.Load(), downloads.Load(), rejected.Load())
			}
			if variant == "vless" {
				t.Run("reject-wrong-download-pin", func(t *testing.T) {
					extra["downloadSettings"].(map[string]any)["tlsSettings"].(map[string]any)["pinnedPeerCertSha256"] = hex.EncodeToString(bytes.Repeat([]byte{0x7f}, 32))
					body, err := json.Marshal(extra)
					if err != nil {
						t.Fatal(err)
					}
					parameters["extra"] = string(body)
					client := additiveClient(t, node, "uri")
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					conn, err := core.Dial(ctx, client, tcp)
					if err != nil {
						return
					}
					defer conn.Close()
					if _, err = conn.Write([]byte("untrusted-download")); err != nil {
						return
					}
					done := make(chan error, 1)
					go func() { _, e := conn.Read(make([]byte, 1)); done <- e }()
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("download certificate pin was ignored")
						}
					case <-ctx.Done():
						conn.Close()
						<-done
						t.Fatal("bad download pin did not fail promptly")
					}
				})
			}
		})
	}
}
