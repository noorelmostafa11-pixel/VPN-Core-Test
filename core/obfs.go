package core

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"
)

type obfsCodec struct {
	c                Config
	input            []byte
	sent, httpHeader bool
	stage            int
}

func itoa(n int) string                     { return strconv.Itoa(n) }
func obfsRecord(kind byte, b []byte) []byte { return join([]byte{kind, 3, 3}, word(len(b)), b) }
func (o *obfsCodec) encode(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if !o.sent {
		o.sent = true
		if o.c.Transport == "obfs-http" {
			method := option(o.c.PluginOptions, "GET", "obfs-http-method")
			if !httpToken(method) {
				return nil, errors.New("OBFS_HTTP_METHOD")
			}
			header := method + " " + httpPath(o.c) + " HTTP/1.1\r\nHost: " + httpHost(o.c) + "\r\nUser-Agent: curl/7.52.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(randomBytes(16)) + "\r\nContent-Length: " + itoa(len(b)) + "\r\n\r\n"
			return join([]byte(header), b), nil
		}
		host := httpHost(o.c)
		body := join([]byte{3, 3}, wide(uint64(time.Now().Unix()))[4:], randomBytes(28), []byte{32}, randomBytes(32))
		suites := []byte{0xc0, 0x2c, 0xc0, 0x30, 0, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0, 0x39, 0xc0, 9, 0xc0, 0x13, 0, 0x33, 0, 0x9d, 0, 0x9c, 0, 0x3d, 0, 0x3c, 0, 0x35, 0, 0x2f, 0, 0xff}
		body = join(body, word(len(suites)), suites, []byte{1, 0})
		ext := join([]byte{0, 0x23}, word(len(b)), b, word(0), word(len(host)+5), word(len(host)+3), []byte{0}, word(len(host)), []byte(host), []byte{0, 0xb, 0, 4, 3, 1, 0, 2, 0, 0xa, 0, 0xa, 0, 8, 0, 0x1d, 0, 0x17, 0, 0x19, 0, 0x18, 0, 0xd, 0, 0x20, 0, 0x1e, 6, 1, 6, 2, 6, 3, 5, 1, 5, 2, 5, 3, 4, 1, 4, 2, 4, 3, 3, 1, 3, 2, 3, 3, 2, 1, 2, 2, 2, 3, 0, 0x16, 0, 0, 0, 0x17, 0, 0})
		body = join(body, word(len(ext)), ext)
		hello := join([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body)
		out := obfsRecord(22, hello)
		out[2] = 1
		return out, nil
	}
	if o.c.Transport == "obfs-http" {
		return b, nil
	}
	var out []byte
	for len(b) > 0 {
		n := min(16384, len(b))
		out = append(out, obfsRecord(23, b[:n])...)
		b = b[n:]
	}
	return out, nil
}
func (o *obfsCodec) finish() []byte { return nil }
func (o *obfsCodec) decode(b []byte) ([]byte, error) {
	o.input = append(o.input, b...)
	if len(o.input) > 1048576 {
		return nil, errors.New("OBFS_INPUT_LIMIT")
	}
	if o.c.Transport == "obfs-http" {
		if !o.httpHeader {
			end := bytes.Index(o.input, []byte("\r\n\r\n"))
			if end < 0 {
				if len(o.input) > 65536 {
					return nil, errors.New("OBFS_HTTP_HEADER")
				}
				return nil, nil
			}
			resp, e := http.ReadResponse(bufio.NewReader(bytes.NewReader(o.input[:end+4])), &http.Request{Method: "GET"})
			if e != nil || resp.StatusCode != 101 {
				return nil, errors.New("OBFS_HTTP_STATUS")
			}
			o.input = o.input[end+4:]
			o.httpHeader = true
		}
		out := o.input
		o.input = nil
		return out, nil
	}
	var out []byte
	for len(o.input) >= 5 {
		kind := o.input[0]
		if o.input[1] != 3 || o.input[2] != 1 && o.input[2] != 3 {
			return nil, errors.New("OBFS_TLS_HEADER")
		}
		n := getWord(o.input, 3)
		if len(o.input) < n+5 {
			break
		}
		body := o.input[5 : n+5]
		o.input = o.input[n+5:]
		switch o.stage {
		case 0:
			if kind != 22 || len(body) < 4 || body[0] != 2 {
				return nil, errors.New("OBFS_TLS_SERVER_HELLO")
			}
		case 1:
			if kind != 20 || !bytes.Equal(body, []byte{1}) {
				return nil, errors.New("OBFS_TLS_CCS")
			}
		case 2:
			if kind != 22 {
				return nil, errors.New("OBFS_TLS_HANDSHAKE")
			}
			out = append(out, body...)
		default:
			if kind != 23 {
				return nil, errors.New("OBFS_TLS_RECORD")
			}
			out = append(out, body...)
		}
		o.stage++
	}
	return out, nil
}
