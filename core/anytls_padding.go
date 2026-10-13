package core

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

// These are public protocol identifiers; the implementation is project code.
const (
	anyWaste byte = iota
	anySYN
	anyPSH
	anyFIN
	anySettings
	anyAlert
	anyPadding
	anySYNACK
	anyHeartRequest
	anyHeartResponse
	anyServerSettings
)
const anyDefaultPadding = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"

type anyPadSize struct {
	low, high int
	check     bool
}
type anyPadScheme struct {
	text, hash string
	stop       int
	packets    map[int][]anyPadSize
}

func parseAnyPadding(text string) (*anyPadScheme, error) {
	bad := errors.New("ANYTLS_PADDING_INVALID")
	if len(text) == 0 || len(text) > 8192 {
		return nil, bad
	}
	p := &anyPadScheme{text: text, packets: map[int][]anyPadSize{}}
	digest := md5.Sum([]byte(text))
	p.hash = hex.EncodeToString(digest[:]) // protocol metadata, not authentication
	seen := map[string]bool{}
	hasStop := false
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || seen[k] {
			return nil, bad
		}
		seen[k] = true
		if k == "stop" {
			n, err := number(v, 0, 64)
			if err != nil {
				return nil, bad
			}
			p.stop = n
			hasStop = true
			continue
		}
		packet, err := number(k, 0, 63)
		if err != nil {
			return nil, bad
		}
		var sizes []anyPadSize
		total := 0
		for _, item := range strings.Split(v, ",") {
			if len(sizes) >= 16 {
				return nil, bad
			}
			if item == "c" {
				if packet == 0 {
					return nil, bad
				}
				sizes = append(sizes, anyPadSize{check: true})
				continue
			}
			lo, hi, ok := strings.Cut(item, "-")
			if !ok {
				return nil, bad
			}
			l, e1 := number(lo, 0, 16384)
			h, e2 := number(hi, l, 16384)
			if e1 != nil || e2 != nil {
				return nil, bad
			}
			total += h
			if total > 65536 {
				return nil, bad
			}
			sizes = append(sizes, anyPadSize{low: l, high: h})
		}
		if packet == 0 && (len(sizes) != 1 || sizes[0].check) {
			return nil, bad
		}
		p.packets[packet] = sizes
	}
	if !hasStop {
		return nil, bad
	}
	return p, nil
}
func anyFrame(command byte, id uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = command
	binary.BigEndian.PutUint32(b[1:], id)
	binary.BigEndian.PutUint16(b[5:], uint16(len(data)))
	copy(b[7:], data)
	return b
}
func padChoice(s anyPadSize) int {
	if s.low == s.high {
		return s.low
	}
	b := randomBytes(4)
	return s.low + int(binary.BigEndian.Uint32(b)%uint32(s.high-s.low+1))
}
func (s *anyPadScheme) authPadding() []byte {
	if sizes := s.packets[0]; s.stop > 0 && len(sizes) == 1 {
		return randomBytes(padChoice(sizes[0]))
	}
	return nil
}
func (s *anyPadScheme) write(conn net.Conn, packet int, data []byte) error {
	if packet >= s.stop {
		return writeAll(conn, data)
	}
	for _, size := range s.packets[packet] {
		if size.check {
			if len(data) == 0 {
				return nil
			}
			continue
		}
		n := padChoice(size)
		if n == 0 {
			continue
		}
		if len(data) >= n {
			if err := writeAll(conn, data[:n]); err != nil {
				return err
			}
			data = data[n:]
			continue
		}
		// A waste frame includes its seven-byte header. Do not invent padding
		// bytes outside a frame when the remaining gap is smaller than that.
		gap := n - len(data)
		if gap >= 7 {
			waste := anyFrame(anyWaste, 0, make([]byte, gap-7))
			chunk := make([]byte, 0, n)
			chunk = append(chunk, data...)
			chunk = append(chunk, waste...)
			if err := writeAll(conn, chunk); err != nil {
				return err
			}
			data = nil
		} else if len(data) > 0 {
			if err := writeAll(conn, data); err != nil {
				return err
			}
			data = nil
		}
	}
	if len(data) > 0 {
		return writeAll(conn, data)
	}
	return nil
}
func parseAnySettings(data []byte) (map[string]string, error) {
	if len(data) > 4096 {
		return nil, errors.New("ANYTLS_SETTINGS_INVALID")
	}
	out := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || seen[k] || len(out) >= 32 {
			return nil, errors.New("ANYTLS_SETTINGS_INVALID")
		}
		out[k] = v
		seen[k] = true
	}
	version, err := strconv.Atoi(out["v"])
	if err != nil || version < 1 || version > 2 {
		return nil, errors.New("ANYTLS_VERSION_UNSUPPORTED")
	}
	return out, nil
}
