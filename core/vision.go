package core

import "errors"

type vision struct {
	c                                                                          Config
	enabled, prefix, writeDone, readDone, direct, tls13, probeDone, needHeader bool
	input, hello, handshake                                                    []byte
	command, content, padding                                                  int
}

func (v *vision) frame(cmd byte, data []byte, first bool) []byte {
	n := 1 + int(randomBytes(1)[0])
	if first {
		n = 900 + int(randomBytes(1)[0])
	}
	var b []byte
	if first {
		b = append(b, v.c.UUID[:]...)
	}
	return join(b, []byte{cmd}, word(len(data)), word(n), data, randomBytes(n))
}
func (v *vision) encode(b []byte) []byte {
	if !v.enabled || v.writeDone || len(b) == 0 {
		return b
	}
	v.writeDone = true
	return v.frame(1, b, false)
}
func getWord(b []byte, p int) int { return int(b[p])<<8 | int(b[p+1]) }
func (v *vision) probe(data []byte) {
	if v.probeDone || len(data) == 0 {
		return
	}
	if len(v.hello)+len(v.handshake)+len(data) > 32768 {
		v.probeDone = true
		return
	}
	v.hello = append(v.hello, data...)
	for len(v.hello) >= 5 {
		n := getWord(v.hello, 3)
		if v.hello[0] != 22 || v.hello[1] != 3 || v.hello[2] != 3 || n > 16384 {
			v.probeDone = true
			return
		}
		if len(v.hello) < n+5 {
			return
		}
		v.handshake = append(v.handshake, v.hello[5:n+5]...)
		v.hello = v.hello[n+5:]
		if len(v.handshake) < 4 {
			continue
		}
		b := v.handshake
		n = int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if b[0] != 2 || n < 38 || n > 32764 {
			v.probeDone = true
			return
		}
		if len(b) < n+4 {
			return
		}
		end := n + 4
		p := 38
		sid := int(b[p])
		p++
		if p+sid+5 > end {
			v.probeDone = true
			return
		}
		p += sid
		suite := getWord(b, p)
		p += 3
		ext := getWord(b, p)
		p += 2
		if p+ext != end {
			v.probeDone = true
			return
		}
		for p+4 <= end {
			k, l := getWord(b, p), getWord(b, p+2)
			p += 4
			if p+l > end {
				break
			}
			if k == 43 && l == 2 && getWord(b, p) == 0x0304 && suite >= 0x1301 && suite <= 0x1304 {
				v.tls13 = true
			}
			p += l
		}
		v.probeDone = true
		v.hello = nil
		v.handshake = nil
		return
	}
}
func (v *vision) decode(data []byte) ([]byte, error) {
	if !v.enabled || v.readDone {
		return data, nil
	}
	v.input = append(v.input, data...)
	if len(v.input) > 262144 {
		return nil, errors.New("VISION_LIMIT")
	}
	var out []byte
	if v.prefix {
		n := min(len(v.input), 16)
		if !bytesEqual(v.input[:n], v.c.UUID[:n]) {
			v.readDone = true
			out = v.input
			v.input = nil
			return out, nil
		}
		if len(v.input) < 16 {
			return nil, nil
		}
		v.input = v.input[16:]
		v.prefix = false
	}
	for {
		if v.needHeader {
			if len(v.input) < 5 {
				break
			}
			v.command = int(v.input[0])
			if v.command > 2 {
				return nil, errors.New("VISION_COMMAND")
			}
			v.content = getWord(v.input, 1)
			v.padding = getWord(v.input, 3)
			v.input = v.input[5:]
			v.needHeader = false
		}
		if v.content > 0 {
			n := min(v.content, len(v.input))
			part := v.input[:n]
			v.probe(part)
			out = append(out, part...)
			v.input = v.input[n:]
			v.content -= n
			if v.content > 0 {
				break
			}
		}
		if v.padding > 0 {
			n := min(v.padding, len(v.input))
			v.input = v.input[n:]
			v.padding -= n
			if v.padding > 0 {
				break
			}
		}
		if v.command == 0 {
			v.needHeader = true
			continue
		}
		if v.command == 2 {
			layered := v.c.Protocol == "vless" && v.c.Encryption != "" && v.c.Encryption != "none"
			if !v.tls13 || v.c.Transport != "raw" && !layered {
				return nil, errors.New("VISION_DIRECT_SECURITY")
			}
			v.direct = true
		}
		v.readDone = true
		out = append(out, v.input...)
		v.input = nil
		break
	}
	return out, nil
}
