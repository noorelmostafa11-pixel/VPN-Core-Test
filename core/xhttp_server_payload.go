package core

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const xServerPayloadChunkLimit = 128
const xServerPayloadEncodedLimit = 8192

type xServerPayloadPart struct {
	chunks            []string
	count, last, size int
}

func xServerPayloadSuffix(name, key string, separator byte, fold bool) (string, bool) {
	if len(name) <= len(key) || name[len(key)] != separator {
		return "", false
	}
	if name[:len(key)] != key && (!fold || !strings.EqualFold(name[:len(key)], key)) {
		return "", false
	}
	return name[len(key)+1:], true
}

func (p *xServerPayloadPart) add(suffix, value string) bool {
	index, err := strconv.Atoi(suffix)
	if err != nil || index < 0 || index >= xServerPayloadChunkLimit || strconv.Itoa(index) != suffix || value == "" || len(value) > xServerPayloadEncodedLimit-p.size {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	if p.chunks == nil {
		p.chunks = make([]string, xServerPayloadChunkLimit)
	}
	if p.chunks[index] != "" {
		return false
	}
	p.chunks[index] = value
	p.count++
	p.last = max(p.last, index)
	p.size += len(value)
	return true
}

func (p *xServerPayloadPart) valid() bool {
	if p.count == 0 {
		return true
	}
	if p.last+1 != p.count || p.size%4 == 1 {
		return false
	}
	// Strict raw Base64URL also requires unused low bits to be zero.
	last := p.chunks[p.last]
	value := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", last[len(last)-1])
	return !(p.size%4 == 2 && value&15 != 0 || p.size%4 == 3 && value&3 != 0)
}

type xServerPacketPlan struct {
	header, cookie                   xServerPayloadPart
	decoded, bodyLimit, bodyCapacity int
	allowBody                        bool
}

func xServerPlanPacket(r *http.Request, x XHTTPServerOptions) (plan xServerPacketPlan, status int) {
	for _, line := range r.Header.Values("Cookie") {
		if strings.ContainsAny(line, "\r\n\x00") {
			return plan, http.StatusBadRequest
		}
	}
	for name, values := range r.Header {
		if suffix, matched := xServerPayloadSuffix(name, x.UplinkDataKey, '-', true); matched {
			if len(values) != 1 || !plan.header.add(suffix, values[0]) {
				return plan, http.StatusBadRequest
			}
		}
	}
	for _, cookie := range r.Cookies() {
		if suffix, matched := xServerPayloadSuffix(cookie.Name, x.UplinkDataKey, '_', false); matched {
			if !plan.cookie.add(suffix, cookie.Value) {
				return plan, http.StatusBadRequest
			}
		}
	}
	if !plan.header.valid() || !plan.cookie.valid() || plan.header.size+plan.cookie.size > xServerPayloadEncodedLimit {
		return plan, http.StatusBadRequest
	}
	switch x.UplinkDataPlacement {
	case "body":
		if plan.header.count != 0 || plan.cookie.count != 0 {
			return plan, http.StatusBadRequest
		}
		plan.allowBody = true
	case "header":
		if plan.header.count == 0 || plan.cookie.count != 0 {
			return plan, http.StatusBadRequest
		}
	case "cookie":
		if plan.cookie.count == 0 || plan.header.count != 0 {
			return plan, http.StatusBadRequest
		}
	case "auto":
		plan.allowBody = true
	default:
		return plan, http.StatusBadRequest
	}
	if !plan.allowBody && (r.ContentLength > 0 || len(r.TransferEncoding) != 0) {
		return plan, http.StatusBadRequest
	}
	plan.decoded = base64.RawURLEncoding.DecodedLen(plan.header.size) + base64.RawURLEncoding.DecodedLen(plan.cookie.size)
	if plan.allowBody {
		plan.bodyLimit = xServerPostLimit - plan.decoded
		if r.ContentLength > int64(plan.bodyLimit) {
			return plan, http.StatusRequestEntityTooLarge
		}
		plan.bodyCapacity = plan.bodyLimit + 1
		if r.ContentLength >= 0 {
			plan.bodyCapacity = int(r.ContentLength) + 1
		}
	} else {
		plan.bodyCapacity = 1 // Read the actual empty body/FIN, including HTTP3.
	}
	return plan, 0
}

func (p *xServerPayloadPart) decode(dst, scratch []byte) (int, error) {
	offset := 0
	for _, chunk := range p.chunks[:p.count] {
		offset += copy(scratch[offset:], chunk)
	}
	return base64.RawURLEncoding.Strict().Decode(dst, scratch[:offset])
}

func (e *Engine) receiveXHTTPPacket(c *serverHTTP2Conn, session *xServerSession, seq uint64, plan xServerPacketPlan) {
	capacity := plan.decoded + plan.bodyCapacity
	scratchSize := plan.header.size + plan.cookie.size
	reserved := capacity + scratchSize
	if !session.manager.reserve(reserved) {
		xServerStatus(c, http.StatusServiceUnavailable)
		return
	}
	defer func() { session.manager.buffered.Add(-int64(reserved)) }()
	body := make([]byte, capacity)
	if scratchSize > 0 {
		scratch := make([]byte, scratchSize)
		n, err := plan.header.decode(body, scratch[:plan.header.size])
		if err != nil {
			xServerStatus(c, http.StatusBadRequest)
			return
		}
		if _, err = plan.cookie.decode(body[n:], scratch[plan.header.size:]); err != nil {
			xServerStatus(c, http.StatusBadRequest)
			return
		}
		session.manager.buffered.Add(-int64(scratchSize))
		reserved -= scratchSize
	}
	n, err := io.ReadFull(c, body[plan.decoded:])
	if n > plan.bodyLimit {
		status := http.StatusRequestEntityTooLarge
		if !plan.allowBody {
			status = http.StatusBadRequest
		}
		xServerStatus(c, status)
		return
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF || c.request.ContentLength >= 0 && int64(n) != c.request.ContentLength {
		xServerStatus(c, http.StatusBadRequest)
		return
	}
	if session.push(seq, xServerPacket{body: body[:plan.decoded+n], cost: capacity}) != nil {
		xServerStatus(c, http.StatusConflict)
		return
	}
	reserved = 0 // The session now owns the decoded backing allocation.
	xServerStatus(c, http.StatusOK)
}
