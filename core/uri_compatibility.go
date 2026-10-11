package core

import (
	"encoding/json"
	"strings"
)

func extraWhitespace(s string) string {
	var out strings.Builder
	quote := rune(0)
	escaped := false
	a := []rune(s)
	for i, ch := range a {
		if quote != 0 {
			out.WriteRune(ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == quote {
				quote = 0
			}
		} else if ch == '\'' || ch == '"' {
			quote = ch
			out.WriteRune(ch)
		} else if ch == '+' {
			exponent := i > 0 && (a[i-1] == 'e' || a[i-1] == 'E') && i+1 < len(a) && a[i+1] >= '0' && a[i+1] <= '9'
			if exponent {
				out.WriteRune('+')
			} else {
				out.WriteRune(' ')
			}
		} else {
			out.WriteRune(ch)
		}
	}
	return out.String()
}
func extraQuotes(s string) string {
	var out strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote == 0 {
			if ch == '"' || ch == '\'' {
				quote = ch
				out.WriteByte('"')
			} else {
				out.WriteByte(ch)
			}
			continue
		}
		if ch == '\\' {
			if i+1 == len(s) {
				return s
			}
			i++
			next := s[i]
			if quote == '\'' && next == '\'' {
				out.WriteByte('\'')
			} else {
				out.WriteByte('\\')
				out.WriteByte(next)
			}
		} else if ch == quote {
			out.WriteByte('"')
			quote = 0
		} else if quote == '\'' && ch == '"' {
			out.WriteString("\\\"")
		} else {
			out.WriteByte(ch)
		}
	}
	if quote != 0 {
		return s
	}
	return out.String()
}
func compatibleExtra(s string) (json.RawMessage, string) {
	object := func(s string) bool {
		var m map[string]json.RawMessage
		return json.Unmarshal([]byte(s), &m) == nil && m != nil
	}
	space := extraWhitespace(s)
	if space != s && object(space) {
		return []byte(space), "XHTTP_EXTRA_PLUS_WHITESPACE"
	}
	quotes := extraQuotes(space)
	if quotes != space && object(quotes) {
		strategy := "XHTTP_EXTRA_SINGLE_QUOTES"
		if space != s {
			strategy = "XHTTP_EXTRA_QUOTES_AND_WHITESPACE"
		}
		return []byte(quotes), strategy
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "%7b") {
		twice := decode(s)
		if twice != s && object(twice) {
			return []byte(twice), "XHTTP_EXTRA_DOUBLE_URL_ENCODING"
		}
	}
	return nil, ""
}
