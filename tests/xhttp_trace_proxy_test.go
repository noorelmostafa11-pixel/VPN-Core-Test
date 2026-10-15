package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTracePreservesBytesAndRedactsMetadata(t *testing.T) {
	for _, input := range []string{"", "application bytes", "143e09cd521e1843338ce46783390b5ee80477f5655f8733b9137dc1\r\n\x01payload"} {
		b := &traceBody{ReadCloser: io.NopCloser(strings.NewReader(input)), sum: sha256.New()}
		got, err := io.ReadAll(b)
		if err != nil || string(got) != input {
			t.Fatal("diagnostic observer changed bytes", err)
		}
		r := httptest.NewRequest("POST", "https://localhost/vpn?Meta-Sequence=2", nil)
		r.Header.Set("Meta-Session", "do-not-export-session")
		r.Header.Set("Authorization", "do-not-export-credential")
		trace := tracePacket(r, b, "header", "query")
		want := sha256.Sum256(got)
		if trace.Seq != "2" || trace.Bytes != len(input) || trace.SHA256 != hex.EncodeToString(want[:]) || trace.Header != strings.HasPrefix(input, "143e09") {
			t.Fatal("incorrect packet diagnostic", trace)
		}
		encoded, _ := json.Marshal(trace)
		if bytes.Contains(encoded, []byte("do-not-export")) || len(input) > 0 && bytes.Contains(encoded, got) {
			t.Fatal("raw credential/metadata/payload leaked")
		}
	}
}

func TestTraceMetadataPlacementsStayDistinct(t *testing.T) {
	for _, pair := range [][2]string{{"query", "header"}, {"header", "query"}, {"cookie", "cookie"}, {"path", "header"}, {"header", "path"}} {
		r := httptest.NewRequest("POST", "https://localhost/vpn%20path", nil)
		set := func(placement, key, value string) {
			switch placement {
			case "path":
				r.URL.Path += "/" + value
			case "header":
				r.Header.Set(key, value)
			case "query":
				q := r.URL.Query()
				q.Set(key, value)
				r.URL.RawQuery = q.Encode()
			case "cookie":
				r.AddCookie(&http.Cookie{Name: key, Value: value})
			}
		}
		set(pair[0], "Meta-Session", "synthetic-session")
		set(pair[1], "Meta-Sequence", "7")
		b := &traceBody{ReadCloser: http.NoBody, sum: sha256.New()}
		got := tracePacket(r, b, pair[0], pair[1])
		id := sha256.Sum256([]byte("synthetic-session"))
		if got.Session != hex.EncodeToString(id[:]) || got.Seq != "7" {
			t.Fatal("diagnostic merged unrelated sessions", pair, got)
		}
	}
}
