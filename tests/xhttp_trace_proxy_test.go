package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
		trace := tracePacket(r, b)
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
