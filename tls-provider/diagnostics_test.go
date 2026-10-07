package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"io"
	"net"
	"testing"
)

func TestTypedTLSFailures(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{x509.HostnameError{}, 311}, {x509.UnknownAuthorityError{}, 312},
		{x509.CertificateInvalidError{Reason: x509.Expired}, 313},
		{x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}, 314},
		{context.DeadlineExceeded, 316}, {context.Canceled, 319}, {io.EOF, 317},
		{io.ErrUnexpectedEOF, 317}, {providerError(308), 308}, {providerError(315), 315},
		{&utls.ECHRejectionError{}, 336}, {utls.RecordHeaderError{}, 321},
		{utls.AlertError(40), 318}, {&net.OpError{Op: "remote error", Err: errors.New("opaque")}, 318},
		{errors.New("opaque secret must never leave provider"), 303},
	}
	for _, c := range cases {
		if got := tlsErrorCode(fmt.Errorf("wrapped: %w", c.err), 303); got != c.code {
			t.Fatalf("class %T: got %d expected %d", c.err, got, c.code)
		}
	}
}
func TestECHClassifications(t *testing.T) {
	for _, c := range []struct {
		text string
		code int
	}{{"invalid", 330}, {"https://user:password@localhost/query", 331}, {"dns://localhost", 331}} {
		_, err := resolveECH(context.Background(), c.text, "localhost", nil)
		if got := tlsErrorCode(err, 309); got != c.code {
			t.Fatalf("ECH got %d expected %d", got, c.code)
		}
	}
	if got := tlsErrorCode(echLookupError(context.DeadlineExceeded), 309); got != 334 {
		t.Fatal(got)
	}
}

func TestXHTTPPreservesTypedTLSCause(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{x509.HostnameError{}, 311}, {x509.UnknownAuthorityError{}, 312},
		{providerError(330), 330}, {providerError(334), 334}, {providerError(404), 404},
		{context.DeadlineExceeded, 401}, {errors.New("opaque response failure"), 401},
	} {
		if got := xhttpErrorCode(fmt.Errorf("request wrapper: %w", c.err)); got != c.code {
			t.Fatalf("XHTTP got %d want %d", got, c.code)
		}
	}
}
