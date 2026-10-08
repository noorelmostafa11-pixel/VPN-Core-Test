package main

import (
	"context"
	"crypto/x509"
	"errors"
	utls "github.com/refraction-networking/utls"
	"io"
	"net"
	"os"
)

// The ABI exposes only stable numeric classes. Never export err.Error(), names,
// certificates, resolver URLs, credentials, or peer packet contents.
func tlsErrorCode(err error, fallback int) int {
	var pe providerError
	if errors.As(err, &pe) {
		return int(pe)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return 316
	}
	if errors.Is(err, context.Canceled) {
		return 319
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return 311
	}
	var authority x509.UnknownAuthorityError
	if errors.As(err, &authority) {
		return 312
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		if invalid.Reason == x509.Expired {
			return 313
		}
		return 314
	}
	var verification *utls.CertificateVerificationError
	if errors.As(err, &verification) {
		return tlsErrorCode(verification.Err, 314)
	}
	var ech *utls.ECHRejectionError
	if errors.As(err, &ech) {
		return 336
	}
	var record utls.RecordHeaderError
	if errors.As(err, &record) {
		return 321
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return 316
	}
	var alert utls.AlertError
	if errors.As(err, &alert) {
		return 318
	}
	var op *net.OpError
	if errors.As(err, &op) && (op.Op == "remote error" || op.Op == "local error") {
		return 318
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return 317
	}
	return fallback
}
func echLookupError(err error) error {
	code := tlsErrorCode(err, 332)
	if code == 453 || code == 454 || code == 455 || code == 456 {
		return providerError(code)
	}
	if code == 316 || code == 319 {
		code = 334
	}
	// Lookup certificate/connection failures belong to the resolver, not node TLS.
	if code != 334 {
		code = 332
	}
	return providerError(code)
}

func xhttpErrorCode(err error) int {
	var pe providerError
	if errors.As(err, &pe) {
		return int(pe)
	}
	code := tlsErrorCode(err, 401)
	switch code {
	case 311, 312, 313, 314, 315, 318, 319, 321, 336, 453, 454, 455, 456:
		return code
	}
	// A request timeout may follow a successful TLS handshake. Do not label
	// it a TLS failure without a typed provider error identifying that stage.
	return 401
}
