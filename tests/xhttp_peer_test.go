package main

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/quic-go/quic-go/http3"
)

func TestPacketReadCancellationAndMalformedErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		canceled bool
		want     bool
	}{
		{"completed", nil, false, false},
		{"empty-completed-after-cancel", nil, true, false},
		{"uncanceled-short-body", io.ErrUnexpectedEOF, false, false},
		{"read-timeout", os.ErrDeadlineExceeded, false, false},
		{"explicit-cancel", context.Canceled, false, true},
		{"body-interrupted-by-owner", io.ErrUnexpectedEOF, true, true},
		{"remote-request-cancel", &http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestCanceled}, false, true},
		{"remote-normal-close", &http3.Error{Remote: true, ErrorCode: http3.ErrCodeNoError}, false, true},
		{"remote-quic-close-zero", &http3.Error{Remote: true}, false, true},
		{"local-stream-error", &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}, false, false},
		{"remote-incomplete-frame", &http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestIncomplete}, false, false},
		{"remote-general-protocol-error", &http3.Error{Remote: true, ErrorCode: http3.ErrCodeGeneralProtocolError}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.canceled {
				cancel()
			}
			r := httptest.NewRequest("POST", "http://localhost/test/session/0", nil).WithContext(ctx)
			err := test.err
			if err != nil {
				err = fmt.Errorf("body read: %w", err)
			}
			if got := canceledPacketRead(r, err); got != test.want {
				t.Fatal("cancellation/malformed classification", got, err)
			}
		})
	}
}
