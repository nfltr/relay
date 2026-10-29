// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"errors"
	"testing"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
)

func TestReasonNamesMatchTheEnum(t *testing.T) {
	for got, want := range map[string]relayv1.ErrorReason{
		ReasonMailboxFull: relayv1.ErrorReason_ERROR_REASON_MAILBOX_FULL, ReasonLimitExceeded: relayv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED,
		ReasonUnauthenticated: relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED, ReasonWebhookNotFound: relayv1.ErrorReason_ERROR_REASON_WEBHOOK_NOT_FOUND,
		ReasonUnsupported: relayv1.ErrorReason_ERROR_REASON_FEATURE_UNSUPPORTED,
	} {
		if got != want.String() {
			t.Errorf("%s != %s", got, want)
		}
	}
}

// A google.rpc.Status body yields its reason and message; any other body is
// a reason-less error carrying the status.
func TestDecodeError(t *testing.T) {
	err := decodeError(429, []byte(`{"code":8,"message":"mailbox inbox is full","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ERROR_REASON_MAILBOX_FULL","domain":"relay.nfltr.xyz"}]}`))
	if ReasonOf(err) != ReasonMailboxFull || err.Error() != "ERROR_REASON_MAILBOX_FULL: mailbox inbox is full" {
		t.Fatalf("typed = %v", err)
	}
	var e *Error
	if err := decodeError(404, []byte("404 page not found\n")); !errors.As(err, &e) || e.Reason != "" || e.HTTPStatus != 404 || e.Message != "404 page not found" {
		t.Fatalf("plain = %+v", e)
	}
}

// FuzzDecodeError: any error body from a relay decodes without a panic into
// an *Error with the HTTP status kept.
func FuzzDecodeError(f *testing.F) {
	f.Add(429, []byte(`{"code":8,"message":"m","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ERROR_REASON_MAILBOX_FULL"}]}`))
	f.Add(400, []byte(`{"details":[{"@type":"type.googleapis.com/google.protobuf.Empty"}]}`))
	f.Add(500, []byte("\xff"))
	f.Fuzz(func(t *testing.T, code int, body []byte) {
		var e *Error
		if err := decodeError(code, body); !errors.As(err, &e) || e.HTTPStatus != code {
			t.Fatalf("decode = %v", err)
		}
	})
}
