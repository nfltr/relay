// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsRetryableTransportError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unavailable", status.Error(codes.Unavailable, "down"), true},
		{"internal", status.Error(codes.Internal, "oops"), true},
		{"aborted", status.Error(codes.Aborted, "abort"), true},
		{"resource_exhausted", status.Error(codes.ResourceExhausted, "full"), true},
		{"canceled", status.Error(codes.Canceled, "cancel"), true},
		{"not_found", status.Error(codes.NotFound, "gone"), true},
		{"unauthenticated", status.Error(codes.Unauthenticated, "nope"), false},
		{"permission_denied", status.Error(codes.PermissionDenied, "nope"), false},
		{"invalid_argument", status.Error(codes.InvalidArgument, "bad"), false},
		{"other_code_falls_through_to_string_match", status.Error(codes.OutOfRange, "unavailable right now"), true},
		{"other_code_no_string_match", status.Error(codes.OutOfRange, "range issue"), false},
		{"wrapped_retryable_code", fmt.Errorf("dispatch failed: %w", status.Error(codes.Unavailable, "down")), true},
		{"wrapped_nonretryable_code", fmt.Errorf("dispatch failed: %w", status.Error(codes.InvalidArgument, "bad")), false},
		{"plain_connection_reset", errors.New("connection reset by peer"), true},
		{"plain_goaway", errors.New("received GOAWAY"), true},
		{"plain_broken_pipe", errors.New("write: broken pipe"), true},
		{"plain_context_deadline", errors.New("context deadline exceeded"), true},
		{"plain_unrelated", errors.New("some unrelated error"), false},
		{"plain_eof", errors.New("EOF"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRetryableTransportError(tc.err); got != tc.want {
				t.Errorf("IsRetryableTransportError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsStreamBrokenError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context_canceled", context.Canceled, true},
		{"context_deadline_exceeded", context.DeadlineExceeded, true},
		{"wrapped_context_canceled", fmt.Errorf("send failed: %w", context.Canceled), true},
		{"code_canceled", status.Error(codes.Canceled, "cancel"), true},
		{"code_unavailable", status.Error(codes.Unavailable, "down"), true},
		{"code_deadline_exceeded", status.Error(codes.DeadlineExceeded, "timeout"), true},
		{"code_aborted", status.Error(codes.Aborted, "abort"), true},
		{"code_not_found_is_not_broken", status.Error(codes.NotFound, "gone"), false},
		{"code_internal_is_not_broken", status.Error(codes.Internal, "oops"), false},
		{"plain_error_is_not_broken", errors.New("some other error"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsStreamBrokenError(tc.err); got != tc.want {
				t.Errorf("IsStreamBrokenError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsTransportNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"not_found", status.Error(codes.NotFound, "gone"), true},
		{"unavailable", status.Error(codes.Unavailable, "down"), false},
		{"plain_error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTransportNotFound(tc.err); got != tc.want {
				t.Errorf("IsTransportNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestConstructorErrorCodes(t *testing.T) {
	cases := []struct {
		name    string
		ctor    func(string, ...any) error
		code    codes.Code
		wantMsg string
	}{
		{"invalid_argument", InvalidArgumentError, codes.InvalidArgument, "bad field %s: %d"},
		{"failed_precondition", FailedPreconditionError, codes.FailedPrecondition, "precondition %s: %d"},
		{"aborted", AbortedError, codes.Aborted, "aborted %s: %d"},
		{"not_found", NotFoundError, codes.NotFound, "missing %s: %d"},
		{"unimplemented", UnimplementedError, codes.Unimplemented, "todo %s: %d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ctor(tc.wantMsg, "x", 42)
			if got := status.Code(err); got != tc.code {
				t.Errorf("status.Code() = %v, want %v", got, tc.code)
			}
			wantFormatted := fmt.Sprintf(tc.wantMsg, "x", 42)
			if s, ok := status.FromError(err); !ok || s.Message() != wantFormatted {
				t.Errorf("message = %q, want %q", err.Error(), wantFormatted)
			}
		})
	}
}

func TestTransportStatusCode(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantName string
		wantOK   bool
	}{
		{"nil", nil, "", false},
		{"plain", errors.New("plain error"), "", false},
		{"unavailable", status.Error(codes.Unavailable, "x"), "Unavailable", true},
		{"deadline", status.Error(codes.DeadlineExceeded, "x"), "DeadlineExceeded", true},
		{"notfound_via_constructor", NotFoundError("x"), "NotFound", true},
		{"aborted_via_constructor", AbortedError("x"), "Aborted", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotOK := TransportStatusCode(tc.err)
			if gotName != tc.wantName || gotOK != tc.wantOK {
				t.Fatalf("TransportStatusCode(%v) = (%q, %v), want (%q, %v)", tc.err, gotName, gotOK, tc.wantName, tc.wantOK)
			}
		})
	}
}
