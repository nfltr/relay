// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"errors"
	"fmt"
	"testing"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func reasoned(t *testing.T, code codes.Code, reason relayv1.ErrorReason) error {
	t.Helper()
	st, err := status.New(code, "balance exhausted: top up on the dashboard to continue").
		WithDetails(&errdetails.ErrorInfo{Reason: reason.String(), Domain: "relay.nfltr.xyz"})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// A balance refusal is never a bad key: a loop keeps redialing (slowly)
// so the agent comes back on its own after a top-up, whatever gRPC code
// carries the reason.
func TestBalanceExhaustedIsNotFatal(t *testing.T) {
	for _, code := range []codes.Code{codes.FailedPrecondition, codes.Unauthenticated, codes.PermissionDenied} {
		err := fmt.Errorf("wrap: %w", reasoned(t, code, relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED))
		if !IsBalanceExhausted(err) {
			t.Errorf("%v: IsBalanceExhausted = false", code)
		}
		if f := FatalClass(err); f != NotFatal {
			t.Errorf("%v: FatalClass = %d, want NotFatal", code, f)
		}
	}
	for _, err := range []error{
		nil,
		errors.New("balance exhausted"), // text is never enough
		reasoned(t, codes.Unauthenticated, relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED),
		status.Error(codes.FailedPrecondition, "x"),
	} {
		if IsBalanceExhausted(err) {
			t.Errorf("%v: IsBalanceExhausted = true", err)
		}
	}
}
