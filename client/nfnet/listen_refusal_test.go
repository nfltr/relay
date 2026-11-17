// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"fmt"
	"testing"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A relay that registers no agent without an account (nf1.anon off)
// refuses a registration with no credential as PermissionDenied with the
// typed reason ERROR_REASON_UNAUTHENTICATED: Listen reports auth, not a
// reset (nfltr lane SENDFIX).
func TestListenRefusedUnauthenticatedIsAuth(t *testing.T) {
	st, err := status.New(codes.PermissionDenied, "no credential").WithDetails(&errdetails.ErrorInfo{
		Reason: relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED.String(), Domain: "relay.nfltr.xyz"})
	if err != nil {
		t.Fatal(err)
	}
	got := listenError(t.Context(), fmt.Errorf("agent: %w", st.Err()))
	wantCode(t, "typed refusal", got, CodeAuth, relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED.String())
}
