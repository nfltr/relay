// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
)

// BalanceExhaustedHint is the one line a client prints when the relay
// refuses or ends its connection because the account's prepaid balance is
// exhausted (ERROR_REASON_BALANCE_EXHAUSTED).
const BalanceExhaustedHint = "the account's prepaid balance is exhausted: top up on the dashboard; reconnecting by itself once it is active again"

// IsBalanceExhausted reports whether err is the relay's refusal for an
// account whose prepaid balance is exhausted (a google.rpc.ErrorInfo
// reason ERROR_REASON_BALANCE_EXHAUSTED, whatever its gRPC code). It is
// never fatal (FatalClass): a loop keeps redialing with its bounded
// backoff, so the agent comes back after a top-up.
func IsBalanceExhausted(err error) bool {
	s, ok := status.FromError(err) // unwraps
	if !ok || err == nil {
		return false
	}
	for _, d := range s.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED.String() {
			return true
		}
	}
	return false
}
