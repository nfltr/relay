// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecert

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRefusalOnlyForTheCertificate (pubcheck 2026-11-18): the relay's
// Unauthenticated is this machine's certificate refused (enrol again); a
// PermissionDenied, the relay refusing an agent name for this credential,
// is policy and stays itself, never "revoked, rotated away or expired".
func TestRefusalOnlyForTheCertificate(t *testing.T) {
	c := &Credential{}
	if err := c.Refusal(fmt.Errorf("agent: %w", status.Error(codes.Unauthenticated, "invalid credential"))); !errors.Is(err, ErrRefused) {
		t.Fatalf("Unauthenticated: %v, want ErrRefused", err)
	}
	denied := fmt.Errorf("agent: %w", status.Error(codes.PermissionDenied, "agent name not allowed for this credential"))
	if err := c.Refusal(denied); errors.Is(err, ErrRefused) {
		t.Fatalf("PermissionDenied: %v, want the relay's refusal as it is", err)
	}
}
