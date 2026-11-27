// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nfltr/relay/client/machinecert"
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

// Past the grace the command's error is one plain line that names the
// program's sign-in command once and no certificate; the relay's answer
// (its own words) stays the cause (lane CERTGAPS, CERTPROOF's row 9).
func TestRefusalIsOnePlainLine(t *testing.T) {
	answer := &machinecert.RefusedError{Status: 401, Message: "machine_offline_too_long: this machine's certificate expired more than 90 days ago; run `nfltr config login` on it"}
	c := &Credential{}
	c.refused.Store(true)
	if got := c.Refusal(answer).Error(); got != ErrRefused.Error() {
		t.Fatalf("no sign-in command: %q", got)
	}
	c.SetSignIn("nfltr config login")
	err := c.Refusal(fmt.Errorf("agent: %w", answer))
	if want := ErrRefused.Error() + ": sign in again: nfltr config login"; err.Error() != want {
		t.Fatalf("refusal %q, want %q", err, want)
	}
	if !errors.Is(err, ErrRefused) || !errors.Is(err, answer) || errors.Is(c.Refusal(err), answer) != true || c.Refusal(err) != err {
		t.Fatalf("the refusal lost ErrRefused or its cause: %v", err)
	}
}
