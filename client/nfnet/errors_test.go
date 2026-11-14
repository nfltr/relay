// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
)

// TestCodeStrings: the codes are the sidecar's exit statuses with its
// event names (nfltr docs/guides/connect-sidecar.md).
func TestCodeStrings(t *testing.T) {
	for c, want := range map[Code]string{
		1: "usage", 2: "auth", 3: "not_found", 4: "refused", 5: "unreachable", 6: "reset",
		7: "e2ee_pin_mismatch", 9: "balance_exhausted", 10: "e2ee_client_refused", 8: "code(8)", 11: "code(11)",
	} {
		if c.String() != want {
			t.Errorf("Code(%d) = %q, want %q", int(c), c.String(), want)
		}
	}
}

// TestCodeOfNF1Errors: nf1.Dial's and capaddr's errors land on the exit
// codes of nfltr docs/decisions/nf1-rendezvous-2026-11-13.md section 6,
// wrapped or not; an *Error's own code wins over its cause.
func TestCodeOfNF1Errors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want Code
	}{
		{nil, 0},
		{io.EOF, 0},
		{context.Canceled, 0},
		{nf1.ErrNotServed, CodeNotFound},
		{fmt.Errorf("%w (agent offline)", nf1.ErrNotServed), CodeNotFound},
		{fmt.Errorf("%w: too many connections", nf1.ErrRefused), CodeRefused},
		{fmt.Errorf("%w: dial tcp: refused", nf1.ErrUnreachable), CodeUnreachable},
		{nf1.ErrBalance, CodeBalanceExhausted},
		{nf1.ErrAnswer, CodeE2EEPinMismatch},
		{capaddr.ErrPin, CodeE2EEPinMismatch},
		{capaddr.ErrRendezvous, CodeE2EEPinMismatch},
		{capaddr.ErrTLS, CodeE2EEPinMismatch},
		{capaddr.ErrProof, CodeE2EEClientRefused},
		{capaddr.ErrChecksum, CodeUsage},
		{fmt.Errorf("%w 2", capaddr.ErrVersion), CodeUsage},
		{tlsend.ErrTruncated, CodeReset},
		{context.DeadlineExceeded, CodeUnreachable},
		{io.ErrUnexpectedEOF, CodeReset},
		{&Error{Code: CodeAuth}, CodeAuth},
		{fmt.Errorf("open: %w", &Error{Code: CodeRefused, Err: nf1.ErrNotServed}), CodeRefused},
		{&Error{Code: CodeReset, Err: io.EOF}, CodeReset},
	} {
		if got := CodeOf(tc.err); got != tc.want {
			t.Errorf("CodeOf(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestErrorUnwraps: errors.Is sees an *Error's cause; Error() is its
// message, else its cause's, else its code's name.
func TestErrorUnwraps(t *testing.T) {
	e := &Error{Code: CodeE2EEPinMismatch, Err: capaddr.ErrPin}
	if !errors.Is(fmt.Errorf("x: %w", e), capaddr.ErrPin) || e.Error() != capaddr.ErrPin.Error() {
		t.Fatalf("%v", e)
	}
	if got := (&Error{Code: CodeAuth, Message: "no key", Err: io.EOF}).Error(); got != "no key" {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&Error{Code: CodeAuth}).Error(); got != "auth" {
		t.Fatalf("Error() = %q", got)
	}
	_, err := ParseTarget("home")
	if e, ok := errors.AsType[*Error](err); !ok || e.Code != CodeUsage || e.Message == "" {
		t.Fatalf("ParseTarget(home) = %#v", err)
	}
}
