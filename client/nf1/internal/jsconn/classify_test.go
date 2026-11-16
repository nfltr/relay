// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package jsconn

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
)

// TestClassify: each close code of the relay path (relay-core nf1ws.go)
// is the CLI's class and exit for the same answer; a handshake verdict
// wins over the close that followed it.
func TestClassify(t *testing.T) {
	for _, c := range []struct {
		err    error
		closed *CloseError
		name   string
		exit   int
	}{
		{io.ErrUnexpectedEOF, &CloseError{Code: 4003}, "not_served", 3},
		{io.ErrUnexpectedEOF, &CloseError{Code: 4004, Reason: "address_max"}, "refused", 4},
		{io.ErrUnexpectedEOF, &CloseError{Code: 4009}, "balance", 9},
		{io.ErrUnexpectedEOF, &CloseError{Code: 1013}, "unreachable", 5},
		{io.ErrUnexpectedEOF, &CloseError{Code: 1006}, "unreachable", 5},
		{io.ErrUnexpectedEOF, &CloseError{Code: 1011}, "reset", 0},
		{io.ErrUnexpectedEOF, &CloseError{Code: 1001}, "idle", 0},
		{io.ErrUnexpectedEOF, &CloseError{Code: 1003}, "protocol", 0},
		{io.EOF, &CloseError{Code: 1000}, "closed", 0},
		{capaddr.ErrProof, &CloseError{Code: 1000}, "proof", 10},
		{fmt.Errorf("handshake: %w", capaddr.ErrPin), &CloseError{Code: 1011}, "pin", 7},
		{nf1.ErrKind, nil, "kind", 0},
		{errors.New("other"), nil, "error", 0},
	} {
		name, exit := Classify(c.err, c.closed)
		if name != c.name || exit != c.exit {
			t.Errorf("Classify(%v, %+v) = %s %d, want %s %d", c.err, c.closed, name, exit, c.name, c.exit)
		}
	}
	if !errors.Is(&CloseError{Code: 4003}, nf1.ErrNotServed) {
		t.Error("a 4003 close does not unwrap to nf1.ErrNotServed")
	}
}
