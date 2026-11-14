// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"errors"
	"io"
	"strconv"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
)

// Code is an error's class: the connect sidecar's exit status (nfltr
// docs/guides/connect-sidecar.md "Exit codes"). 8 (parent_gone) and 11
// (remote_failed) are the CLI's, not the SDK's.
type Code int

const (
	CodeUsage             Code = 1  // bad target or options
	CodeAuth              Code = 2  // no credential, or the relay refused it
	CodeNotFound          Code = 3  // agent offline or unknown, service not declared
	CodeRefused           Code = 4  // the target, the relay's policy or the service refused the session
	CodeUnreachable       Code = 5  // the relay or the agent's target was not reached
	CodeReset             Code = 6  // the session was cut after it opened
	CodeE2EEPinMismatch   Code = 7  // the server is not the identity the target names
	CodeBalanceExhausted  Code = 9  // the serving account's prepaid balance is exhausted
	CodeE2EEClientRefused Code = 10 // the server refused this client's identity
)

var codeNames = map[Code]string{
	CodeUsage: "usage", CodeAuth: "auth", CodeNotFound: "not_found", CodeRefused: "refused",
	CodeUnreachable: "unreachable", CodeReset: "reset", CodeE2EEPinMismatch: "e2ee_pin_mismatch",
	CodeBalanceExhausted: "balance_exhausted", CodeE2EEClientRefused: "e2ee_client_refused",
}

// String is the code's name in the sidecar's events ("usage" ...
// "e2ee_client_refused"); "code(N)" for another value.
func (c Code) String() string {
	if n, ok := codeNames[c]; ok {
		return n
	}
	return "code(" + strconv.Itoa(int(c)) + ")"
}

// Error is a failed target, open or session, typed onto the exit table.
type Error struct {
	Code Code
	// Reason is the relay's ERROR_REASON_* name, or "drain_deadline"; ""
	// when none.
	Reason string
	// Message names the hop that refused and the fix.
	Message string
	// Unopened: the path failed before the agent answered, so another open
	// may succeed.
	Unopened bool
	// Err is the cause (nf1.ErrNotServed, capaddr.ErrPin, ...); errors.Is
	// and errors.As see it through Unwrap.
	Err error
}

func (e *Error) Error() string {
	switch {
	case e.Message != "":
		return e.Message
	case e.Err != nil:
		return e.Err.Error()
	}
	return e.Code.String()
}

func (e *Error) Unwrap() error { return e.Err }

// codeOfCause maps the errors of nf1.Dial and capaddr (nfltr
// docs/decisions/nf1-rendezvous-2026-11-13.md section 6) and tlsend onto
// the table; the first match wins.
var codeOfCause = []struct {
	err  error
	code Code
}{
	{nf1.ErrNotServed, CodeNotFound},
	{nf1.ErrRefused, CodeRefused},
	{nf1.ErrUnreachable, CodeUnreachable},
	{nf1.ErrBalance, CodeBalanceExhausted},
	{nf1.ErrAnswer, CodeE2EEPinMismatch},
	{capaddr.ErrPin, CodeE2EEPinMismatch},
	{capaddr.ErrRendezvous, CodeE2EEPinMismatch},
	{capaddr.ErrTLS, CodeE2EEPinMismatch},
	{capaddr.ErrProof, CodeE2EEClientRefused},
	{capaddr.ErrNotAddress, CodeUsage},
	{capaddr.ErrEncoding, CodeUsage},
	{capaddr.ErrChecksum, CodeUsage},
	{capaddr.ErrVersion, CodeUsage},
	{capaddr.ErrLength, CodeUsage},
	{capaddr.ErrSecret, CodeUsage},
	{capaddr.ErrRelay, CodeUsage},
	{tlsend.ErrTruncated, CodeReset},
	{context.DeadlineExceeded, CodeUnreachable},
}

// CodeOf is err's exit code: an *Error's Code; 0 for nil, io.EOF and
// context.Canceled (a clean end, or the caller's own stop); the mapped code
// of an nf1, capaddr or tlsend error, and of context.DeadlineExceeded (5:
// nothing answered in time); else CodeReset (a session that failed).
func CodeOf(err error) Code {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return 0
	}
	for _, m := range codeOfCause {
		if errors.Is(err, m.err) {
			return m.code
		}
	}
	return CodeReset
}
