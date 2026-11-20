// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"errors"
	"strings"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrRelaySilent marks a connection dropped because the relay sent no frame
// within the silence limit. It is transient: the loop that sees it redials.
var ErrRelaySilent = errors.New("connection lost")

// Fatal is why a long-lived connection loop must stop instead of redialling.
type Fatal int

const (
	// NotFatal: redial.
	NotFatal Fatal = iota
	// FatalAuth: the relay refused the credential (Unauthenticated,
	// PermissionDenied).
	FatalAuth
	// FatalVersion: client and relay cannot speak (FailedPrecondition
	// carrying agentwire.ClientGenerationTooOld or agentwire.RelayTooOld).
	FatalVersion
	// FatalConfig: the relay rejected the request itself (InvalidArgument).
	FatalConfig
	// FatalReplaced: another process connected with the same agent ID.
	FatalReplaced
)

// FatalClass classifies err for a connection loop's stop-or-redial decision.
// Every error that is not one of the closed fatal classes is NotFatal: a
// loop redials on it, whatever it is; a balance refusal
// (IsBalanceExhausted) is never fatal, whatever its code. It looks at gRPC
// codes, ErrorInfo reasons and the agentwire refusal constants, never at other error text. The loop's own
// context cancellation is the loop's to check (ctx.Err()).
func FatalClass(err error) Fatal {
	if err == nil {
		return NotFatal
	}
	s, ok := status.FromError(err) // unwraps
	if !ok || IsBalanceExhausted(err) {
		// a top-up ends a balance refusal: redial
		return NotFatal
	}
	switch s.Code() {
	case codes.Unauthenticated, codes.PermissionDenied:
		return FatalAuth
	case codes.InvalidArgument:
		return FatalConfig
	case codes.FailedPrecondition:
		switch {
		case strings.Contains(s.Message(), agentwire.ClientGenerationTooOld),
			strings.Contains(s.Message(), agentwire.RelayTooOld):
			return FatalVersion
		case IsSessionReplaced(err):
			return FatalReplaced
		}
	}
	return NotFatal
}

// IsCredentialEnded reports whether err is the relay's end of a connection
// it had accepted, for its credential (Unauthenticated, reason
// ERROR_REASON_UNAUTHENTICATED: relay-core grpcauth.CredentialEndedStatus,
// sent when the certificate the connection was opened with expires, or the
// machine is revoked). A loop redials it rather than stop: a holder renews
// ahead of the expiry and the redial presents the newest certificate; a
// revoked machine's redial is refused, and that refusal is the fatal one
// (relay-server spec/MachineAuth.tla AgentStopsOnlyRefused). Only for an
// accepted connection's end: a refusal at admission stays FatalAuth.
func IsCredentialEnded(err error) bool {
	s, ok := status.FromError(err) // unwraps
	if !ok || err == nil || s.Code() != codes.Unauthenticated {
		return false
	}
	for _, d := range s.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED.String() {
			return true
		}
	}
	return false
}

// Hint is what to do about a fatal class; empty for NotFatal.
func (f Fatal) Hint() string {
	switch f {
	case FatalAuth:
		return "the relay refused this machine (revoked, or off for more than 90 days: nfltr config login), or its token lacks the permission"
	case FatalVersion:
		return "this client and the relay are incompatible: update the client (or the relay)"
	case FatalConfig:
		return "the relay rejected the connection request: check the agent's configuration"
	case FatalReplaced:
		return "another process connected with the same agent ID: stop it or use another ID"
	}
	return ""
}

// FatalError is err with the class's hint, for a loop to stop with. It
// unwraps to err, so FatalClass and status.Code still see the original.
func FatalError(err error) error {
	f := FatalClass(err)
	if f == NotFatal {
		return err
	}
	return &fatalError{err: err, hint: f.Hint()}
}

type fatalError struct {
	err  error
	hint string
}

func (e *fatalError) Error() string { return e.err.Error() + " (" + e.hint + ")" }
func (e *fatalError) Unwrap() error { return e.err }
