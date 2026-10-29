// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"errors"
	"strings"

	"github.com/nfltr/relay/proto/wire/agentwire"
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
// loop redials on it, whatever it is. It looks at gRPC codes and the
// agentwire refusal constants, never at other error text. The loop's own
// context cancellation is the loop's to check (ctx.Err()).
func FatalClass(err error) Fatal {
	if err == nil {
		return NotFatal
	}
	s, ok := status.FromError(err) // unwraps
	if !ok {
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

// Hint is what to do about a fatal class; empty for NotFatal.
func (f Fatal) Hint() string {
	switch f {
	case FatalAuth:
		return "the relay refused the credential: check the API key and its permissions"
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
