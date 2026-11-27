// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"io"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsRetryableTransportError reports whether err represents a transient gRPC
// transport failure that a caller may safely retry (e.g. redialing or
// re-dispatching). It first inspects the gRPC status code, then recurses
// through wrapped errors, then falls back to a lowercased substring match
// against known transient transport error strings.
func IsRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Unavailable, codes.Internal, codes.Aborted,
			codes.ResourceExhausted, codes.Canceled, codes.NotFound:
			return true
		case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument:
			return false
		}
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		return IsRetryableTransportError(unwrapped)
	}
	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "goaway"),
		strings.Contains(errStr, "graceful_stop"),
		strings.Contains(errStr, "error reading from server: eof"),
		strings.Contains(errStr, "closing transport"),
		strings.Contains(errStr, "transport is closing"),
		strings.Contains(errStr, "connection reset"),
		strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "broken pipe"),
		strings.Contains(errStr, "closed pipe"),
		strings.Contains(errStr, "context canceled"),
		strings.Contains(errStr, "context deadline exceeded"),
		strings.Contains(errStr, "eof"),
		strings.Contains(errStr, "unavailable"),
		strings.Contains(errStr, "network unreachable"),
		strings.Contains(errStr, "no route to host"),
		strings.Contains(errStr, "i/o timeout"):
		return true
	}
	return false
}

// TransportStatusCode reports the gRPC status code carried by err as its
// canonical string name (e.g. "Unavailable", "DeadlineExceeded", "NotFound",
// per codes.Code.String()), with ok=true when err carries a gRPC status.
// It lets callers branch on transport codes to implement their own retry
// policy without importing google.golang.org/grpc/codes or /status — the
// transport lane provides the classification input; the caller decides.
func TransportStatusCode(err error) (name string, ok bool) {
	if err == nil {
		return "", false
	}
	s, ok := status.FromError(err)
	if !ok {
		return "", false
	}
	return s.Code().String(), true
}

// IsStreamBrokenError reports whether err indicates a gRPC stream is
// permanently unrecoverable (as opposed to an application-level rejection
// that a subsequent stream might handle differently). Callers use this to
// decide whether to force-detach a transport rather than retry on it.
func IsStreamBrokenError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Canceled, codes.Unavailable, codes.DeadlineExceeded, codes.Aborted:
			return true
		}
	}
	return false
}

// IsTransportNotFound reports whether err is a non-nil gRPC status error
// carrying codes.NotFound. Callers that also treat a nil err as "not found"
// (e.g. an already-absent target) must check that separately.
func IsTransportNotFound(err error) bool {
	return err != nil && status.Code(err) == codes.NotFound
}

// IsSessionReplaced reports whether err (an Agent's Err, a tunnel's
// receive error) is the relay ending this session because another process
// connected with the same agent ID. It is final: redialing would evict the
// other in turn. A newer connection of this same process (a reconnect, its
// InstanceHeader equal) ends the older stream with a retryable Canceled
// instead, which this does not match.
func IsSessionReplaced(err error) bool {
	s, ok := status.FromError(err) // unwraps
	return err != nil && ok && s.Code() == codes.FailedPrecondition && strings.Contains(s.Message(), "session was replaced")
}

// InvalidArgumentError constructs a gRPC status error with codes.InvalidArgument.
func InvalidArgumentError(format string, args ...any) error {
	return status.Errorf(codes.InvalidArgument, format, args...)
}

// FailedPreconditionError constructs a gRPC status error with codes.FailedPrecondition.
func FailedPreconditionError(format string, args ...any) error {
	return status.Errorf(codes.FailedPrecondition, format, args...)
}

// AbortedError constructs a gRPC status error with codes.Aborted.
func AbortedError(format string, args ...any) error {
	return status.Errorf(codes.Aborted, format, args...)
}

// NotFoundError constructs a gRPC status error with codes.NotFound.
func NotFoundError(format string, args ...any) error {
	return status.Errorf(codes.NotFound, format, args...)
}

// UnimplementedError constructs a gRPC status error with codes.Unimplemented.
func UnimplementedError(format string, args ...any) error {
	return status.Errorf(codes.Unimplemented, format, args...)
}

// ErrConnectionClosed marks a call that ended because the agent's relay
// connection did (the relay closed the tunnel, cleanly as when it drains for
// a deploy, or it broke, or the agent was closed), not because the peer
// ended the call: unlike io.EOF it proves nothing reached or was applied by
// the peer. errors.Is matches it; its gRPC status is Unavailable, so the
// transport-retry helpers treat it as a retryable transport loss.
var ErrConnectionClosed = errors.New("rpcclient: relay connection closed")

type connectionClosedError struct{ cause error }

func (e connectionClosedError) Error() string {
	if e.cause == nil {
		return ErrConnectionClosed.Error()
	}
	return ErrConnectionClosed.Error() + ": " + e.cause.Error()
}

func (e connectionClosedError) Is(target error) bool { return target == ErrConnectionClosed }

// Unwrap exposes the transport failure behind the close, except an io.EOF
// one (a send that hit the closed stream): errors.Is(err, io.EOF) must stay
// the peer ending the call.
func (e connectionClosedError) Unwrap() error {
	if errors.Is(e.cause, io.EOF) {
		return nil
	}
	return e.cause
}

func (e connectionClosedError) GRPCStatus() *status.Status {
	if cause := e.Unwrap(); cause != nil {
		if s, ok := status.FromError(cause); ok {
			return s
		}
	}
	return status.New(codes.Unavailable, e.Error())
}
