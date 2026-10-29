// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFatalClass(t *testing.T) {
	replaced := status.Error(codes.FailedPrecondition, "this session was replaced by a newer one with the same agent ID and key")
	cases := []struct {
		name string
		err  error
		want Fatal
	}{
		{"nil", nil, NotFatal},
		{"unknown error", errors.New("something unfamiliar"), NotFatal},
		{"silence", fmt.Errorf("rpcclient: no frame from the relay for 1s: %w", ErrRelaySilent), NotFatal},
		{"unavailable", status.Error(codes.Unavailable, "down"), NotFatal},
		{"unknown code", status.Error(codes.Unknown, "boom"), NotFatal},
		{"canceled", context.Canceled, NotFatal},
		{"failed precondition, other", status.Error(codes.FailedPrecondition, "services conflict"), NotFatal},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad key"), FatalAuth},
		{"permission denied", fmt.Errorf("wrap: %w", status.Error(codes.PermissionDenied, "no")), FatalAuth},
		{"generation too old", status.Error(codes.FailedPrecondition, agentwire.ClientGenerationTooOld), FatalVersion},
		{"relay too old", status.Error(codes.FailedPrecondition, agentwire.RelayTooOld), FatalVersion},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad"), FatalConfig},
		{"session replaced", replaced, FatalReplaced},
		{"text only is not enough", errors.New(agentwire.ClientGenerationTooOld), NotFatal},
	}
	for _, c := range cases {
		if got := FatalClass(c.err); got != c.want {
			t.Errorf("%s: FatalClass = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestFatalErrorActionable(t *testing.T) {
	orig := status.Error(codes.Unauthenticated, "bad key")
	err := FatalError(orig)
	if !errors.Is(err, orig) || status.Code(err) != codes.Unauthenticated {
		t.Fatalf("FatalError does not unwrap to the original: %v", err)
	}
	if !strings.Contains(err.Error(), "bad key") || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("FatalError = %q, want the cause and a hint", err)
	}
	plain := errors.New("x")
	if FatalError(plain) != plain {
		t.Fatal("a non-fatal error must pass through")
	}
}
