// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// TestAbortDirectRequiredOnALinkSession: a link session ends with the
// ACCOUNT_REQUIRED abort, which its peer reads, not a bare reset (link
// v0.13.0 dropped Session.Abort; the assertion is on AbortWith).
func TestAbortDirectRequiredOnALinkSession(t *testing.T) {
	a, b := net.Pipe()
	ctx := context.Background()
	got := make(chan error, 1)
	go func() {
		c, _, err := link.Server(ctx, b, link.Config{Auth: link.NoAuth})
		if err != nil {
			got <- err
			return
		}
		_ = link.NewMux(c).Serve(func(_ []byte, s *link.Session) {
			_, err := io.ReadAll(s)
			got <- err
		})
	}()
	c, err := link.Client(ctx, a, link.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m := link.NewMux(c)
	go func() { _ = m.Serve(nil) }()
	defer m.Close()
	s, err := m.Open(ctx, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := AbortDirectRequired(s); err != nil {
		t.Fatal(err)
	}
	var ab *link.Abort
	if err := <-got; !errors.As(err, &ab) || ab.Code != dataplane.AbortCode(relayv1.ErrorReason_ERROR_REASON_ACCOUNT_REQUIRED) {
		t.Fatalf("peer read %v, want the ACCOUNT_REQUIRED abort", err)
	}
}
