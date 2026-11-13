// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
)

// TestDirectRevokedClientCutOnEveryPath (nfltr docs/decisions/
// direct-paths-2026-11-11.md "Lane REVOKEDIRECT"): a session on the direct
// path whose client the agent's organisation revokes ends at both ends
// within the bound (the agent's holdAdmission resets it: the ABORT goes on
// the direct stream, Enrol.tla RevocationBound, DirectPath.tla
// ResetReaches); no byte of it flows after; a relayed re-attach finds no
// live session (only the reset); a re-punch (a new control exchange) is
// refused; and the agent closes the pair's direct connection, which the
// revoked client may otherwise keep.
func TestDirectRevokedClientCutOnEveryPath(t *testing.T) {
	const bound = 5 * time.Second
	r := newDirectRig(t, DirectOn)
	ds, tc, events := r.session(t)
	waitPath(t, events, PathDirect)
	_ = tc.SetDeadline(time.Now().Add(bound))
	if _, err := io.WriteString(tc, "ping"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tc, make([]byte, 4)); err != nil {
		t.Fatalf("echo on the direct path: %v", err)
	}
	p := r.d.pair("web", "web")
	p.mu.Lock()
	q := p.q
	p.mu.Unlock()
	if ds.Path() != PathDirect || q == nil {
		t.Fatalf("path %s, connection %v: want direct", ds.Path(), q)
	}
	key, err := sessionKey(tc.ConnectionState())
	if err != nil {
		t.Fatal(err)
	}

	t0 := time.Now()
	r.org.change(r.client.cert.Leaf)
	if !cutWithin(tc, bound) {
		t.Fatalf("the revoked client's direct session went on %s after the revoke", bound)
	}
	select {
	case <-ds.Done():
	case <-time.After(bound):
		t.Fatalf("the client's path layer still open %s after the revoke", bound)
	}
	t.Logf("cut %s after the revoke", time.Since(t0).Round(time.Millisecond))
	if _, err := io.WriteString(tc, "more"); err == nil {
		if _, err := io.ReadFull(tc, make([]byte, 4)); err == nil {
			t.Fatal("bytes flowed after the cut")
		}
	}

	// A relayed re-attach names the session by its token: the agent holds
	// it only as reset (it answers with the ABORT), never live.
	o := pathswitch.Open{Epoch: ds.c.Epoch() + 1, Token: pathToken(key, roleClient, ds.c.Epoch()+1, nil)}
	d := r.l.targets.services.direct
	d.mu.Lock()
	sess := d.matchLocked(tokenMatch(o, nil))
	d.mu.Unlock()
	if sess != nil {
		if _, err := sess.c.Write([]byte("x")); err == nil {
			t.Fatal("a relayed re-attach after the revoke finds the session live")
		}
	}

	// A re-punch: a new control exchange of the revoked client (a TLS 1.3
	// client's handshake ends before the server's check: the refusal is
	// the alert its first read gets, as punch reads the offer).
	ctx, cancel := context.WithTimeout(t.Context(), bound)
	defer cancel()
	if c, err := r.d.control(ctx, p); err == nil {
		_ = c.SetDeadline(time.Now().Add(bound))
		_, _ = io.WriteString(c, `{"service":"blob"}`+"\n")
		n, rerr := c.Read(make([]byte, 64))
		_ = c.Close()
		if rerr == nil || n > 0 {
			t.Fatal("the revoked client's control exchange (a re-punch) got an offer")
		}
	}

	// A re-punch's direct connection: the agent's listener refuses it (the
	// QUIC client's handshake ends first: the refusal closes it).
	if q2, err := r.d.dialPair(ctx, p); err == nil {
		select {
		case <-q2.Context().Done():
		case <-time.After(bound):
			t.Fatal("the revoked client's new direct connection (a re-punch) was admitted")
		}
	}

	// The pair's direct connection: the agent closes it.
	select {
	case <-q.Context().Done():
	case <-time.After(bound):
		t.Fatalf("the revoked client's direct connection still open %s after the revoke", bound)
	}
}
