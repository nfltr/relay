// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
)

// downBox is a mailbox that is down (every pull fails) beside the relay's
// copy of the CRL (CRLCopy), which holds copy.
type downBox struct {
	mu   sync.Mutex
	copy []byte
}

func (b *downBox) Pull(ctx context.Context, _ string, _ uint64, _ int, _ time.Duration) ([]mailboxclient.Envelope, string, error) {
	return nil, "", errors.New("mailbox: 502 bad gateway")
}

func (b *downBox) OrgCRL(context.Context, string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.copy, nil
}

func (b *downBox) set(t testing.TB, m CRLMessage) {
	p, err := json.Marshal(m)
	check(t, err)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.copy = p
}

// With the mailbox down, a revoke reaches a follower through the relay's
// copy (CrlCarriers.tla CurrentWithoutMailbox; mutant mailbox-only, the
// code before 2026-11-20: the 2026-11-19 mailbox outage lapsed every
// member's CRL after an hour).
func TestFollowTakesTheRelayCopyWhileTheMailboxIsDown(t *testing.T) {
	r := newFollowRig(t)
	mb := &downBox{}
	changed := r.cli.Changed()
	r.o.revoke(r.web)
	mb.set(t, CRLMessage{CRL: r.o.crl(t, time.Now()), Issuer: r.o.iss.Raw})
	goFollow(t, func(ctx context.Context) { followCRL(ctx, mb, r.cli, time.Hour, time.Now, quiet()) })
	select {
	case <-changed:
	case <-time.After(10 * time.Second):
		t.Fatal("the relay's copy did not reach the follower while the mailbox was down")
	}
	if r.checksWeb() == nil {
		t.Fatal("a revoked machine still checks")
	}
}

// The copy is taken by the CRL's signature and NextUpdate, never by its
// carrier: one past its NextUpdate (stale-copy), one older than the CRL
// held (copy-rollback: a revoked machine admitted again by the second
// path) and one the organisation's issuer did not sign (copy-unsigned) are
// refused, and a revoked machine stays refused.
func TestFollowRefusesAStaleRolledBackOrUnsignedCopy(t *testing.T) {
	for _, c := range []struct {
		name string
		copy func(r *followRig) CRLMessage
	}{
		{"stale", func(r *followRig) CRLMessage {
			o := *r.o
			o.revoked = nil // a newer number, listing nothing, lapsed an hour ago
			r.o.crlNum += 5
			o.crlNum = r.o.crlNum
			return CRLMessage{CRL: o.crl(t, time.Now().Add(-2*crlLife)), Issuer: r.o.iss.Raw}
		}},
		{"rollback", func(r *followRig) CRLMessage { return CRLMessage{CRL: r.preRevoke, Issuer: r.o.iss.Raw} }},
		{"unsigned", func(r *followRig) CRLMessage {
			other := newTestOrg(t, time.Now())
			other.crlNum = r.o.crlNum + 5 // a newer number, listing nothing, signed by another key
			return CRLMessage{CRL: other.crl(t, time.Now()), Issuer: r.o.iss.Raw}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newFollowRig(t)
			r.preRevoke = r.o.crl(t, time.Now())
			r.o.revoke(r.web)
			_, err := r.cli.TakeCRL(r.o.crl(t, time.Now()), r.o.iss.Raw, time.Now())
			check(t, err)
			mb := &downBox{}
			mb.set(t, c.copy(r))
			notTaken := &signalWriter{text: "copy not taken", ch: make(chan struct{})}
			logger := slog.New(slog.NewTextHandler(notTaken, &slog.HandlerOptions{Level: slog.LevelDebug}))
			goFollow(t, func(ctx context.Context) { followCRL(ctx, mb, r.cli, time.Hour, time.Now, logger) })
			select {
			case <-notTaken.ch:
			case <-time.After(10 * time.Second):
				t.Fatal("the copy was not refused")
			}
			if r.checksWeb() == nil {
				t.Fatal("a revoked machine checks after the copy")
			}
		})
	}
}
