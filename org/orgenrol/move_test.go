// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
)

// Moving the issuer (spec/orgmove/OrgMove.tla): the fleet's side.

// moveTo fences and seals the issuer directory dir to a new machine's
// receive key and imports it there; it returns the new issuer directory.
func moveTo(t *testing.T, dir, rootPin string, now time.Time) string {
	t.Helper()
	conf := t.TempDir()
	keyPath := filepath.Join(conf, orgissuer.ReceiveKeyFile)
	k, err := orgissuer.LoadReceiveKey(keyPath)
	check(t, err)
	sealed, err := orgissuer.Send(filepath.Dir(dir), orgissuer.ReceiveKey{Pub: k.PublicKey()}, now)
	check(t, err)
	_, err = orgissuer.Import(conf, keyPath, sealed, rootPin, now)
	check(t, err)
	return orgissuer.Dir(conf)
}

// AtMostOneIssuer: the service of a directory that `nfltr org move send`
// fenced stops with ErrMoved (and nfltr node then serves it no more).
func TestServiceStopsAtTheFence(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	o := newOrg(t, now)
	r := newRelay()
	errc := make(chan error, 1)
	go func() {
		errc <- Service{Mailbox: r, Dir: o.dir, Logger: quiet(), Now: time.Now, Wait: 50 * time.Millisecond}.Run(t.Context())
	}()
	eventually(t, "the CRL published", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.boxes[orgid.CRLMailbox(o.id)]) > 0
	})
	moveTo(t, o.dir, o.pins.Root, now)
	select {
	case err := <-errc:
		if !errors.Is(err, orgpki.ErrMoved) {
			t.Fatalf("the service stopped with %v, want ErrMoved", err)
		}
	case <-time.After(hang):
		t.Fatal("the fenced issuer's service still runs")
	}
}

// FleetUnderServingIssuer, TokenOnce: after the move the fleet needs no
// action: a machine renews with the moved issuer, and a token made before
// the move, posted while nobody served, is redeemed by the new machine.
func TestFleetRenewsWithTheMovedIssuer(t *testing.T) {
	f := newFleet(t)
	tok := f.org.token(t, "web-2", f.clk.Now())
	dir := moveTo(t, f.org.dir, f.org.pins.Root, f.clk.Now())
	joined := make(chan error, 1)
	go func() {
		_, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "machine"), f.org.pins, tok, hang, f.clk.Now)
		joined <- err
	}()
	time.Sleep(100 * time.Millisecond) // the request waits in the enrol mailbox
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Service{Mailbox: f.relay, Dir: dir, Logger: quiet(), Now: f.clk.Now, Wait: 50 * time.Millisecond, MachineKey: f.keys.make}.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	if err := <-joined; err != nil {
		t.Fatalf("a token made before the move: %v", err)
	}
	before := serial(f.m)
	f.clk.Add(17 * time.Hour)
	check(t, f.keeper().renew(f.ctx, ""))
	if serial(f.m) == before {
		t.Fatal("the machine did not renew with the moved issuer")
	}
}
