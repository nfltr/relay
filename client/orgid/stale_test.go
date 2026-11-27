// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A member's CRL signed CRLWarnAge or more ago is a warning naming the
// fix; a newer CRL clears it, and none held is not this warning (Check's
// nocrl). spec/enrol/CrlCarriers.tla QuietWhileIssuerUp (mutant
// warn-early) and WarnWhileIssuerDown (warn-on-lapse: nothing said until
// the CRL lapsed, the design before ISSUEROUT).
func TestCRLStaleNamesTheFix(t *testing.T) {
	t0 := time.Now()
	o := newTestOrg(t, t0)
	if err := o.ver.CRLStale(t0); err != nil {
		t.Fatalf("no CRL held: %v", err)
	}
	o.takeCRL(t, t0)
	if err := o.ver.CRLStale(t0.Add(CRLWarnAge - time.Second)); err != nil {
		t.Fatalf("a CRL younger than CRLWarnAge: %v", err)
	}
	err := o.ver.CRLStale(t0.Add(CRLWarnAge))
	if err == nil || !strings.Contains(err.Error(), "nfltr org serve") || !strings.Contains(err.Error(), "lapses at") {
		t.Fatalf("a CRL CRLWarnAge old: %v, want a warning naming nfltr org serve and the lapse", err)
	}
	o.takeCRL(t, t0.Add(CRLWarnAge))
	if err := o.ver.CRLStale(t0.Add(CRLWarnAge)); err != nil {
		t.Fatalf("after a newer CRL: %v", err)
	}
}

// A follower logs the warning while the CRL it holds is stale, every
// every (the issuer down: nothing newer arrives).
func TestFollowWarnsOfAStaleCRL(t *testing.T) {
	r := newFollowRig(t)
	stale := &signalWriter{text: "nfltr org serve", ch: make(chan struct{})}
	later := func() time.Time { return time.Now().Add(CRLWarnAge + time.Minute) }
	goFollow(t, func(ctx context.Context) {
		followCRL(ctx, r.box, r.cli, 50*time.Millisecond, later, slog.New(slog.NewTextHandler(stale, nil)))
	})
	select {
	case <-stale.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("no warning of a CRL older than CRLWarnAge")
	}
}
