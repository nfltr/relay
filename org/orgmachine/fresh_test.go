// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
	"github.com/nfltr/relay/org/orgpki"
)

// A fresh-bounded service refuses and cuts its sessions once the CRL the
// machine holds is fresh old, a newer CRL moves the bound, and the
// machine's own CheckClient (no key) is unchanged (spec/enrol/CrlCarriers.tla
// FreshBound; mutants fresh-ignored, fresh-not-cut).
func TestFreshCutsAtTheBound(t *testing.T) {
	base := time.Now().Add(-orgid.FreshMin + 2*time.Second) // the CRL signed then: the bound ends in 1 to 2 s
	o := orgmachinetest.New(t, base)
	d := t.TempDir()
	o.Enrol(t, filepath.Join(d, "web"), "web", base, "web")
	cli := o.Enrol(t, filepath.Join(d, "cli"), "cli", base, "db")
	allowDB(t, o, base)
	web := open(t, filepath.Join(d, "web"))
	crt, _ := web.Certificate()
	iss, _ := x509.ParseCertificate(crt.Certificate[1])
	certs := []*x509.Certificate{cli, iss}

	for _, bad := range []time.Duration{10 * time.Minute, orgid.FreshMin - time.Second, orgpki.CRLLife + time.Second} {
		if _, err := web.Fresh(bad); err == nil {
			t.Errorf("Fresh(%s) taken", bad)
		}
	}
	f, err := web.Fresh(orgid.FreshMin)
	if err != nil {
		t.Fatal(err)
	}
	end := base.Truncate(time.Second).Add(orgid.FreshMin) // ThisUpdate is in seconds
	changed := f.Changed()
	until, err := f.CheckClient(certs, []string{"db"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if until.After(end) {
		t.Fatalf("until %s, past the bound %s", until, end)
	}
	if _, err := f.CheckClient(certs, []string{"db"}, end); err == nil {
		t.Error("admitted at the bound")
	}
	if _, err := web.CheckClient(certs, []string{"db"}, end); err != nil {
		t.Errorf("the machine without the key refused at the bound: %v", err)
	}
	cut := make(chan struct{})
	go f.Hold(until, changed, func(now time.Time) (time.Time, error) { return f.CheckClient(certs, []string{"db"}, now) },
		func() { close(cut) }, t.Context().Done())
	select {
	case <-cut:
	case <-time.After(10 * time.Second):
		t.Fatal("the session outlived the bound on a withheld CRL")
	}
	if time.Now().Before(end) {
		t.Errorf("cut %s before the bound", end.Sub(time.Now()))
	}
	o.PublishCRL(t, time.Now())
	if _, err := web.Reload(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CheckClient(certs, []string{"db"}, end.Add(time.Second)); err != nil {
		t.Errorf("a newer CRL did not move the bound: %v", err)
	}
}
