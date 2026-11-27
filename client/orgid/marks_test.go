// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

// A fresh process holds the newest CRL number, rules number and status
// time a machine took, and the clock's floor (MarksFile; lane SECFIX,
// review S10, S18): the relay's older list or status is refused after a
// restart, also once crl.der lapsed, and a clock set back before the
// newest list taken admits no one and takes no list.
func TestMarksHoldAcrossARestart(t *testing.T) {
	base := time.Now().Add(-3 * crlLife) // crl.der lapses before the restarts (Load reads at time.Now)
	o := newTestOrg(t, base)
	d := t.TempDir()
	dir := filepath.Join(d, "cli")
	o.enrolDir(t, dir, "cli", base, "db")
	web := o.enrolDir(t, filepath.Join(d, "web"), "web", base, "web")
	cli := load(t, dir)
	// An older list a relay kept, of a longer life than the newest.
	old, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: base, NextUpdate: base.Add(6 * crlLife)}, o.iss, o.issKey)
	check(t, err)
	o.crlNum = 10
	seen := base.Add(30 * time.Minute)
	if took, err := cli.TakeCRL(o.crl(t, seen), o.iss.Raw, seen); err != nil || !took {
		t.Fatalf("TakeCRL: %v %v", took, err)
	}
	if _, err := cli.CheckServer([]*x509.Certificate{web, o.iss}, "web", seen.Add(-20*time.Minute)); err == nil {
		t.Error("a clock 20 minutes before the newest list taken admits")
	}
	five := o.policy(t, Policy{Number: 5, Rules: []Rule{{Who: "group:db", Where: "machine:cli", Service: AnyService}}})
	three := o.policy(t, Policy{Number: 3, Rules: []Rule{{Who: "group:web", Where: "machine:cli", Service: AnyService}}})
	now := time.Now()
	if _, err := cli.TakeStatus(o.status(t, now.Add(2*time.Second), now.Add(crlLife), &five), now); err != nil {
		t.Fatal(err)
	}

	again := load(t, dir) // crl.der lapsed: the verifier holds none
	if _, err := again.TakeStatus(o.status(t, now.Add(3*time.Second), now.Add(crlLife), &three), now); err == nil {
		t.Error("a fresh process took rules older than the newest taken")
	}
	if took, _ := again.TakeStatus(o.status(t, now.Add(time.Second), now.Add(crlLife), &five), now); took {
		t.Error("a fresh process took a status older than the newest taken")
	}
	if err := again.Verifier().TakeCRL(old, o.iss, now); err == nil {
		t.Error("a fresh process with a lapsed crl.der took an older list")
	}
	if err := again.Verifier().TakeCRL(o.crl(t, base.Add(10*time.Minute)), o.iss, base.Add(10*time.Minute)); err == nil {
		t.Error("a fresh process took a list at a clock before the newest list taken")
	}
	if took, err := again.TakeCRL(o.crl(t, now), o.iss.Raw, now); err != nil || !took {
		t.Errorf("the issuer's next list: %v %v", took, err)
	}
}
