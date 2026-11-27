// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

// The restore drill (spec/orgmove/OrgMove.tla Revive; nfltr's runbook "The
// organisation issuer from a backup"): a backup of the issuer directory is
// taken, the issuer goes on for most of a day (a machine renews, another
// is revoked, CRLs published), then its machine is lost. The copy, behind
// the published CRL, takes it from the relay and moves onto a new
// machine: the fleet needs no action (the renewed machine renews on its
// own), the revoked machine stays revoked, and the CRL goes on above the
// published one.
func TestRestoreFromABackupBehindThePublishedCRL(t *testing.T) {
	clk := &clock{t: time.Now().Truncate(time.Second)}
	r, o := newRelay(), newOrg(t, clk.Now())
	keys := &machineKeys{made: map[string]bool{}, names: map[string]string{}}
	serve := func(ctx context.Context, dir string) func() {
		ctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = Service{Mailbox: r, Dir: dir, Logger: quiet(), Now: clk.Now, Wait: 50 * time.Millisecond, MachineKey: keys.make}.Run(ctx)
		}()
		return func() { cancel(); <-done }
	}
	stopLost := serve(t.Context(), o.dir)
	t.Cleanup(stopLost)
	join := func(name string) *orgmachine.Machine {
		dir := filepath.Join(t.TempDir(), "machine")
		_, err := Join(t.Context(), r, dir, o.pins, o.token(t, name, clk.Now()), hang, clk.Now)
		check(t, err)
		m, err := orgmachine.Open(dir)
		check(t, err)
		return m
	}
	keeper := func(m *orgmachine.Machine) Keeper {
		return Keeper{Mailbox: r, Machine: m, Logger: quiet(), Now: clk.Now, AnswerWait: hang, RetryWait: 10 * time.Millisecond, FollowEvery: 100 * time.Millisecond}
	}
	web1, web2 := join("web-1"), join("web-2")
	root := o.root(t)

	// The nightly backup, under the issuer's lock (nfltr-backup.sh
	// snapshot-secrets).
	backup := filepath.Join(t.TempDir(), "backup")
	s, err := orgissuer.Lock(o.dir)
	check(t, err)
	check(t, os.CopyFS(filepath.Join(backup, "org"), os.DirFS(o.dir)))
	s.Unlock()

	// The day after it: web-1 renews, web-2 is revoked.
	clk.Add(17 * time.Hour)
	check(t, keeper(web1).renew(t.Context(), ""))
	c2, _ := web2.Current()
	o.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) { check(t, iss.Revoke("web-2", clk.Now())) })
	var lostNum int64
	eventually(t, "web-2's revocation published", func() bool {
		der, err := PublishedRevocationList(t.Context(), r, root, clk.Now())
		if err != nil {
			return false
		}
		crl, err := x509.ParseRevocationList(der)
		check(t, err)
		lostNum = crl.Number.Int64()
		return listed(crl, c2)
	})

	// The machine is lost; no CRL is published for RestoreQuiet.
	stopLost()
	clk.Add(2 * time.Hour)
	der, err := PublishedRevocationList(t.Context(), r, root, clk.Now())
	check(t, err)
	check(t, orgissuer.Restore(backup, der, clk.Now()))
	stopNew := serve(t.Context(), moveTo(t, r, o.id, filepath.Join(backup, "org"), o.pins.Root, clk.Now()))
	t.Cleanup(stopNew)

	clk.Add(15 * time.Hour) // web-1's certificate of the day after the backup is due
	before := serial(web1)
	if err := keeper(web1).renew(t.Context(), ""); err != nil || serial(web1) == before {
		t.Fatalf("a machine that renewed after the backup does not renew with the restored issuer: %v", err)
	}
	if err := keeper(web2).renew(t.Context(), ""); err == nil {
		t.Fatal("a machine revoked after the backup renewed with the restored issuer")
	}
	eventually(t, "the restored issuer's CRL published above the lost one's, web-2 listed", func() bool {
		der, err := PublishedRevocationList(t.Context(), r, root, clk.Now())
		if err != nil {
			return false
		}
		crl, err := x509.ParseRevocationList(der)
		check(t, err)
		return crl.Number.Int64() > lostNum && listed(crl, c2)
	})
}

func listed(crl *x509.RevocationList, c *x509.Certificate) bool {
	return slices.ContainsFunc(crl.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool {
		return hex.EncodeToString(e.SerialNumber.Bytes()) == hex.EncodeToString(c.SerialNumber.Bytes())
	})
}
