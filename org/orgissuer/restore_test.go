// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgissuer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgpki"
)

// A restore from a backup (spec/orgmove/OrgMove.tla Revive): the copy,
// behind the CRL its lost machine published, takes that CRL, and the move
// it then sends arrives above it; a fenced copy takes none.
func TestRestoreThenMoveResumesAboveThePublishedCRL(t *testing.T) {
	copyConf, pin := newOrgConfig(t)
	lostConf := filepath.Join(t.TempDir(), "lost")
	if err := os.CopyFS(lostConf, os.DirFS(copyConf)); err != nil {
		t.Fatal(err)
	}
	// The lost machine signs two CRLs after the copy; the second is the
	// one the relay holds.
	s, err := Lock(Dir(lostConf))
	if err != nil {
		t.Fatal(err)
	}
	iss, err := s.Open()
	if err != nil {
		t.Fatal(err)
	}
	var published []byte
	for _, at := range []time.Time{t0, t0.Add(20 * time.Minute)} {
		if published, err = iss.CRL(at); err != nil {
			t.Fatal(err)
		}
	}
	s.Unlock()
	at := t0.Add(3 * time.Hour)
	if _, err := Restore(copyConf, published, t0.Add(30*time.Minute)); !errors.Is(err, orgpki.ErrNotQuiet) {
		t.Fatalf("a restore over a CRL signed less than RestoreQuiet ago: %v", err)
	}
	if _, err := Restore(copyConf, published, at); err != nil {
		t.Fatal(err)
	}
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(copyConf, rk, at)
	if err != nil {
		t.Fatal(err)
	}
	im, err := Import(conf, keyPath, sealed, pin, at)
	if err != nil {
		t.Fatal(err)
	}
	if im.CRL != 3 {
		t.Fatalf("CRL #%d imported after a restore over #2, want #3", im.CRL)
	}
	if _, err := Restore(copyConf, published, at); !errors.Is(err, orgpki.ErrMoved) {
		t.Fatalf("a restore of a fenced copy: %v", err)
	}
}

// This machine's own member CRL (orgid.Dir's crl.der) outvotes an older
// CRL the relay hands the restore (OrgMove.tla OfferAny, mutant
// restore-older-crl there; lane SECFIX2, review S8); one of another
// issuer is not taken.
func TestRestoreTakesThisMachinesNewerMemberCRL(t *testing.T) {
	copyConf, _ := newOrgConfig(t)
	lostConf := filepath.Join(t.TempDir(), "lost")
	if err := os.CopyFS(lostConf, os.DirFS(copyConf)); err != nil {
		t.Fatal(err)
	}
	s, err := Lock(Dir(lostConf))
	if err != nil {
		t.Fatal(err)
	}
	iss, err := s.Open()
	if err != nil {
		t.Fatal(err)
	}
	var crls [][]byte
	for _, at := range []time.Time{t0, t0.Add(20 * time.Minute)} {
		der, err := iss.CRL(at)
		if err != nil {
			t.Fatal(err)
		}
		crls = append(crls, der)
	}
	s.Unlock()
	member := orgid.Dir(copyConf)
	if err := os.MkdirAll(member, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(member, orgid.CRLFile), crls[1], 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := Restore(copyConf, crls[0], t0.Add(3*time.Hour)); err != nil || n != 2 {
		t.Fatalf("restored at CRL #%d (%v), want the member's #2 over the relay's #1", n, err)
	}
}
