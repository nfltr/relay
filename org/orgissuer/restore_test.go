// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgissuer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if err := Restore(copyConf, published, t0.Add(30*time.Minute)); !errors.Is(err, orgpki.ErrNotQuiet) {
		t.Fatalf("a restore over a CRL signed less than RestoreQuiet ago: %v", err)
	}
	if err := Restore(copyConf, published, at); err != nil {
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
	if err := Restore(copyConf, published, at); !errors.Is(err, orgpki.ErrMoved) {
		t.Fatalf("a restore of a fenced copy: %v", err)
	}
}
