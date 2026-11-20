// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
)

// A renewal in another process replaces the key, then the certificate,
// each by rename (writeIdentity; lane CERTPAIR: nfltr cat serve --ssh
// failed "machine.pem: tls: private key does not match public key" while
// another process renewed): an Open between the two waits for the
// certificate.
func TestReadPairWaitsForTheWritersCertificate(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	d, next := t.TempDir(), t.TempDir()
	o.Enrol(t, d, "web", now, "web")
	renewed := o.Enrol(t, next, "web2", now, "web") // the issuer certifies a name once: another name stands for the renewal
	replace := func(file string) {
		data, err := os.ReadFile(filepath.Join(next, file)) // #nosec G304 -- the test's own temp dir
		if err == nil {
			err = os.WriteFile(filepath.Join(d, file+".tmp"), data, 0o600)
		}
		if err == nil {
			err = os.Rename(filepath.Join(d, file+".tmp"), filepath.Join(d, file))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	replace(orgmachine.KeyFile) // the writer, between its two renames
	done := make(chan *orgmachine.Machine, 1)
	go func() {
		m, err := orgmachine.Open(d)
		if err != nil {
			t.Error(err)
		}
		done <- m
	}()
	select {
	case <-done:
		t.Fatal("Open returned with the key renewed and the certificate not yet")
	case <-time.After(50 * time.Millisecond):
	}
	replace(orgmachine.CertFile)
	if m := <-done; m != nil {
		if cur, _ := m.Current(); !cur.Equal(renewed) {
			t.Errorf("Open took %s, want the renewed certificate", cur.Subject)
		}
	}
}
