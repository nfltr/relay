// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A Load that read the certificate before another process's whole renewal
// and the key after it (lane CERTPAIR: nfltr cat serve --ssh failed
// "machine.pem: tls: private key does not match public key" while another
// process renewed) reads again; the files here stand for what it read.
func TestReadPairWaitsForTheWritersCertificate(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d, next := t.TempDir(), t.TempDir()
	o.enrolDir(t, d, "web", now, "web")
	renewed := o.enrolDir(t, next, "web", now, "web")
	replace := func(file string) {
		data, err := os.ReadFile(filepath.Join(next, file)) // #nosec G304 -- the test's own temp dir
		check(t, err)
		tmp := filepath.Join(d, file+".tmp")
		check(t, os.WriteFile(tmp, data, 0o600))
		check(t, os.Rename(tmp, filepath.Join(d, file)))
	}
	replace(KeyFile) // read after the renewal
	done := make(chan *Identity, 1)
	go func() {
		m, err := Load(d)
		if err != nil {
			t.Error(err)
		}
		done <- m
	}()
	select {
	case <-done:
		t.Fatal("Load returned with the key renewed and the certificate not yet")
	case <-time.After(50 * time.Millisecond):
	}
	replace(CertFile)
	if m := <-done; m != nil {
		c, err := m.Certificate()
		check(t, err)
		if !c.Leaf.Equal(renewed) {
			t.Errorf("Load took %s, want the renewed certificate", c.Leaf.Subject)
		}
	}
}
