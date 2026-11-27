// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/client/pairfile"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
)

// An Open that read the certificate before another process's whole
// renewal and the key after it (lane CERTPAIR: nfltr cat serve --ssh
// failed "machine.pem: tls: private key does not match public key" while
// another process renewed) reads again; the files here stand for what it
// read.
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
	replace(orgmachine.KeyFile) // read after the renewal
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

// A renewal stopped after each of its steps (killed: the files as that
// step left them) leaves a machine that opens, with the old certificate or
// the renewed one, and the next renewal completes (lane CERTATOMIC,
// spec/pair/MachinePair.tla Usable; before it, a renewal killed between the
// key and the certificate left a machine that needed nfltr org join again).
func TestEveryStoppedRenewalOpens(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	for n := range pairfile.Steps + 1 {
		d, next := t.TempDir(), t.TempDir()
		old := o.Enrol(t, d, "web"+string(rune('a'+n)), now, "web")
		renewed := o.Enrol(t, next, "renewed"+string(rune('a'+n)), now, "web")
		chain, err := os.ReadFile(filepath.Join(next, orgmachine.CertFile)) // #nosec G304 -- the test's own temp dir
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(filepath.Join(next, orgmachine.KeyFile)) // #nosec G304 -- the test's own temp dir
		if err != nil {
			t.Fatal(err)
		}
		if err := orgid.Pair(d).WriteFirst(n, chain, key); err != nil {
			t.Fatal(err)
		}
		m, err := orgmachine.Open(d)
		if err != nil {
			t.Fatalf("stopped after %d steps: %v", n, err)
		}
		if cur, _ := m.Current(); !cur.Equal(old) && !cur.Equal(renewed) {
			t.Fatalf("stopped after %d steps: opened %s", n, cur.Subject)
		}
		if err := orgid.Pair(d).Write(chain, key); err != nil {
			t.Fatal(err)
		}
		if m, err = orgmachine.Open(d); err != nil {
			t.Fatalf("stopped after %d steps, then renewed: %v", n, err)
		}
		if cur, _ := m.Current(); !cur.Equal(renewed) {
			t.Fatalf("stopped after %d steps, then renewed: opened %s", n, cur.Subject)
		}
	}
}
