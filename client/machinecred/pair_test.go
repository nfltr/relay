// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
	"github.com/nfltr/relay/client/pairfile"
)

// A process that read machine.json before a whole `nfltr config login` and
// the key after it reads again (lane CERTPAIR) instead of presenting the
// new key with the old certificate; the files here stand for what it read.
func TestLoadWaitsForTheWritersCertificate(t *testing.T) {
	dir := t.TempDir()
	enrolPair(t, dir, "m-a")
	key, _ := machinecert.NewKey()
	if err := machinecert.SaveKey(machinecert.KeyPath(dir), key); err != nil { // read after the login
		t.Fatal(err)
	}
	done := make(chan *Credential, 1)
	go func() { done <- load(dir) }()
	select {
	case c := <-done:
		t.Fatalf("load returned with the key replaced and the certificate not yet: %v", c != nil)
	case <-time.After(50 * time.Millisecond):
	}
	s := machinecert.Saved{Cert: *leafFor(t, key, "m-b", 1), RelayHost: "127.0.0.1", BaseURL: "https://127.0.0.1"}
	if err := s.Store(dir); err != nil {
		t.Fatal(err)
	}
	if c := <-done; c == nil || c.MachineID() != "m-b" || !c.key.Equal(key) {
		t.Fatalf("load: %+v, want machine m-b with the new key", c)
	}
}

// `nfltr config login` stopped after each of its steps (killed: the files
// as machinecert.SavePair's step left them) leaves a credential, the old
// machine's or the new one's, and the next login completes (lane
// CERTATOMIC, spec/pair/MachinePair.tla Usable; before it, a login killed
// between the key and machine.json left a machine that needed another
// login).
func TestEveryStoppedLoginLoads(t *testing.T) {
	for n := range pairfile.Steps + 1 {
		dir := t.TempDir()
		enrolPair(t, dir, "m-a")
		key, _ := machinecert.NewKey()
		s := machinecert.Saved{Cert: *leafFor(t, key, "m-b", 1), RelayHost: "127.0.0.1", BaseURL: "https://127.0.0.1"}
		b, err := json.MarshalIndent(&s, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		kp := machinecert.KeyPath(t.TempDir())
		if err := machinecert.SaveKey(kp, key); err != nil {
			t.Fatal(err)
		}
		kb, err := os.ReadFile(kp) // #nosec G304 -- the test's own temp dir
		if err != nil {
			t.Fatal(err)
		}
		if err := machinecert.Pair(dir).WriteFirst(n, append(b, '\n'), kb); err != nil {
			t.Fatal(err)
		}
		if c := load(dir); c == nil || (c.MachineID() != "m-a" && c.MachineID() != "m-b") {
			t.Fatalf("stopped after %d steps: load %+v", n, c)
		}
		if err := machinecert.SavePair(dir, &s, key); err != nil {
			t.Fatal(err)
		}
		if c := load(dir); c == nil || c.MachineID() != "m-b" || !c.key.Equal(key) {
			t.Fatalf("stopped after %d steps, then a login: load %+v", n, c)
		}
	}
}

// With $NFLTR_MACHINE_KEY the key is not the directory's: machine.json of
// another key is no credential.
func TestLoadRefusesAnEnvKeyOfAnotherCertificate(t *testing.T) {
	dir := t.TempDir()
	enrolPair(t, dir, "m-a")
	other, _ := machinecert.NewKey()
	kp := machinecert.KeyPath(t.TempDir())
	if err := machinecert.SaveKey(kp, other); err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(kp) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(machinecert.KeyEnv, string(kb))
	if c := load(dir); c != nil {
		t.Fatalf("load took machine.json of another key than %s", machinecert.KeyEnv)
	}
}
