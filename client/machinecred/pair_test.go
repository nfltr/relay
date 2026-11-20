// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
)

// `nfltr config login` replaces the key, then machine.json, each by rename
// (lane CERTPAIR): a process loading the credential between the two waits
// for the certificate instead of presenting the new key with the old
// certificate.
func TestLoadWaitsForTheWritersCertificate(t *testing.T) {
	dir := t.TempDir()
	enrolPair(t, dir, "m-a")
	key, _ := machinecert.NewKey()
	if err := machinecert.SaveKey(machinecert.KeyPath(dir), key); err != nil { // the writer, between its two renames
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
