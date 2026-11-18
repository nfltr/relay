// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nfltr/relay/client/machinecert"
)

// The files `nfltr config login` writes and every program reads (moved
// from nfltr's machinecred, lane ORCHX1): their names, the certificate
// file's 0600 mode, a round trip through machinecert.Load, the relay match, and the
// refusal users read, unchanged.
func TestFilesAndMessagesUnchanged(t *testing.T) {
	dir := t.TempDir()
	if machinecert.KeyPath(dir) != filepath.Join(dir, "machine.key") || machinecert.CertPath(dir) != filepath.Join(dir, "machine.json") || machinecert.KeyEnv != "NFLTR_MACHINE_KEY" {
		t.Fatalf("file layout changed: %s %s %s", machinecert.KeyPath(dir), machinecert.CertPath(dir), machinecert.KeyEnv)
	}
	key, _ := enrolPair(t, dir, "m-aaaa")
	if fi, err := os.Stat(machinecert.CertPath(dir)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("machine.json mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	s, err := machinecert.Load(dir)
	if err != nil || s.MachineID != "m-aaaa" || s.RelayHost != "127.0.0.1" || s.BaseURL != "https://127.0.0.1" || s.Leaf == nil {
		t.Fatalf("machinecert.Load = %+v, %v", s, err)
	}
	c := ForRelay(dir, "https://127.0.0.1:8443")
	t.Cleanup(Forget)
	if c == nil || c.MachineID() != "m-aaaa" || !c.key.Equal(key) {
		t.Fatal("ForRelay did not load the saved pair")
	}
	if ForRelay(dir, "other.example:443") != nil {
		t.Fatal("a certificate for another relay was presented")
	}
	for in, want := range map[string]string{"grpc.nfltr.xyz:443": "grpc.nfltr.xyz", "https://nfltr.xyz/x": "nfltr.xyz", "relay": "relay"} {
		if got := machinecert.RelayHost(in); got != want {
			t.Errorf("machinecert.RelayHost(%q) = %q, want %q", in, got, want)
		}
	}
	if !sameRelay("nfltr.xyz", "grpc.nfltr.xyz:443") {
		t.Error("the hosted relay's gRPC host is not its HTTP host")
	}
	const msg = "the relay refused this machine's certificate (revoked, rotated away or expired): run `nfltr config login` to enrol this machine again"
	if ErrRefused.Error() != msg {
		t.Fatalf("ErrRefused = %q", ErrRefused)
	}
}
