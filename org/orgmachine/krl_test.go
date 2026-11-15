// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stripe/krl"
	"golang.org/x/crypto/ssh"

	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
)

// The KRL follows the CRL: a CRL push (TakeCRL) revoking lost rewrites it by rename
// (a reader of the old file reads the whole old one), another machine stays
// in, and a process holding an older CRL never takes the file back.
func TestKRLFollowsTheCRL(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	o := orgmachinetest.New(t, now)
	d := t.TempDir()
	o.Enrol(t, filepath.Join(d, "web"), "web", now, "web")
	o.Enrol(t, filepath.Join(d, "lost"), "lost", now, "db")
	web, stale := open(t, filepath.Join(d, "web")), open(t, filepath.Join(d, "web"))
	hostCert := func(name string) ssh.PublicKey {
		s, err := open(t, filepath.Join(d, name)).HostSigner()
		if err != nil {
			t.Fatal(err)
		}
		return s.PublicKey()
	}
	path, err := web.KRL()
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("KRL %s: %v %v, want mode 0644", path, fi, err)
	}
	revoked := func() (lost, webIn bool) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		k, err := krl.ParseKRL(data)
		if err != nil {
			t.Fatal(err)
		}
		return k.IsRevoked(hostCert("lost")), k.IsRevoked(hostCert("web"))
	}
	if lost, w := revoked(); lost || w {
		t.Fatalf("before the revoke: lost %v web %v", lost, w)
	}
	before, _ := os.ReadFile(path)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	at := now.Add(2 * time.Second)
	if err := o.Issuer.Revoke("lost", at); err != nil {
		t.Fatal(err)
	}
	crl, err := o.Issuer.CRL(at)
	if err != nil {
		t.Fatal(err)
	}
	if taken, err := web.TakeCRL(crl, o.Issuer.Cert().Raw, at); err != nil || !taken {
		t.Fatalf("TakeCRL: %v %v", taken, err)
	}
	if lost, w := revoked(); !lost || w {
		t.Fatalf("after the revoke: lost revoked %v, web revoked %v", lost, w)
	}
	var old bytes.Buffer
	if _, err := old.ReadFrom(reader); err != nil || !bytes.Equal(old.Bytes(), before) {
		t.Fatalf("the reader of the old KRL read %d bytes, want the whole old file (%d): %v", old.Len(), len(before), err)
	}
	if _, err := stale.KRL(); err != nil {
		t.Fatal(err)
	}
	if lost, _ := revoked(); !lost {
		t.Fatal("a process holding the older CRL took the KRL back")
	}
	if left, _ := filepath.Glob(filepath.Join(d, "web", orgmachine.KRLFile+".*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}
