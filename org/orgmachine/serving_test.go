// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
	"github.com/nfltr/relay/org/orgpki"
)

// A serving process (nfltr cat serve, nfltr up) takes a renewal another
// process on the machine installed (its keeper) at its next Reload, which
// nfltr's watchOrg runs at the files' change notice: it presents the new
// certificate and signs SSH with the new key, without a restart (lane
// CERTGAPS).
func TestServingMachineTakesAnotherProcesssRenewal(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	dir := filepath.Join(t.TempDir(), "web")
	o.Enrol(t, dir, "web", now, "web")
	serving, keeper := open(t, dir), open(t, dir)
	cur, curKey := keeper.Current()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.Issuer.Renew(orgpki.NewRenewRequest(cur.Raw, curKey, csr), now)
	if err != nil {
		t.Fatal(err)
	}
	host, err := o.Issuer.HostCert(der, now)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := keeper.LockRenewal()
	if err != nil {
		t.Fatal(err)
	}
	err = keeper.Install(der, o.Issuer.Cert().Raw, host, key, now)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := serving.Reload(now); err != nil || !changed {
		t.Fatalf("Reload after another process's renewal: changed %v, %v", changed, err)
	}
	if c, k := serving.Current(); !bytes.Equal(c.Raw, der) || !k.Equal(key) {
		t.Fatal("the serving process still presents the old certificate")
	}
	s, err := serving.HostSigner()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := s.PublicKey().(*ssh.Certificate)
	want, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !bytes.Equal(c.Key.Marshal(), want.Marshal()) {
		t.Fatal("the serving process signs SSH with the old key")
	}
}
