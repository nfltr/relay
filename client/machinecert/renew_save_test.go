// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"
)

// enrolPair saves a key and a certificate of machine id in dir, as
// `nfltr config login` does; it returns the key and a renewal of the same
// machine (a new certificate for the same key).
func enrolPair(t *testing.T, dir, id string) (*ecdsa.PrivateKey, *Cert) {
	t.Helper()
	key, _ := NewKey()
	if err := SaveKey(KeyPath(dir), key); err != nil {
		t.Fatal(err)
	}
	s := Saved{Cert: *leafFor(t, key, id, 1), RelayHost: "127.0.0.1", BaseURL: "https://127.0.0.1"}
	if err := s.Store(dir); err != nil {
		t.Fatal(err)
	}
	return key, leafFor(t, key, id, 2)
}

func leafFor(t *testing.T, key *ecdsa.PrivateKey, id string, serial int64) *Cert {
	t.Helper()
	u, _ := url.Parse("spiffe://nfltr.xyz/m/" + id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCert(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	c.MachineID = id
	return c
}

func files(t *testing.T, dir string) []byte {
	t.Helper()
	k, err := os.ReadFile(KeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(CertPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	return append(k, c...)
}

// A process holding machine A's pair renews after `nfltr config login`
// replaced the directory's pair with machine B's: the renewal is kept in
// memory and the directory stays B's (a v2.1.67 nfltr up wrote
// A's certificate over B's key, and every certificate user on the machine
// failed its TLS handshake).
func TestRenewalNeverWritesOverAnotherMachinesPair(t *testing.T) {
	dir := t.TempDir()
	_, next := enrolPair(t, dir, "m-aaaa")
	c := load(dir)
	if c == nil {
		t.Fatal("pair A did not load")
	}
	enrolPair(t, dir, "m-bbbb") // nfltr config login: another machine's pair
	before := files(t, dir)
	if err := c.save(next, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("save: %v, want nil (kept in memory)", err)
	}
	if !bytes.Equal(files(t, dir), before) {
		t.Fatal("the renewal wrote over machine B's pair")
	}
	if got := c.cur.Load().Leaf; got == nil || got.SerialNumber.Cmp(next.Leaf.SerialNumber) != 0 {
		t.Fatal("the renewed certificate is not presented from memory")
	}
}

// The directory still holding this process's pair: the renewal is saved.
func TestRenewalSavesItsOwnPair(t *testing.T) {
	dir := t.TempDir()
	_, next := enrolPair(t, dir, "m-aaaa")
	c := load(dir)
	if err := c.save(next, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil || s.Leaf.SerialNumber.Cmp(next.Leaf.SerialNumber) != 0 {
		t.Fatalf("saved = %v, %v; want the renewal", s, err)
	}
}

// A node's agent holds the key in KeyEnv: a directory whose certificate is
// now another machine's is not written either.
func TestRenewalWithKeyEnvNeverWritesOverAnotherMachinesCertificate(t *testing.T) {
	dir := t.TempDir()
	_, next := enrolPair(t, dir, "m-aaaa")
	c := load(dir)
	t.Setenv(KeyEnv, c.KeyPEM())
	enrolPair(t, dir, "m-bbbb")
	before := files(t, dir)
	if err := c.save(next, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(files(t, dir), before) {
		t.Fatal("the renewal wrote over machine B's certificate")
	}
}
