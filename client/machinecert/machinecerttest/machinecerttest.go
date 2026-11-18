// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package machinecerttest saves a test machine's certificate and key in a
// config directory the way `nfltr config login` saves them.
package machinecerttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
)

// MachineID is the machine Save's certificate names.
const MachineID = "m-aaaaaaaaaaaaaaaaaaaaaaaaaa"

// Save writes a machine certificate for relayHost (signed by a throwaway
// CA) and its key into dir; it returns the leaf.
func Save(t testing.TB, dir, relayHost string) *x509.Certificate {
	t.Helper()
	key, _ := machinecert.NewKey()
	if err := machinecert.SaveKey(machinecert.KeyPath(dir), key); err != nil {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse("spiffe://nfltr.xyz/m/" + MachineID)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"machine_id": MachineID, "name": "box1", "group": "default",
		"chain": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "relay_host": relayHost, "base_url": "https://" + relayHost})
	if err := os.WriteFile(machinecert.CertPath(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := x509.ParseCertificate(der)
	return out
}
