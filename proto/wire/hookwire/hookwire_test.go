// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package hookwire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen(t *testing.T) {
	k := key(t)
	b := Binding{Owner: "alice", Mailbox: "hub.h1.hooks", WebhookID: "wh-1", KeyID: "k1"}
	body := []byte(`{"alert":"disk full"}`)
	row, err := Seal(k.PublicKey(), b, "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row, body) || bytes.Contains(row, []byte("application/json")) {
		t.Fatal("the row holds the plaintext")
	}
	if id, err := KeyID(row); err != nil || id != "k1" {
		t.Fatalf("KeyID %q, %v", id, err)
	}
	ct, got, err := Open(k, b, row)
	if err != nil || ct != "application/json" || !bytes.Equal(got, body) {
		t.Fatalf("Open %q %q %v", ct, got, err)
	}
	// another key, another binding, a changed byte: refused
	if _, _, err := Open(key(t), b, row); err == nil {
		t.Fatal("opened with another key")
	}
	for _, other := range []Binding{
		{Owner: "eve", Mailbox: b.Mailbox, WebhookID: b.WebhookID, KeyID: b.KeyID},
		{Owner: b.Owner, Mailbox: "hub.h2.hooks", WebhookID: b.WebhookID, KeyID: b.KeyID},
		{Owner: b.Owner, Mailbox: b.Mailbox, WebhookID: "wh-2", KeyID: b.KeyID},
		{Owner: b.Owner, Mailbox: b.Mailbox, WebhookID: b.WebhookID, KeyID: "k2"},
	} {
		if _, _, err := Open(k, other, row); err == nil {
			t.Fatalf("opened for %+v", other)
		}
	}
	bad := bytes.Clone(row)
	bad[len(bad)-1] ^= 1
	if _, _, err := Open(k, b, bad); err == nil {
		t.Fatal("opened an altered row")
	}
}

// Sizes leak only to the bucket.
func TestPadding(t *testing.T) {
	k := key(t)
	b := Binding{Owner: "o", Mailbox: "m", WebhookID: "w", KeyID: "k"}
	a, _ := Seal(k.PublicKey(), b, "", make([]byte, 10))
	c, _ := Seal(k.PublicKey(), b, "text/plain", make([]byte, 900))
	d, _ := Seal(k.PublicKey(), b, "", make([]byte, 1100))
	if len(a) != len(c) || len(d) <= len(a) {
		t.Fatalf("sizes %d %d %d: want the first two equal, the third a bucket larger", len(a), len(c), len(d))
	}
	_, got, err := Open(k, b, d)
	if err != nil || len(got) != 1100 {
		t.Fatalf("%d %v", len(got), err)
	}
}

func TestMalformed(t *testing.T) {
	for _, row := range [][]byte{nil, {}, {5, 'a'}, {0}, {1, ' '}} {
		if _, err := KeyID(row); err == nil {
			t.Fatalf("KeyID(%q) accepted", row)
		}
	}
}

func FuzzOpen(f *testing.F) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	b := Binding{Owner: "o", Mailbox: "m", WebhookID: "w", KeyID: "k"}
	row, _ := Seal(k.PublicKey(), b, "t", []byte("body"))
	f.Add(row)
	f.Fuzz(func(t *testing.T, row []byte) {
		_, _, _ = Open(k, b, row) // never panics
	})
}
