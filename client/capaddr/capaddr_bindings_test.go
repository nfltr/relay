// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package capaddr

// The bindings spec/proverif/cap_address.pv relies on, against the real
// code: each BIND:<id> the model lists has one row here that changes just
// what a relay (or the holder of another address of the same server) can
// change of an honest exchange and requires a refusal. TLS sessions are
// real (crypto/tls over a pipe). `make spec-bindings`.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"regexp"
	"slices"
	"testing"
)

const capBindModel = "../../spec/proverif/cap_address.pv"

// honest is one server key serving two addresses at one relay (the model's
// A1 and A2) and A1's registration.
type honest struct {
	sk     ed25519.PrivateKey
	spki   []byte
	a1, a2 Address
	hints  []byte
	rec    []byte
}

func newHonest(t *testing.T) honest {
	sk, spki := newKey(t)
	a1, err := New("relay.example.com", spki)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := New("relay.example.com", spki)
	if err != nil {
		t.Fatal(err)
	}
	hints := []byte("direct candidates")
	return honest{sk, spki, a1, a2, hints, mustSign(t, sk, a1.Relay, a1.RID, hints)}
}

func refused(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", what, err, want)
	}
}

var capBindings = map[string]func(t *testing.T, h honest){
	// The answer's key and the TLS certificate's key, each against
	// pinOf(sec, key): another key, with a record honestly signed by it.
	"cap.pin": func(t *testing.T, h honest) {
		osk, ospki := newKey(t)
		refused(t, "answer with another key", h.a1.CheckAnswer(ospki, mustSign(t, osk, h.a1.Relay, h.a1.RID, h.hints), h.hints), ErrPin)
		refused(t, "answer with no key (plain)", h.a1.CheckAnswer(nil, nil, h.hints), ErrPin)
		if _, _, err := session(t, h.a1, osk); !errors.Is(err, ErrPin) {
			t.Errorf("TLS certificate of another key: %v, want ErrPin", err)
		}
	},
	// The answer: signed under the pinned key, over the tag, the relay
	// opened at, rid and hints.
	"cap.rendezvous": func(t *testing.T, h honest) {
		osk, _ := newKey(t)
		a := h.a1
		otherTag := ed25519.Sign(h.sk, append([]byte("nf1-xxx"), rendezvousMessage(a.Relay, a.RID, h.hints)[len(tagRendezvous):]...))
		for what, rec := range map[string][]byte{
			"another relay": mustSign(t, h.sk, "other.example.com", a.RID, h.hints),
			"another rid":   mustSign(t, h.sk, a.Relay, h.a2.RID, h.hints),
			"other hints":   mustSign(t, h.sk, a.Relay, a.RID, []byte("attacker candidates")),
			"another tag":   otherTag,
			"another key":   mustSign(t, osk, a.Relay, a.RID, h.hints),
			"no record":     nil,
		} {
			refused(t, what, a.CheckAnswer(h.spki, rec, h.hints), ErrRendezvous)
		}
		refused(t, "hints changed after signing", a.CheckAnswer(h.spki, h.rec, []byte("attacker candidates")), ErrRendezvous)
	},
	// The proof: the address's secret over this session's exporter.
	"cap.secret": func(t *testing.T, h honest) {
		cexp, sexp, err := session(t, h.a1, h.sk)
		if err != nil {
			t.Fatal(err)
		}
		other, _, err := session(t, h.a1, h.sk)
		if err != nil {
			t.Fatal(err)
		}
		replayed := Proof(h.a1.Secret, other)
		refused(t, "proof over another session's exporter", Admit(h.a1.Secret, sexp, replayed[:]), ErrProof)
		var guess [SecretSize]byte
		guess[0] = 1
		forged := Proof(guess, cexp)
		refused(t, "proof under another secret", Admit(h.a1.Secret, sexp, forged[:]), ErrProof)
		unbound := Proof(h.a1.Secret, nil)
		refused(t, "proof without the exporter", Admit(h.a1.Secret, sexp, unbound[:]), ErrProof)
	},
	// The acceptor checks the proof with the secret of the address routed
	// to it: A1's client's session routed to A2's acceptor, and the holder
	// of A2 at A1's acceptor, both under the same key.
	"cap.service": func(t *testing.T, h honest) {
		cexp, sexp, err := session(t, h.a1, h.sk)
		if err != nil {
			t.Fatal(err)
		}
		p1 := Proof(h.a1.Secret, cexp)
		refused(t, "A1's proof at A2's acceptor", Admit(h.a2.Secret, sexp, p1[:]), ErrProof)
		cexp2, sexp2, err := session(t, h.a2, h.sk)
		if err != nil {
			t.Fatal(err)
		}
		p2 := Proof(h.a2.Secret, cexp2)
		refused(t, "A2's proof at A1's acceptor", Admit(h.a1.Secret, sexp2, p2[:]), ErrProof)
	},
}

// TestCapAddressModelBindings runs every row after an honest exchange, and
// fails when the model's BIND ids and the rows differ.
func TestCapAddressModelBindings(t *testing.T) {
	src, err := os.ReadFile(capBindModel)
	if err != nil {
		t.Fatal(err)
	}
	var model, rows []string
	for _, m := range regexp.MustCompile(`BIND:([a-z0-9][a-z0-9.]*[a-z0-9])`).FindAllSubmatch(src, -1) {
		model = append(model, string(m[1]))
	}
	for id := range capBindings {
		rows = append(rows, id)
	}
	slices.Sort(model)
	model = slices.Compact(model)
	slices.Sort(rows)
	if !slices.Equal(model, rows) {
		t.Fatalf("%s BIND ids %v, rows %v: each binding of the model needs one row", capBindModel, model, rows)
	}
	h := newHonest(t)
	t.Run("honest", func(t *testing.T) {
		if err := h.a1.CheckAnswer(h.spki, h.rec, h.hints); err != nil {
			t.Fatal(err)
		}
		cexp, sexp, err := session(t, h.a1, h.sk)
		if err != nil {
			t.Fatal(err)
		}
		p := Proof(h.a1.Secret, cexp)
		if err := Admit(h.a1.Secret, sexp, p[:]); err != nil {
			t.Fatal(err)
		}
	})
	for _, id := range rows {
		t.Run(id, func(t *testing.T) { capBindings[id](t, h) })
	}
}

func mustSign(t testing.TB, sk ed25519.PrivateKey, relay string, rid [RIDSize]byte, hints []byte) []byte {
	t.Helper()
	rec, err := SignRecord(sk, relay, rid, hints)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
