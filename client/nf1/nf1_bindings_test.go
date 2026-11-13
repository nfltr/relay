// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

// The bindings spec/proverif/cap_address.pv relies on, against the
// transport (the codec's own rows are client/capaddr's): each BIND:<id> has
// one row that changes what a relay can change of an honest session and
// requires the client's or the listener's refusal. `make spec-bindings`.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nfltr/relay/client/capaddr"
)

func refusedBy(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", what, err, want)
	}
}

var nf1Bindings = map[string]func(t *testing.T){
	// The relay routes the session to another server (another key), or
	// answers with the address's key and then runs TLS under another.
	"cap.pin": func(t *testing.T) {
		l, _ := mint(t)
		other, _ := mint(t)
		_, err, _ := run(t, l.Address(), func(s net.Conn) error {
			_, err := other.Accept(context.Background(), s)
			return err
		})
		refusedBy(t, "another server's answer", err, capaddr.ErrPin)
		_, err, _ = run(t, l.Address(), func(s net.Conn) error {
			if _, err := s.Write(appendAnswer(nil, l.spki, l.rec, nil)); err != nil {
				return err
			}
			return tls.Server(s, other.cfg).Handshake()
		})
		refusedBy(t, "the address's answer, another key's TLS", err, capaddr.ErrPin)
	},
	// The right key with a record over another rid, or with hints the
	// record does not cover.
	"cap.rendezvous": func(t *testing.T) {
		l, key := mint(t)
		spki, _ := x509.MarshalPKIXPublicKey(key.Public())
		rec, _ := capaddr.SignRecord(key, relay, [capaddr.RIDSize]byte{7}, nil)
		_, err, _ := run(t, l.Address(), func(s net.Conn) error {
			_, err := s.Write(appendAnswer(nil, spki, rec, nil))
			return err
		})
		refusedBy(t, "a record over another rid", err, capaddr.ErrRendezvous)
		_, err, _ = run(t, l.Address(), func(s net.Conn) error {
			_, err := s.Write(appendAnswer(nil, l.spki, l.rec, []byte("added hints")))
			return err
		})
		refusedBy(t, "hints the record does not cover", err, capaddr.ErrRendezvous)
		_, err, _ = run(t, l.Address(), func(s net.Conn) error {
			_, err := s.Write(appendAnswer(nil, l.spki, l.rec, []byte(HintDirect)))
			return err
		})
		refusedBy(t, "a direct-path hint the record does not cover (cap_address.pv hint-unbound)", err, capaddr.ErrRendezvous)
	},
	// A proof over another exporter than this session's: the listener
	// refuses it and sends no verdict.
	"cap.secret": func(t *testing.T) {
		l, _ := mint(t)
		c, s := net.Pipe()
		serr := make(chan error, 1)
		go func() { _, err := l.Accept(context.Background(), s); serr <- err }()
		defer c.Close() //nolint:errcheck
		if _, _, _, err := readAnswer(c); err != nil {
			t.Fatal(err)
		}
		addr := l.Address()
		tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: addr.VerifyConnection}) // #nosec G402 -- the pin
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		proof := capaddr.Proof(addr.Secret, []byte("another session's exporter"))
		if _, err := tc.Write(proof[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(tc, make([]byte, 1)); err == nil {
			t.Error("a verdict for a proof over another exporter")
		}
		refusedBy(t, "proof over another exporter", <-serr, capaddr.ErrProof)
	},
	// A1's client routed to A2's listener (one key, two addresses): the
	// listener checks with its own address's secret.
	"cap.service": func(t *testing.T) {
		l2, key := mint(t)
		spki, _ := x509.MarshalPKIXPublicKey(key.Public())
		a1, err := capaddr.New(relay, spki)
		if err != nil {
			t.Fatal(err)
		}
		a1.RID = l2.Address().RID // the record A2's listener signs verifies for this client
		_, err, serr := run(t, a1, func(s net.Conn) error {
			_, err := l2.Accept(context.Background(), s)
			return err
		})
		refusedBy(t, "client", err, capaddr.ErrProof)
		refusedBy(t, "listener", serr, capaddr.ErrProof)
	},
}

func TestNF1ModelBindings(t *testing.T) {
	for id, row := range nf1Bindings {
		t.Run(id, row)
	}
}
