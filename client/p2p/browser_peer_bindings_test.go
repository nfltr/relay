// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

// The bindings spec/proverif/browser_peer.pv relies on at the agent: each
// BIND:<id> row changes one field of an honest visitor's session and
// requires the agent to refuse. The visitor is the pion stand-in of
// browserpeer_test.go; BIND:browser.bundle is the bundle's (lane BP4,
// modelbind.Pending). `make spec-bindings`.

import (
	"context"
	"crypto/x509"
	"errors"
	"maps"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/nfltr/relay/client/nf1"
)

const browserBindModel = "../../spec/proverif/browser_peer.pv"

// otherAddress is a second address of the agent's key (the model's A2):
// its pin holds for the agent's certificate, its secret is not the
// served address's.
func otherAddress(t *testing.T, a *bpAgent) capaddr.Address {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(a.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	addr, err := capaddr.New(a.l.Address().Relay, spki)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

var browserBindings = map[string]func(t *testing.T){
	// The agent writes its SDP only after Admit, inside the TLS
	// (signal-before-admit): a control session whose proof is under
	// another secret, and one that sends its offer in the clear, get no
	// answer and no connection.
	"browser.signal": func(t *testing.T) {
		a := newBPAgent(t, &BrowserDirect{})
		ctl, done := a.control(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := nf1.ClientTLS(ctx, ctl, otherAddress(t, a)); !errors.Is(err, capaddr.ErrProof) {
			t.Fatalf("a control session under another secret: %v, want %v", err, capaddr.ErrProof)
		}
		<-done
		ctl, done = a.control(t)
		go func() { _ = writeSignal(ctl, nil) }()
		if _, err := readSignal(ctl); err == nil {
			t.Fatal("an offer in the clear was answered")
		}
		<-done
		if n := a.b.offers.Load(); n != 0 {
			t.Fatalf("%d connections made for control sessions not admitted", n)
		}
	},
	// A data channel's bytes reach the service only after its own nf1
	// handshake (dc-no-proof): a stream whose proof is under another
	// secret, on a connection of an admitted control session, is refused
	// before the service.
	"browser.dc.nf1": func(t *testing.T) {
		a := newBPAgent(t, &BrowserDirect{})
		ctl, _ := a.control(t)
		v := newBPVisitor(t)
		v.admitted(t, ctl, a.l.Address())
		dc := openDC(t, v.first)
		_ = dc.SetDeadline(time.Now().Add(10 * time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := nf1.ReadAnswer(dc, a.l.Address()); err != nil {
			t.Fatal(err)
		}
		if _, err := nf1.ClientTLS(ctx, dc, otherAddress(t, a)); !errors.Is(err, capaddr.ErrProof) {
			t.Fatalf("a stream under another secret: %v, want %v", err, capaddr.ErrProof)
		}
		c, err := v.stream(t, a.l.Address(), false)
		if err != nil {
			t.Fatal(err)
		}
		if err := echo(t, c, "honest"); err != nil {
			t.Fatal(err)
		}
		if n := a.served.Load(); n != 1 {
			t.Fatalf("served %d streams, want the honest one only", n)
		}
	},
}

func TestBrowserPeerModelBindings(t *testing.T) {
	src, err := os.ReadFile(browserBindModel)
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(browserBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:([a-z0-9.]+)`), rows); err != nil {
		t.Fatalf("%s: %v", browserBindModel, err)
	}
	for _, id := range rows {
		t.Run(id, browserBindings[id])
	}
}
