// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wgexit

// The bindings spec/proverif/wg_exit.pv relies on, against the real code:
// each BIND:<id> the model lists has one row here (or, for the client's
// choices, in nfltr: ids nfltr.*) that changes just what the relay can
// change of an honest pairing and requires the WireGuard handshake to fail.
// The handshakes are real: wireguard-go tunnels on both ends, this file's
// relay moving their sealed packets. `make spec-bindings`.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/wg"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/wgwire"
)

const wgBindModel = "../../../spec/proverif/wg_exit.pv"

// wgNfltrRows are the model's client-side ids, whose rows are in nfltr
// cmd/nfltr/internal/wgcli/wg_exit_bindings_test.go (the client's choices:
// which key id it takes, its psk whatever x-wg-paired says, one key per
// machine). A change here changes those rows.
var wgNfltrRows = []string{"nfltr.client.kid", "nfltr.client.paired", "nfltr.key.machine"}

var wgBindKey = []byte("0123456789abcdef0123456789abcdef")

// pairedExit is an exit named name with key id kid holding key (nil:
// unpaired).
func pairedExit(t *testing.T, key []byte, name, kid string) *exit {
	t.Helper()
	x, err := update(nil, generateKeys([]string{"all"}))
	if err == nil && key != nil {
		x, err = update(x, pairing(key, name, kid))
	}
	if err != nil {
		t.Fatal(err)
	}
	return x.(*exit)
}

// wgClient is what a client sets on its tunnel: its key pair, the exit key
// the relay told it and its preshared key.
type wgClient struct{ priv, pub, peer, psk string }

func newWGClient(t *testing.T, peer string, key []byte, name, kid string) wgClient {
	t.Helper()
	priv, pub, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := wgClient{priv: priv, pub: pub, peer: peer}
	if key != nil {
		if c.psk, err = wg.PresharedKey(key, name, kid); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// handshake runs client c against exit x through a relay that tells x the
// client key told (PeerUpdate), and reports whether the client completed a
// handshake: its first transport packet (wireguard-go's keepalive after the
// response) reached the exit. Once the exit's response has reached the
// client, a refusal is a second without one; an honest handshake takes
// milliseconds.
func handshake(t *testing.T, x *exit, c wgClient, told string) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	xt, err := x.start(ctx, netip.MustParseAddr("100.64.0.2"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	u, _ := json.Marshal(wgwire.PeerUpdate{Op: wgwire.PeerAdd, PublicKey: told, IP: netip.MustParseAddr("100.64.0.3")})
	xt.Handle(&pb.HTTPRequest{TransactionId: wgwire.PeerTxnID, Payload: u})

	cb := wg.NewRelayBind()
	ct := wg.NewTunnel(log)
	defer ct.Close()
	if err := ct.Start(ctx, wg.TunnelConfig{PrivateKey: c.priv, PeerPublicKey: c.peer, PresharedKey: c.psk,
		LocalAddress: netip.MustParseAddr("100.64.0.3"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}, cb); err != nil {
		t.Fatal(err)
	}
	responded, transport := make(chan struct{}, 8), make(chan struct{}, 8)
	go func() { // the relay: client -> exit
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-cb.Outbound():
				if !ok {
					return
				}
				if p.Data[0] == 4 { // MessageTransportType
					transport <- struct{}{}
				}
				xt.Handle(&pb.HTTPRequest{TransactionId: wgwire.ExitPacketTxnID(told), Payload: p.Data})
			}
		}
	}()
	go func() { // exit -> client
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-xt.bind.Outbound():
				if !ok {
					return
				}
				_ = cb.Deliver("", p.Data)
				if p.Data[0] == 2 { // MessageResponseType
					responded <- struct{}{}
				}
			}
		}
	}()
	if err := ct.Rehandshake(c.peer); err != nil {
		t.Fatal(err)
	}
	var after <-chan time.Time
	for {
		select {
		case <-transport:
			return true
		case <-responded:
			after = time.After(time.Second)
		case <-after:
			return false
		case <-time.After(10 * time.Second):
			if after == nil {
				t.Fatal("the exit never answered the client's initiation")
			}
		}
	}
}

func refusedHandshake(t *testing.T, what string, x *exit, c wgClient, told string) {
	t.Helper()
	if handshake(t, x, c, told) {
		t.Fatalf("%s: handshake completed", what)
	}
}

var wgBindings = map[string]func(t *testing.T){
	// p = hpsk(k, name, kid): name. Two exits on one machine key; the relay
	// reroutes a client of home3 to office3 (finding 5, query 4).
	"psk.name": func(t *testing.T) {
		office := pairedExit(t, wgBindKey, "office3", "m3.1")
		c := newWGClient(t, office.publicKey, wgBindKey, "home3", "m3.1")
		refusedHandshake(t, "a client of home3 at office3", office, c, c.pub)
	},
	// RootClient's p: the client applies its psk to the exit key the relay
	// told it; the relay tells its own (an exit without the key).
	"client.psk": func(t *testing.T) {
		relays := pairedExit(t, nil, "home1", "")
		c := newWGClient(t, relays.publicKey, wgBindKey, "home1", "m1.1")
		refusedHandshake(t, "a paired client at the relay's exit", relays, c, c.pub)
	},
	// Exit's p: the exit applies its own psk to the client key the relay
	// told it (PeerUpdate); the relay tells its own (a client without the key).
	"exit.psk": func(t *testing.T) {
		home := pairedExit(t, wgBindKey, "home1", "m1.1")
		relays := newWGClient(t, home.publicKey, nil, "", "")
		refusedHandshake(t, "the relay's client at a paired exit", home, relays, relays.pub)
	},
}

// TestWGExitModelBindings runs every row after an honest handshake, and
// fails when the model's BIND ids and the rows differ.
func TestWGExitModelBindings(t *testing.T) {
	src, err := os.ReadFile(wgBindModel)
	if err != nil {
		t.Fatal(err)
	}
	var model, nfltr []string
	for _, m := range regexp.MustCompile(`BIND:([a-z0-9.]+)`).FindAllSubmatch(src, -1) {
		if id := string(m[1]); strings.HasPrefix(id, "nfltr.") {
			nfltr = append(nfltr, id)
		} else {
			model = append(model, id)
		}
	}
	var rows []string
	for id := range wgBindings {
		rows = append(rows, id)
	}
	slices.Sort(model)
	slices.Sort(rows)
	slices.Sort(nfltr)
	if !slices.Equal(model, rows) || !slices.Equal(nfltr, wgNfltrRows) {
		t.Fatalf("%s BIND ids %v and %v, rows %v and nfltr's %v: each binding of the model needs one row", wgBindModel, model, nfltr, rows, wgNfltrRows)
	}
	t.Run("honest", func(t *testing.T) {
		home := pairedExit(t, wgBindKey, "home1", "m1.1")
		c := newWGClient(t, home.publicKey, wgBindKey, "home1", "m1.1")
		if !handshake(t, home, c, c.pub) {
			t.Fatal("an honest paired handshake did not complete")
		}
	})
	for _, id := range rows {
		t.Run(id, wgBindings[id])
	}
}
