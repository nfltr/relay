// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The binding spec/proverif/nf1_anon.pv adds (BIND:anon.*), on
// direct_nf1_anon_test.go's rig.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/nfltr/relay/client/nf1"
)

// rogueUDP is a UDP socket a relay names as a candidate: quiet reports
// whether no datagram reached it within d.
func rogueUDP(t *testing.T) (string, func(d time.Duration) bool) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String(), func(d time.Duration) bool {
		_ = pc.SetReadDeadline(time.Now().Add(d))
		_, _, err := pc.ReadFrom(make([]byte, 2048))
		return err != nil
	}
}

// nf1AnonBindings: each BIND:anon.* of nf1_anon.pv, a row that changes
// what a relay can change of an honest session and requires a refusal.
var nf1AnonBindings = map[string]func(t *testing.T){
	// Candidates travel only inside the admitted session's TLS (the
	// control exchange, after the proof and the verdict), both ways. The
	// relay sends them outside it instead: to the client in the control
	// exchange's open, after the agent's answer, before TLS; to the agent
	// after the control mark, before TLS. Neither end punches toward them.
	"anon.cands": func(t *testing.T) {
		r, _ := newNF1AnonRig(t)
		rogue, quiet := rogueUDP(t)
		ds, tc := r.handshake(t)
		open := func(context.Context) (net.Conn, error) {
			c, s := net.Pipe()
			go func() {
				defer s.Close() //nolint:errcheck
				if r.lis.WriteAnswer(s) != nil {
					return
				}
				var mark [1]byte
				if _, err := io.ReadFull(s, mark[:]); err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, s) }()
				_, _ = fmt.Fprintf(s, "{\"candidates\":[%q]}\n", rogue)
			}()
			return c, nil
		}
		if err := ds.RunNF1(tc.ConnectionState(), NF1Route{Addr: r.lis.Address(), Open: open, Anonymous: true}, DirectOn, nil); err != nil {
			t.Fatal(err)
		}
		if err := ds.WaitDirect(t.Context()); !errors.Is(err, nf1.ErrDirectRequired) {
			t.Fatalf("client: WaitDirect = %v, want ErrDirectRequired", err)
		}
		if !quiet(time.Second) {
			t.Fatal("client: punched toward candidates sent outside the admitted TLS")
		}
		raw, err := r.open(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close() //nolint:errcheck
		if _, err := nf1.ReadAnswer(raw, r.lis.Address()); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(raw, "%c{\"candidates\":[%q]}\n", nf1MarkControl, rogue); err != nil {
			t.Fatal(err)
		}
		if !quiet(2 * time.Second) {
			t.Fatal("agent: probed candidates sent outside the admitted TLS")
		}
	},
}

// TestNF1AnonModelBindings runs every row, and fails when the model's
// BIND:anon ids and the rows differ.
func TestNF1AnonModelBindings(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/nf1_anon.pv")
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(nf1AnonBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(anon\.[a-z0-9.]+)`), rows); err != nil {
		t.Fatalf("nf1_anon.pv: %v", err)
	}
	for _, id := range rows {
		t.Run(id, nf1AnonBindings[id])
	}
}
