// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

// web2 is another relay machine of the issuer's account.
const web2 = "m-bbbbbbbbbbbbbbbbbbbbbbbbbb"

// spec/enrol/Join.tla JoinedBound (lane LOGINREDS): a login bundle's token
// names no relay machine id; the join states its own (Pins.MachineID) and
// the issuer binds it, so the machine's keeper moves nothing at its first
// serve (before: the move replaced the pair while a second nfltr cat serve
// read it, nfltr TestLoginJoinsTheOrganisation).
func TestJoinBindsItsRelayMachineID(t *testing.T) {
	acct := &account{id: map[string]string{"web-1": web1, "box": web2}}
	f := newFleetWith(t, func(f *fleet) {
		f.relay.from = web1
		f.machineOf = acct.of
		f.noA2A = true
	})
	f.relay.mu.Lock()
	f.relay.from = web2
	f.relay.mu.Unlock()
	dir := filepath.Join(t.TempDir(), "box")
	pins := f.org.pins
	pins.MachineID = web2
	j, err := Join(f.ctx, f.relay, dir, pins, loginToken(t, f.org, "box", f.clk.Now()), hang, f.clk.Now)
	check(t, err)
	if got := orgid.MachineID(j.Cert); got != web2 {
		t.Fatalf("joined with relay machine id %q, want %s", got, web2)
	}
	m, err := orgmachine.Open(dir)
	check(t, err)
	before := serial(m)
	k := Keeper{Mailbox: f.mailbox(), Machine: m, Logger: quiet(), Now: f.clk.Now, AnswerWait: hang, RetryWait: 10 * time.Millisecond, FollowEvery: 100 * time.Millisecond,
		RelayMachineID: func() string { return web2 }}
	keep(t, f.ctx, k)
	time.Sleep(300 * time.Millisecond) // a move is the keeper's first step: none comes
	if got := serial(m); got != before {
		t.Fatalf("the keeper replaced the certificate (%s -> %s): it moved the name", before, got)
	}
}

// Join.tla Relabel: the relay names another machine than the id the join
// states as its sender; the issuer refuses it, naming both.
func TestJoinStatingAnotherSendersIDIsRefused(t *testing.T) {
	acct := &account{id: map[string]string{"web-1": web1, "box": web1}}
	f := newFleetWith(t, func(f *fleet) {
		f.relay.from = web1
		f.machineOf = acct.of
		f.noA2A = true
	})
	pins := f.org.pins
	pins.MachineID = web2
	_, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "box"), pins, loginToken(t, f.org, "box", f.clk.Now()), hang, f.clk.Now)
	if err == nil || !strings.Contains(err.Error(), web2) || !strings.Contains(err.Error(), web1) {
		t.Fatalf("box stating %s, posted by %s: %v", web2, web1, err)
	}
}

// loginToken is a login bundle's token (orgcli MintLoginBundle): no
// machine id.
func loginToken(t *testing.T, o *org, name string, now time.Time) string {
	var tok string
	o.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		var err error
		tok, err = iss.MakeToken(name, []string{"web"}, "", time.Hour, now)
		check(t, err)
	})
	return tok
}
