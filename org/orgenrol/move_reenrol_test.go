// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// web1 is web-1's first relay machine id (the token's is m-web-1: the
// keeper moves whenever the relay's id is not its certificate's).
const web1 = "m-aaaaaaaaaaaaaaaaaaaaaaaaaa"

// account is a relay account's machines by name, changed by a test (a
// re-enrolment gives a name a new id).
type account struct {
	mu sync.Mutex
	id map[string]string
}

func (a *account) of(_ context.Context, name string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.id[name], nil
}

func (a *account) set(name, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.id[name] = id
}

// Enrol.tla Move (lane SEAMLESS): web-1 enrolled with the relay again (a
// new relay machine id, same name, the issuer's account) while it was off
// for 20 days, its organisation certificate expired: the keeper moves its
// name to the new id with no command, and renews under it.
func TestKeeperMovesTheNameAfterAReEnrolment(t *testing.T) {
	const newID = "m-nnnnnnnnnnnnnnnnnnnnnnnnnn"
	acct := &account{id: map[string]string{"web-1": web1}}
	f := newFleetWith(t, func(f *fleet) {
		f.relay.from = web1
		f.machineOf = acct.of
		f.noA2A = true
	})
	acct.set("web-1", newID)
	f.relay.mu.Lock()
	f.relay.from = newID
	f.relay.mu.Unlock()
	f.clk.Add(20 * 24 * time.Hour) // inside RenewGrace, the issuer's certificate (30 days) still valid
	k := f.keeper()
	k.RelayMachineID = func() string { return newID }
	keep(t, f.ctx, k)
	eventually(t, "the name moved to the new relay machine id", func() bool {
		cur, _ := f.m.Current()
		return orgid.MachineID(cur) == newID && f.clk.Now().Before(cur.NotAfter)
	})
}

// MoveOnlyOwnAccount (mutant move-any-account): an id that is not the
// issuer's account machine of that name moves nothing; the keeper keeps
// renewing under the old id.
func TestKeeperMoveRefusedKeepsTheOldID(t *testing.T) {
	const otherID = "m-oooooooooooooooooooooooooo"
	acct := &account{id: map[string]string{"web-1": web1}}
	f := newFleetWith(t, func(f *fleet) {
		f.relay.from = web1
		f.machineOf = acct.of
		f.noA2A = true
	})
	f.relay.mu.Lock()
	f.relay.from = otherID // another account's machine: the account still names web1
	f.relay.mu.Unlock()
	before := serial(f.m)
	f.clk.Add(17 * time.Hour) // due (half the lifetime, up to 10 % later)
	k := f.keeper()
	k.RelayMachineID = func() string { return otherID }
	keep(t, f.ctx, k)
	eventually(t, "renewed under the old id", func() bool {
		cur, _ := f.m.Current()
		return serial(f.m) != before && orgid.MachineID(cur) == "m-web-1" // the token's id
	})
}

// An issuer with an A2A root (MachineKey) moves no name: its machine keys
// are re-keyed only on an enrolment (the rebind token's).
func TestNoMoveWithAnA2ARoot(t *testing.T) {
	s := &service{MachineOf: func(context.Context, string) (string, error) { return web1, nil },
		MachineKey: func(string, string, time.Time) (string, []byte, error) { return "", nil, nil }}
	if s.movePolicy(t.Context()) != nil {
		t.Fatal("a move policy with an A2A root")
	}
}
