// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"errors"
	"fmt"
	"time"
)

// Moving the issuer to another machine (spec/orgmove/OrgMove.tla,
// spec/orgmove/README.md): the old machine commits a fence (ActMoved)
// naming the new machine's single-use receive key, after which its issuer
// commits nothing (AtMostOneIssuer, OldCannotIssue); the new machine,
// having opened the bundle sealed to that key, commits the arrival
// (ActArrived) naming the same key and serves on.

// ErrMoved: the issuer's log ends in a fence; another machine holds the
// organisation now.
var ErrMoved = errors.New("the organisation's issuer moved to another machine")

// Moved is the receive key fingerprint the log's fence names, "" while
// this issuer serves.
func (i *Issuer) Moved() string { i.mu.Lock(); defer i.mu.Unlock(); return i.movedTo }

// Fence commits the move to the receive key of fingerprint to: from now
// this issuer refuses every act (commit).
func (i *Issuer) Fence(to string, now time.Time) error {
	if to == "" {
		return errors.New("a fence names a receive key")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.commit(Entry{Time: now, Act: ActMoved, Key: to})
}

// Arrive commits the arrival of the move the log's fence names, on the
// machine that holds that receive key (fingerprint key): the issuer serves
// again here. It is the import's check (OrgMove.tla import-unfenced): the
// log must end in a fence (a backup, a disk image or a copy made before
// the fence does not) naming this very key (commit).
func (i *Issuer) Arrive(key string, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.movedTo == "" {
		return errors.New("the log ends in no fence: a copy, not a move")
	}
	if key != i.movedTo {
		return fmt.Errorf("%w: the log's fence names receive key %s, not this machine's %s", ErrMoved, i.movedTo, key)
	}
	return i.commit(Entry{Time: now, Act: ActArrived, Key: key})
}

// refuseMoved is commit's refusal after a fence (OrgMove.tla
// serve-after-fence): only the arrival follows it (Arrive checks its key).
func (i *Issuer) refuseMoved(e Entry) error {
	if i.movedTo == "" || e.Act == ActArrived {
		return nil
	}
	return fmt.Errorf("%w (fence to %s): %s refused", ErrMoved, i.movedTo, e.Act)
}

// TraceSend records the old machine sealing its fenced log of head to the
// receive key of fingerprint to (spec/orgmove/TraceOrgMove.tla send).
func TraceSend(orgID, to, head string) {
	moveTrace(map[string]any{"ev": "send", "o": orgID, "k": to, "h": head})
}

// TraceImport records an import whose log is written (orgissuer.Import):
// the arrival's commit is not traced, for an import refused after it (its
// placement) never lands, and its trace read as a second issuer.
func TraceImport(orgID, key, prev, head string) {
	moveTrace(map[string]any{"ev": "import", "o": orgID, "act": ActArrived, "k": key, "num": 0, "p": prev, "h": head})
}
