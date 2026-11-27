// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MarksFile holds the newest CRL number, rules number and status time a
// machine took, and the newest ThisUpdate it saw, under the root it pins
// (lane SECFIX, review S10, S18). A fresh process takes them as floors
// (LoadMarks): the relay's older list or status is refused also after a
// restart, when the verifier holds none (crl.der lapsed, a client
// keeps no status.json), and a clock set back before the newest list
// taken admits no one. A rotation starts them again (another root). They
// guard against the relay, not against a process of the machine's user,
// which can rewrite every file of the directory.
const MarksFile = "marks.json"

// clockSkew is how far the machine's clock may run behind the issuer's
// (the ThisUpdate of the newest list taken) before checks fail closed.
const clockSkew = 5 * time.Minute

type marks struct {
	Root   string    `json:"root"`   // the root's fingerprint they are under
	CRL    int64     `json:"crl"`    // the newest CRL's number
	Seen   time.Time `json:"seen"`   // the newest CRL's ThisUpdate: the clock's floor
	Rules  int64     `json:"rules"`  // the newest status's rules number
	Status time.Time `json:"status"` // the newest status's At
}

// LoadMarks takes dir's MarksFile as v's and r's floors; none is no
// floor. One that does not parse fails it.
func LoadMarks(dir string, v *Verifier, r *Rules) error {
	b, err := os.ReadFile(filepath.Join(dir, MarksFile)) // #nosec G304 -- a file of the machine's own directory
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var m marks
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", MarksFile, err)
	}
	if m.Root != Fingerprint(v.Root()) {
		return nil // another root's: a rotation since
	}
	v.mu.Lock()
	v.floorCRL, v.seen = max(v.floorCRL, m.CRL), maxTime(v.seen, m.Seen)
	v.mu.Unlock()
	r.mu.Lock()
	r.floorRoot, r.floorNum, r.floorAt = m.Root, max(r.floorNum, m.Rules), maxTime(r.floorAt, m.Status)
	r.mu.Unlock()
	return nil
}

// KeepMarks writes v's and r's newest into dir's MarksFile.
func KeepMarks(dir string, v *Verifier, r *Rules) error {
	m := marks{Root: Fingerprint(v.Root())}
	v.mu.Lock()
	m.CRL, m.Seen = v.floorCRL, v.seen
	for _, s := range v.crls {
		m.CRL = max(m.CRL, s.number.Int64())
	}
	v.mu.Unlock()
	r.mu.Lock()
	if r.floorRoot == m.Root {
		m.Rules, m.Status = r.floorNum, r.floorAt
	}
	if h := r.held; h != nil && Fingerprint(h.root) == m.Root {
		m.Rules, m.Status = max(m.Rules, h.policy.Number), maxTime(m.Status, h.at)
	}
	r.mu.Unlock()
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, MarksFile), b)
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
