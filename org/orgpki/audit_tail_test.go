// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Every checkpoint carries the root's signature: one without (stripped
// from the line) is refused, not read as an issuer-only checkpoint (lane
// SECFIX2, review S19; mutant checkpoint-root-optional).
func TestVerifyLogRefusesACheckpointWithoutTheRoot(t *testing.T) {
	o := newOrg(t)
	if err := o.iss.RenewIssuer(o.root, o.groups, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyLog(o.lines); err != nil {
		t.Fatal(err)
	}
	last := len(o.lines) - 1
	var e map[string]any
	if err := json.Unmarshal(o.lines[last], &e); err != nil || e["act"] != ActCheckpoint {
		t.Fatalf("the last line is %v (%v), want the renewal's checkpoint", e["act"], err)
	}
	delete(e, "root_sig")
	stripped, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	lines := append(append([][]byte(nil), o.lines[:last]...), stripped)
	if _, _, err := VerifyLog(lines); err == nil || !strings.Contains(err.Error(), "not the root's signature") {
		t.Fatalf("a checkpoint without the root's signature: %v", err)
	}
}

// A log that lost lines at its tail is seen against the status the issuer
// published (the relay's copy, signed under the root): CheckPublishedHead
// is ErrTruncated for the shorter log, nil for the whole one and for a
// status that does not verify (lane SECFIX2, review S19; mutant
// truncation-unseen).
func TestCheckPublishedHeadSeesALostTail(t *testing.T) {
	o := newOrg(t)
	o.enrol(t, "web-1", "web")
	if err := o.iss.Revoke("web-1", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	st, err := o.iss.SignedStatus(t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.iss.CheckPublishedHead(msg); err != nil {
		t.Fatalf("the whole log: %v", err)
	}
	short, err := Open(append([][]byte(nil), o.lines[:len(o.lines)-1]...), o.iss.key, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := short.CheckPublishedHead(msg); !errors.Is(err, ErrTruncated) {
		t.Fatalf("a log without its last line (the revoke): %v, want ErrTruncated", err)
	}
	other := newOrg(t)
	ost, err := other.iss.SignedStatus(t0)
	if err != nil {
		t.Fatal(err)
	}
	omsg, _ := json.Marshal(ost)
	if err := short.CheckPublishedHead(omsg); err != nil {
		t.Fatalf("another organisation's status: %v", err)
	}
}
