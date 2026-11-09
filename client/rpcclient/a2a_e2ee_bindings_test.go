// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// The bindings spec/proverif/a2a_machine.pv relies on, against the real
// code: each BIND:<id> the model lists has one row here that changes just
// that field of an honest message, as a relay can, and requires the code to
// refuse. The vectors (TestA2AE2EEv2Vectors) pin the bytes; a re-pinned
// vector cannot hide a binding dropped here. `make spec-bindings`.

import (
	"bytes"
	"crypto/rand"
	"os"
	"regexp"
	"slices"
	"testing"
)

const bindModel = "../../spec/proverif/a2a_machine.pv"

// bindHS is an honest call from a root holder to machine m1's agent
// m1-node: the caller's state after message 1, and message 1.
func bindHS(t *testing.T) (*a2aE2EEState, []byte, testMachine) {
	t.Helper()
	kr := testMachine{id: "m1.1", key: bytes.Repeat([]byte{0x4b}, 32)}
	c := newA2AE2EEState("txn-1", "hub-1", "m1-node", testRootOf{kr})
	init, err := c.initMessage()
	if err != nil {
		t.Fatal(err)
	}
	return c, init, kr
}

// bindCall is an honest handshake done: both ends' states.
func bindCall(t *testing.T) (c, s *a2aE2EEState, kr testMachine) {
	t.Helper()
	c, init, kr := bindHS(t)
	s, ack, err := newServerA2AE2EEState("txn-1", "m1-node", init, kr, true, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.complete(ack); err != nil {
		t.Fatal(err)
	}
	return c, s, kr
}

// rewriteInit replaces the init's clear field i (0 caller, 1 callee, 2 key id).
func rewriteInit(init []byte, i int, v string) []byte {
	p := bytes.SplitN(init, []byte{0}, 4)
	p[i] = []byte(v)
	return bytes.Join(p, []byte{0})
}

func refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted", what)
	}
}

var a2aBindings = map[string]func(t *testing.T){
	// prologue t: message 1 delivered on another call
	"init.txn": func(t *testing.T) {
		_, init, kr := bindHS(t)
		_, _, err := newServerA2AE2EEState("txn-2", "m1-node", init, kr, true, rand.Reader)
		refused(t, "message 1 on another txn", err)
	},
	// prologue prole(r): a machine's call returned to it as the root's (F6)
	"init.role": func(t *testing.T) {
		kr := testMachine{id: "m1.1", key: bytes.Repeat([]byte{0x4b}, 32)}
		c := newA2AE2EEState("txn-1", "m1-node", "hub-1", kr)
		init, err := c.initMessage()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = newServerA2AE2EEState("txn-1", "hub-1", init, kr, true, rand.Reader)
		refused(t, "a machine's init answered by a machine", err)
	},
	// prologue caller: the relay names another caller
	"init.caller": func(t *testing.T) {
		_, init, kr := bindHS(t)
		_, _, err := newServerA2AE2EEState("txn-1", "m1-node", rewriteInit(init, 0, "hub-2"), kr, true, rand.Reader)
		refused(t, "another caller", err)
	},
	// prologue callee: the call routed to another agent of the machine, told it is the callee
	"init.callee": func(t *testing.T) {
		_, init, kr := bindHS(t)
		_, _, err := newServerA2AE2EEState("txn-1", "m1-other", rewriteInit(init, 1, "m1-other"), kr, true, rand.Reader)
		refused(t, "another callee", err)
	},
	// prologue k: another key id
	"init.kid": func(t *testing.T) {
		_, init, kr := bindHS(t)
		_, _, err := newServerA2AE2EEState("txn-1", "m1-node", rewriteInit(init, 2, "m1.2"), kr, true, rand.Reader)
		refused(t, "another key id", err)
	},
	// psk(K): a callee holding another key
	"init.psk": func(t *testing.T) {
		_, init, _ := bindHS(t)
		other := testMachine{id: "m1.1", key: bytes.Repeat([]byte{0x4c}, 32)}
		_, _, err := newServerA2AE2EEState("txn-1", "m1-node", init, other, true, rand.Reader)
		refused(t, "another key", err)
	},
	// message 1's payload WARM: a warm retagged as a call, or back
	"init.warm": TestA2AE2EEWarmRetagRefused,
	// ack: aenc(c2, N0, (h1, ct1, r), ...): an ack of another handshake
	"ack.transcript": func(t *testing.T) {
		c, _, kr := bindHS(t)
		_, other, _ := bindHS(t)
		_, ack, err := newServerA2AE2EEState("txn-1", "m1-node", other, kr, true, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		refused(t, "the ack of another handshake", c.complete(ack))
	},
	// back(c) = split2: a frame returned to its sender (F1)
	"frame.dir": func(t *testing.T) {
		c, _, _ := bindCall(t)
		f, _ := c.seal(a2aFrameData, []byte("req"))
		_, err := c.openData(f)
		refused(t, "the caller's own frame", err)
	},
	// N0, N1: a frame replayed or reordered (F2)
	"frame.order": func(t *testing.T) {
		c, s, _ := bindCall(t)
		_, _ = c.seal(a2aFrameData, []byte("0"))
		f1, _ := c.seal(a2aFrameData, []byte("1"))
		_, err := s.openData(f1)
		refused(t, "frame 1 before frame 0", err)
		c, s, _ = bindCall(t)
		f0, _ := c.seal(a2aFrameData, []byte("0"))
		if _, err := s.openData(f0); err != nil {
			t.Fatal(err)
		}
		_, err = s.openData(f0)
		refused(t, "frame 0 twice", err)
	},
	// (END, Lempty) sealed: an end the relay forges (F2)
	"frame.end": TestA2AE2EERefusesForgedEnd,
	// (HDR, hdrFrom(m), ...) sealed: response headers the relay adds
	"frame.header": TestA2AE2EEResponseHeadersAreTheCallees,
	// callk(S, (t, c), dir), rad(t): a resumed call's frame in another call
	"call.txn": func(t *testing.T) {
		c, s, kr := bindCall(t)
		g, _ := newResumedA2AE2EEState("txn-2", c.established, 1, kr).seal(a2aFrameData, []byte("req"))
		_, err := newResumedServerA2AE2EEState("txn-3", s.established, 1, kr).openData(g)
		refused(t, "a frame of txn-2 in txn-3", err)
	},
	// callk(S, (t, c), dir): the same txn, another call number
	"call.ctr": func(t *testing.T) {
		c, s, kr := bindCall(t)
		g, _ := newResumedA2AE2EEState("txn-2", c.established, 1, kr).seal(a2aFrameData, []byte("req"))
		_, err := newResumedServerA2AE2EEState("txn-2", s.established, 2, kr).openData(g)
		refused(t, "a frame of call 1 in call 2", err)
	},
	// rtag(S, t, c): a resume delivered on another txn
	"resume.txn": func(t *testing.T) {
		c, s, kr := bindCall(t)
		ss := recordedSessions(t)
		ss.putIn(s.established)
		_, _, err := ss.resume("txn-3", c.established.resumeMessage("txn-2", 1), kr)
		refused(t, "a resume of txn-2 on txn-3", err)
	},
	// rtag(S, t, c): a resume's call number rewritten
	"resume.ctr": func(t *testing.T) {
		c, s, kr := bindCall(t)
		ss := recordedSessions(t)
		ss.putIn(s.established)
		m := c.established.resumeMessage("txn-2", 1)
		m[a2aSessionIDLen+7] = 2
		_, _, err := ss.resume("txn-2", m, kr)
		refused(t, "a resume with another call number", err)
	},
	// msess(m, ...): a session is its pair's (query 14)
	"resume.pair": TestA2AE2EESessionBoundToPair,
}

// TestA2AE2EEModelBindings runs every row, and fails when the model's
// BIND ids and the rows differ.
func TestA2AE2EEModelBindings(t *testing.T) {
	src, err := os.ReadFile(bindModel)
	if err != nil {
		t.Fatal(err)
	}
	var model []string
	for _, m := range regexp.MustCompile(`BIND:([a-z0-9.]+)`).FindAllSubmatch(src, -1) {
		model = append(model, string(m[1]))
	}
	var rows []string
	for id := range a2aBindings {
		rows = append(rows, id)
	}
	slices.Sort(model)
	slices.Sort(rows)
	if !slices.Equal(model, rows) {
		t.Fatalf("%s BIND ids %v, rows %v: each binding of the model needs one row", bindModel, model, rows)
	}
	for _, id := range rows {
		t.Run(id, a2aBindings[id])
	}
}
