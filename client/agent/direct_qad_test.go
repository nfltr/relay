// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"
)

// QAD against more than one relay (nfltr docs/decisions/direct-paths-2026-11-11.md):
// one rendezvous relay per pair, the agent's, named in the offer; a client
// that cannot ask it asks its own; differing answers are counted, never
// acted on.

// TestDirectClientFallsBackToItsOwnRelaysQAD: the client cannot ask the
// relay the agent's offer names (its UDP port unreachable from the
// client's network); it asks its own relay instead, offers that answer and
// the session goes direct. DirectPublic: no host candidate to hide behind.
func TestDirectClientFallsBackToItsOwnRelaysQAD(t *testing.T) {
	r := newDirectRig(t, DirectPublic)
	r.d.cfg.OwnQAD = qadServer(t)
	r.d.cfg.QADTLS = func(addr string) *tls.Config {
		cfg := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- a test's relay
		if addr == r.relay {
			cfg.VerifyConnection = func(tls.ConnectionState) error { return errors.New("the agent's relay is out of reach") }
		}
		return cfg
	}
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() { waitPath(t, events, PathDirect) })
	if st := r.d.Stats(); st.QAD[QADOwnRelay] != 1 || st.QAD[QADAgentRelay] != 0 || st.QAD[QADDiffer] != 0 {
		t.Fatalf("qad %v, want one own_relay answer", st.QAD)
	}
}

// TestDirectClientPrefersTheAgentsRelay: both relays answer, the same
// mapping (an endpoint-independent NAT): the agent's relay's answer is
// the candidate, nothing differs.
func TestDirectClientPrefersTheAgentsRelay(t *testing.T) {
	r := newDirectRig(t, DirectPublic)
	r.d.cfg.OwnQAD = qadServer(t)
	r.d.qadGrace = 10 * time.Second // both answers in: none differs
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() { waitPath(t, events, PathDirect) })
	if st := r.d.Stats(); st.QAD[QADAgentRelay] != 1 || st.QAD[QADOwnRelay] != 0 || st.QAD[QADDiffer] != 0 {
		t.Fatalf("qad %v, want one agent_relay answer", st.QAD)
	}
}

// TestDirectDifferingQADAnswersAreReportedNotPolicy: the client's own
// relay answers another mapping than the agent's relay (an endpoint-
// dependent NAT): counted as differ, the agent's relay's answer still
// offered and the punch still made (a symmetric client toward a public
// agent goes direct).
func TestDirectDifferingQADAnswersAreReportedNotPolicy(t *testing.T) {
	r := newDirectRig(t, DirectPublic)
	r.d.cfg.OwnQAD = lyingQAD(t, "127.0.0.1:9")
	r.d.qadGrace = 10 * time.Second // its answer observed on a loaded machine too
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() { waitPath(t, events, PathDirect) })
	if st := r.d.Stats(); st.QAD[QADDiffer] != 1 || st.QAD[QADAgentRelay] != 1 || st.Punches["ok"] != 1 {
		t.Fatalf("qad %v punches %v, want differ and agent_relay counted, the punch ok", st.QAD, st.Punches)
	}
}

// TestDirectAgentOnTwoRelaysOffersTheArrivingOnes: an agent whose direct
// paths serve tunnels to two relays (a table carried over by Continue, a
// failover standby) offers, on each control exchange, the QAD of the relay
// that carried it and that relay's answer only.
func TestDirectAgentOnTwoRelaysOffersTheArrivingOnes(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	relayA, relayB := r.relay, lyingQAD(t, "127.0.0.1:9") // B's answer tells its candidate apart
	onA := r.l
	onB := &linkSessions{ctx: t.Context(), targets: sessionTargets{services: onA.targets.services, agent: "web", qad: tunnelQAD(relayB)},
		logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	for _, c := range []struct {
		l        *linkSessions
		relay    string
		wantsLie bool
	}{{onA, relayA, false}, {onB, relayB, true}, {onA, relayA, false}} {
		o := r.controlOffer(t, c.l)
		if o.QAD != c.relay {
			t.Fatalf("offer names relay %q, want %q (the one the exchange arrived on)", o.QAD, c.relay)
		}
		if got := slices.Contains(o.Candidates, "127.0.0.1:9"); got != c.wantsLie {
			t.Fatalf("offer through %s: candidates %v, relay B's answer in them %v, want %v", c.relay, o.Candidates, got, c.wantsLie)
		}
	}
}

// controlOffer runs a control exchange's first half through l: the
// agent's offer for blob.
func (r *directRig) controlOffer(t *testing.T, l *linkSessions) directOffer {
	t.Helper()
	r.mu.Lock()
	prev := r.l
	r.l = l
	r.mu.Unlock()
	raw, err := r.open(t, DirectServiceName)
	r.mu.Lock()
	r.l = prev
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, r.d.controlTLS("web", "web"))
	defer tc.Close() //nolint:errcheck
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var o directOffer
	if err := json.NewEncoder(tc).Encode(directRequest{Service: "blob"}); err != nil {
		t.Fatal(err)
	}
	if err := readJSONLine(bufio.NewReader(io.LimitReader(tc, 8<<10)), &o); err != nil {
		t.Fatal(err)
	}
	return o
}
