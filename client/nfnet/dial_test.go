// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// TestDialerOneDataConnection: every session, one at a time or many at
// once, TLS or plaintext relay, is a session of one data connection; one
// that ended is dialled again for the next open.
func TestDialerOneDataConnection(t *testing.T) {
	for _, useTLS := range []bool{true, false} {
		r := newDataRelay(t, useTLS)
		d := dialer(t, r.config(useTLS))
		var held []*Conn
		for range 8 {
			c, err := dial(t, d, web("echo"), DialOptions{})
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, c)
		}
		for _, c := range held {
			echoAndHalfClose(t, c, "x")
			_ = c.Close()
		}
		if n := r.conns.Load(); n != 1 {
			t.Fatalf("tls=%v: relay saw %d connections, want 1 data connection", useTLS, n)
		}
		_ = (<-r.muxes).Close() // the relay ends it
		p, _ := d.dataPool()
		for deadline := time.Now().Add(5 * time.Second); p.Stats().Conns != 0; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the ended data connection is still in use")
			}
		}
		c, err := dial(t, d, web("echo"), DialOptions{})
		if err != nil {
			t.Fatal(err)
		}
		echoAndHalfClose(t, c, "again")
		_ = c.Close()
		if n := r.conns.Load(); n != 2 {
			t.Fatalf("tls=%v: relay saw %d connections, want 2", useTLS, n)
		}
	}
}

// TestDialerPastOneConnectionsSessions (CONNCAP): a data connection
// carries at most the relay's 1,024 sessions (link.MaxSessions); the
// 1,025th open goes on a second connection, not refused, and no third is
// dialled for it.
func TestDialerPastOneConnectionsSessions(t *testing.T) {
	r := newDataRelay(t, false)
	d := dialer(t, r.config(false))
	var held []*Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := range link.MaxSessions + 1 {
		c, err := dial(t, d, web("echo"), DialOptions{})
		if err != nil {
			t.Fatalf("open %d: %v, want a session (another data connection may open)", i+1, err)
		}
		held = append(held, c)
	}
	echoAndHalfClose(t, held[link.MaxSessions], "past the first connection")
	if n := r.conns.Load(); n != 2 {
		t.Fatalf("relay saw %d connections for %d sessions, want 2", n, link.MaxSessions+1)
	}
}

// TestRelayTunnelsRemoteHalfClose: the remote's half close ends our reads
// only; what we send after it still arrives.
func TestRelayTunnelsRemoteHalfClose(t *testing.T) {
	r := newDataRelay(t, true)
	c, err := dial(t, dialer(t, r.config(true)), web("speak"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	if got, err := io.ReadAll(c); string(got) != "hello" || err != nil {
		t.Fatalf("read %q, %v; want the greeting then EOF", got, err)
	}
	if _, err := c.Write(make([]byte, 1000)); err != nil {
		t.Fatalf("write after the remote's half close: %v", err)
	}
	_ = c.CloseWrite()
	select {
	case n := <-r.late:
		if n != 1000 {
			t.Fatalf("the remote read %d bytes after its half close, want 1000", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the remote never read our bytes after its half close")
	}
}

// TestRelayTunnelsTypedOpens: a refusal is an *Error with the code of its
// reason, and says which hop refused and the session's trace; link's own
// codes (a draining relay) are unreachable, Unopened; a key the relay
// refuses is auth; every refusal sets Reason or Unopened as it applies.
func TestRelayTunnelsTypedOpens(t *testing.T) {
	r := newDataRelay(t, true)
	d := dialer(t, r.config(true))
	_, err := dial(t, d, web("refused"), DialOptions{})
	if e := wantCode(t, "refused target", err, CodeRefused, "ERROR_REASON_TARGET_REFUSED"); !strings.Contains(e.Message, "hop 1, trace ") || e.Unopened {
		t.Fatalf("refused target: %+v", e)
	}
	_, err = dial(t, d, web("draining"), DialOptions{})
	if e := wantCode(t, "a draining relay", err, CodeUnreachable, ""); e.Reason != "" || !e.Unopened {
		t.Fatalf("a draining relay: %+v, want Unopened and no reason", e)
	}
	bad := r.config(true)
	bad.APIKey = "bad"
	_, err = dial(t, dialer(t, bad), web("echo"), DialOptions{})
	wantCode(t, "refused key", err, CodeAuth, "")
	if p, err := d.E2EEPolicy(context.Background()); err != nil || p != "allow" {
		t.Fatalf("policy %q, %v", p, err)
	}
}

// TestRelayTunnelsDrain: a relay that drains the data connection (it
// leaves: GOAWAY) gets the next open on a new connection, not a failure;
// the open session runs on on the old one until the drain's deadline,
// where its Read is a reset with ReasonDrainDeadline.
func TestRelayTunnelsDrain(t *testing.T) {
	r := newDataRelay(t, true)
	d := dialer(t, r.config(true))
	held, err := dial(t, d, web("echo"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck
	old := <-r.muxes
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- old.Drain(ctx) }()
	for start := time.Now(); r.conns.Load() == 1; time.Sleep(5 * time.Millisecond) {
		c, err := dial(t, d, web("echo"), DialOptions{})
		if err != nil {
			t.Fatalf("an open while the relay drains the data connection: %v, want it on a new connection", err)
		}
		_ = c.Close()
		if time.Since(start) > 5*time.Second {
			t.Fatal("no open moved to a new data connection")
		}
	}
	if _, err := held.Write([]byte("still open")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(held, make([]byte, len("still open"))); err != nil {
		t.Fatal(err)
	}
	if err := <-drained; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain: %v, want its deadline", err)
	}
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = held.Read(make([]byte, 1))
	wantCode(t, "the open session at the drain's deadline", err, CodeReset, ReasonDrainDeadline)
}

// Every answer reason has its code (the sidecar's exit status).
func TestAnswerErrorCodes(t *testing.T) {
	for reason, want := range map[relayv1.ErrorReason]Code{
		relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED:       CodeAuth,
		relayv1.ErrorReason_ERROR_REASON_AGENT_NOT_FOUND:       CodeNotFound,
		relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE:         CodeNotFound,
		relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE:       CodeNotFound,
		relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED:        CodeRefused,
		relayv1.ErrorReason_ERROR_REASON_FEATURE_UNSUPPORTED:   CodeRefused,
		relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED:         CodeRefused,
		relayv1.ErrorReason_ERROR_REASON_TARGET_UNREACHABLE:    CodeUnreachable,
		relayv1.ErrorReason_ERROR_REASON_RELAY_DRAINING:        CodeUnreachable,
		relayv1.ErrorReason_ERROR_REASON_DIRECTORY_UNAVAILABLE: CodeUnreachable,
		relayv1.ErrorReason_ERROR_REASON_INVALID_ARGUMENT:      CodeUsage,
		relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE:      CodeE2EEPinMismatch,
		relayv1.ErrorReason_ERROR_REASON_PROTOCOL_UNSUPPORTED:  CodeRefused,
		relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED:     CodeBalanceExhausted,
	} {
		if e := answerError(dataplane.Refusal(reason, "why"), "t"); e.Code != want || e.Reason != reason.String() || e.Err == nil {
			t.Errorf("%v: %+v, want %s with its reason and cause", reason, e, want)
		}
	}
	if e := answerError(dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED, "why"), "t"); !strings.Contains(e.Message, "without Plain") {
		t.Errorf("E2EE_REQUIRED: %q, want how to reach an organisation service", e.Message)
	}
	if e := answerError(dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "why"), "t"); !strings.Contains(e.Message, "not in organisation mode") || !strings.Contains(e.Message, "Plain") {
		t.Errorf("E2EE_UNAVAILABLE: %q, want Plain named", e.Message)
	}
	// Unopened: the path to the agent failed before it answered, so the
	// session never opened.
	for code, want := range map[uint32]struct {
		code     Code
		unopened bool
	}{
		link.CodeDraining: {CodeUnreachable, true}, link.CodeConnLost: {CodeUnreachable, true}, link.CodeNoRoute: {CodeUnreachable, true},
		link.CodeTimeout: {CodeUnreachable, false}, link.CodeHopLimit: {CodeRefused, false}, link.CodeRefused: {CodeRefused, false},
	} {
		if e := answerError(&link.Abort{Refused: true, Code: code}, "t"); e.Code != want.code || e.Unopened != want.unopened || e.Reason != "" {
			t.Errorf("link code %d: %+v, want %+v", code, e, want)
		}
	}
}

// TestRelayTunnelsE2EE: in organisation mode a session is TLS with the
// organisation's machine the target names (half closes pass as
// close_notify); another machine (eve for web), or a relay that answers
// but drops the encryption, fails the open as e2ee_pin_mismatch; a client
// the service refuses (not in its group) gets the typed refusal
// e2ee_client_refused on its first read, not a reset.
func TestRelayTunnelsE2EE(t *testing.T) {
	r := newDataRelay(t, true)
	cfg := r.config(true)
	cfg.Org = r.org.cli
	d := dialer(t, cfg)
	c, err := dial(t, d, web("echo"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if i := c.Info(); !i.E2EE || i.Instance != "web" || i.Path != "relayed" {
		t.Fatalf("an organisation session's info %+v", i)
	}
	echoAndHalfClose(t, c, "secret")
	_ = c.Close()
	for _, svc := range []string{"eve", "strip"} {
		_, err := dial(t, d, web(svc), DialOptions{})
		wantCode(t, svc, err, CodeE2EEPinMismatch, "")
	}
	cfg.Org = r.org.ops
	c, err = dial(t, dialer(t, cfg), web("echo"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	_, _ = c.Write([]byte("x"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	wantCode(t, "a client outside the service's groups", err, CodeE2EEClientRefused, "")
}

// Nothing the relay says changes a session's mode: an organisation open
// the relay answers "the service is plain" (E2EE_UNAVAILABLE) fails as
// e2ee_pin_mismatch naming Plain, and no plain open follows (ProVerif
// e2ee_tcp.pv mutant downgrade-plain).
func TestRelayAnswerNeverChangesTheMode(t *testing.T) {
	r := newDataRelay(t, true)
	cfg := r.config(true)
	cfg.Org = r.org.cli
	_, err := dial(t, dialer(t, cfg), web("plainsvc"), DialOptions{})
	if e := wantCode(t, "an organisation session to a plain service", err, CodeE2EEPinMismatch, ""); !strings.Contains(e.Message, "Plain") {
		t.Fatalf("%q, want Plain named", e.Message)
	}
	for {
		select {
		case o := <-r.opens:
			if !o.GetE2Ee() {
				t.Fatalf("a plain open followed the relay's answer: %v", o)
			}
			continue
		default:
		}
		break
	}
	// Plain on purpose reaches it.
	c, err := dial(t, dialer(t, cfg), web("plainsvc"), DialOptions{Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	echoAndHalfClose(t, c, "plain")
	_ = c.Close()
}

// TestDialEarlySendsBeforeTheAnswer: an Early dial's bytes go out with the
// open, not a round trip after its answer: a far end that reads the first
// byte before it answers echoes it (a dial that waited would hang), and a
// refusal after the first byte is Answered's typed refusal, the Conn
// reading nothing.
func TestDialEarlySendsBeforeTheAnswer(t *testing.T) {
	for _, useTLS := range []bool{true, false} {
		r := newDataRelay(t, useTLS)
		d := dialer(t, r.config(useTLS))
		c, err := dial(t, d, web("peek"), DialOptions{Early: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("pipelined")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len("pipelined"))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "pipelined" {
			t.Fatalf("tls %v: echo %q, %v", useTLS, got, err)
		}
		if err := c.Answered(context.Background()); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()

		c, err = dial(t, d, web("peekref"), DialOptions{Early: true})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("x"))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("tls %v: a refused session read %d bytes, %v", useTLS, n, err)
		}
		wantCode(t, "refusal after the first byte", c.Answered(context.Background()), CodeRefused, "ERROR_REASON_TARGET_REFUSED")
		_ = c.Close()
	}
}

// TestDialEarlyE2EE: an organisation session dialled Early runs its TLS
// handshake behind the open: the echo with machine web, a typed
// e2ee_pin_mismatch with another machine and the typed refusal of a
// refused open.
func TestDialEarlyE2EE(t *testing.T) {
	r := newDataRelay(t, true)
	cfg := r.config(true)
	cfg.Org = r.org.cli
	d := dialer(t, cfg)
	c, err := dial(t, d, web("echo"), DialOptions{Early: true})
	if err != nil {
		t.Fatal(err)
	}
	echoAndHalfClose(t, c, "secret")
	_ = c.Close()
	for svc, code := range map[string]Code{"eve": CodeE2EEPinMismatch, "strip": CodeE2EEPinMismatch, "refused": CodeRefused} {
		_, err := dial(t, d, web(svc), DialOptions{Early: true})
		wantCode(t, svc, err, code, "")
	}
}

// TestRelayTunnelsCutIsReset: a session the agent resets mid-stream reads
// its bytes, then a reset (CodeReset), never EOF.
func TestRelayTunnelsCutIsReset(t *testing.T) {
	r := newDataRelay(t, false)
	c, err := dial(t, dialer(t, r.config(false)), web("cut"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	got, err := io.ReadAll(c)
	if string(got) != "hello" {
		t.Fatalf("read %q", got)
	}
	wantCode(t, "a cut session", err, CodeReset, "")
}

// TestDialHoldsUntilContext: an offline agent is held until ctx ends,
// then the last refusal (CodeNotFound, AGENT_OFFLINE) wraps ctx's error;
// an agent that comes online within ctx gets the session. An Early dial is
// not held.
func TestDialHoldsUntilContext(t *testing.T) {
	r := newDataRelay(t, false)
	d := dialer(t, r.config(false))
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := d.DialTarget(ctx, web("offline"), DialOptions{})
	e := wantCode(t, "held offline", err, CodeNotFound, "ERROR_REASON_AGENT_OFFLINE")
	if !errors.Is(e, context.DeadlineExceeded) || time.Since(start) < 500*time.Millisecond {
		t.Fatalf("held %v: %v, want held until ctx and its error wrapped", time.Since(start), err)
	}
	time.AfterFunc(300*time.Millisecond, func() { r.online.Store(true) })
	c, err := dial(t, d, web("offline"), DialOptions{})
	if err != nil {
		t.Fatalf("an agent online within ctx: %v", err)
	}
	echoAndHalfClose(t, c, "x")
	_ = c.Close()
	r.online.Store(false)
	start = time.Now()
	_, err = dial(t, d, web("offline"), DialOptions{Early: true})
	if err != nil {
		t.Fatal(err) // early: the refusal comes with Answered
	}
	if time.Since(start) > time.Second {
		t.Fatal("an early dial was held")
	}
}

// TestConfigRefusesKeyAndCert: one relay credential, chosen once: a key
// and a certificate together are refused, never resolved by preference;
// so is a certificate to a plaintext relay.
func TestConfigRefusesKeyAndCert(t *testing.T) {
	cert := func() (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	for _, cfg := range []Config{{APIKey: "k", ClientCert: cert}, {ClientCert: cert, Plaintext: true}} {
		if _, err := NewDialer(cfg); CodeOf(err) != CodeUsage {
			t.Errorf("%+v: %v, want usage", cfg, err)
		}
		if _, err := Dial(context.Background(), cfg, "web/echo"); CodeOf(err) != CodeUsage {
			t.Errorf("Dial %+v: %v, want usage", cfg, err)
		}
	}
}

// TestDialerUsage: a group dial or a direct path without organisation
// mode, or a relay target with no Relay, is a usage error before anything
// is dialled.
func TestDialerUsage(t *testing.T) {
	d := dialer(t, Config{Relay: "127.0.0.1:1", Plaintext: true})
	for _, tc := range []struct {
		target string
		o      DialOptions
	}{{"pg@db", DialOptions{}}, {"web/echo", DialOptions{Direct: DirectOn}}} {
		if _, err := d.Dial(context.Background(), tc.target, tc.o); CodeOf(err) != CodeUsage {
			t.Errorf("%s %+v: %v, want usage", tc.target, tc.o, err)
		}
	}
	if _, err := dialer(t, Config{}).Dial(context.Background(), "web/echo", DialOptions{}); CodeOf(err) != CodeUsage {
		t.Errorf("no Relay: %v, want usage", err)
	}
}

// TestDialerCloseResetsItsConns: Close ends the data connections: a Conn
// riding them reads a reset, and no dial opens after it.
func TestDialerCloseResetsItsConns(t *testing.T) {
	r := newDataRelay(t, false)
	d := dialer(t, r.config(false))
	c, err := dial(t, d, web("echo"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("a Conn of a closed Dialer read %v, want a reset", err)
	}
	_ = c.Close()
	if _, err := dial(t, d, web("echo"), DialOptions{}); err == nil {
		t.Fatal("a closed Dialer dialled")
	}
}

// TestEvents: a session's events carry what cat pipe prints: open with
// its target, session and mode, close with the byte counts, error with
// the typed failure.
func TestEvents(t *testing.T) {
	r := newDataRelay(t, false)
	cfg := r.config(false)
	var evs []Event
	cfg.Events = func(e Event) { evs = append(evs, e) }
	d := dialer(t, cfg)
	c, err := dial(t, d, web("echo"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	echoAndHalfClose(t, c, "abc")
	_ = c.Close()
	_, _ = dial(t, d, web("refused"), DialOptions{})
	if len(evs) != 3 {
		t.Fatalf("events %+v", evs)
	}
	open, closed, failed := evs[0], evs[1], evs[2]
	if open.Kind != "open" || open.Target != "web/echo" || !strings.HasPrefix(open.Session, "s-") || open.E2EE || open.Path != "relayed" {
		t.Errorf("open %+v", open)
	}
	if closed.Kind != "close" || closed.Session != open.Session || closed.BytesIn != 3 || closed.BytesOut != 3 || closed.Err != nil {
		t.Errorf("close %+v", closed)
	}
	if failed.Kind != "error" || failed.Err == nil || failed.Err.Code != CodeRefused {
		t.Errorf("error %+v", failed)
	}
}
