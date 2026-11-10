// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/tlsend"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// orgTunnel is the link sessions of a tunnel of nfltr tcp --e2ee
// --allow-group db (Config.TCPE2EEOnly, TCPE2EEOrg, TCPForwardAddr), its
// organisation's machine web, and a client certificate in db.
func orgTunnel(t *testing.T, forward string) (*linkSessions, *testOrg, tls.Certificate) {
	t.Helper()
	o := newTestOrg(t)
	org := o.agentOrg(o.machine(t, "web", nil, time.Hour, false))
	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{forwardAddr: forward, defaultBackend: "http://" + forward, org: org, groups: []string{"db"}},
		logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	return l, o, o.machine(t, "cli", []string{"db"}, time.Hour, false)
}

// orgClient is the client's TLS of organisation mode on c: web's machine
// certificate checked against the root, cli presented.
func orgClient(c net.Conn, o *testOrg, cli tls.Certificate) *tlsend.Conn {
	return tlsend.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: o.pool, ServerName: "web.org.internal", Certificates: []tls.Certificate{cli}})
}

// With Config.TCPE2EEOnly in organisation mode (nfltr tcp --e2ee
// --allow-group: TCPTunnel, no service table) an end-to-end encrypted
// session is the organisation's TLS ended by the agent and the plaintext
// bridged to the agent's fixed target, byte for byte as a raw session's,
// whatever target the open names (the relay writes it: E2EEPROOF finding
// 1, spec/proverif/e2ee_tcp.pv mutant relay-names-target-with-forward).
// Without the option an end-to-end encrypted session to a target stays an
// E2EE share's HTTP to the default route (relay-core
// TestCoreProcessTLSAndE2EE: an agent with a route and a forward).
func TestOrgTunnelCarriesBytes(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "agent")
	target := echoTarget(t)
	l, o, cli := orgTunnel(t, target)

	for _, tc := range []struct {
		name    string
		targets sessionTargets
		target  string
		kind    sessionKind
	}{
		{"organisation, forward", l.targets, "localhost:1", sessionE2EETCP},
		{"organisation, SNI share marker", l.targets, "__e2ee__", sessionE2EETCP},
		{"no option, a port's target", sessionTargets{forwardAddr: target, defaultBackend: "http://" + target}, "localhost:22", sessionE2EE},
		{"no option, SNI share marker", sessionTargets{defaultBackend: "http://" + target}, "__e2ee__", sessionE2EE},
	} {
		p, err := planSession(&pb.TCPData{Open: true, TargetAddr: tc.target, E2Ee: true, Answer: true}, tc.targets, e2ee)
		if err != nil || p.kind != tc.kind {
			t.Errorf("%s: kind %d, %v; want kind %d", tc.name, p.kind, err, tc.kind)
		}
		if tc.kind == sessionE2EETCP && p.target != target {
			t.Errorf("%s: target %q, want the agent's own %q", tc.name, p.target, target)
		}
	}

	// End to end: 8 MiB through the TLS the agent ends, sha256 compared.
	payload := make([]byte, 8<<20)
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCTR(block, make([]byte, 16)).XORKeyStream(payload, payload)
	want := sha256.Sum256(payload)

	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer %v, %v", a, err)
	}
	tc := orgClient(c, o, cli)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	go func() {
		_, _ = tc.Write(payload)
		_ = tc.CloseWrite()
	}()
	hash := sha256.New()
	n, err := io.Copy(hash, tc)
	if err != nil || n != int64(len(payload)) || !bytes.Equal(hash.Sum(nil), want[:]) {
		t.Fatalf("echoed %d bytes (want %d), sha256 match %v, %v", n, len(payload), bytes.Equal(hash.Sum(nil), want[:]), err)
	}
	_ = net.Conn(tc).Close()
}

// Without Config.TCPE2EEOnly an end-to-end encrypted session to a target
// of an agent with a route and a forward is an E2EE share's HTTP to the
// route, never the forward's bytes (relay-core TestCoreProcessTLSAndE2EE's
// agent; the case the first cut of the byte path broke).
func TestE2EESessionWithoutOrgTunnelIsHTTP(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "web saw "+r.URL.Path)
	}))
	defer backend.Close()
	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{forwardAddr: echoTarget(t), defaultBackend: backend.URL},
		e2ee: newE2EETLSConfig(cert, "agent"), logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:22", E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer %v, %v", a, err)
	}
	tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) //nolint:gosec // only the path is under test
	defer tc.Close()                                                                         //nolint:errcheck
	if _, err := io.WriteString(tc, "GET /sealed HTTP/1.1\r\nHost: web\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("not HTTP from the route: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(body) != "web saw /sealed" {
		t.Fatalf("body %q, want the route's answer", body)
	}
}

// With Config.TCPE2EEOnly (nfltr tcp --e2ee) a session that is not end to
// end encrypted is refused with ERROR_REASON_E2EE_REQUIRED, never
// dialled: the relay could read its bytes (lane E2EEPIN). Its refusal
// names no certificate: the answer is not authenticated.
func TestOrgTunnelRefusesPlainSessions(t *testing.T) {
	target := echoTarget(t)
	l, _, _ := orgTunnel(t, target)
	for _, tc := range []struct {
		name string
		open *pb.TCPData
	}{
		{"plain open", &pb.TCPData{Open: true, TargetAddr: target, Answer: true}},
		{"plain open, no answer asked", &pb.TCPData{Open: true, TargetAddr: target}},
	} {
		_, err := planSession(tc.open, l.targets, nil)
		if got := refusalReason(err); err == nil || got != relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED {
			t.Errorf("%s: %v (reason %v), want ERROR_REASON_E2EE_REQUIRED", tc.name, err, got)
		}
	}

	// On the agent link: the opener reads the typed refusal.
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED {
		t.Fatalf("answer %v, %v; want ERROR_REASON_E2EE_REQUIRED", a, err)
	}
}

// An end-to-end encrypted tunnel goes only to the target the agent fixed
// (Config.TCPForwardAddr): an agent configured without one does not start
// (before: it dialled the open's TargetAddr, which the relay writes, and
// sent it the client's plaintext: E2EEPROOF finding 1,
// spec/proverif/e2ee_tcp.pv mutant relay-names-target), and one without
// its organisation does not either (organisation mode is the only E2EE
// tcp mode).
func TestE2EEOnlyTunnelNeedsForwardAndOrg(t *testing.T) {
	a := New(Config{AgentID: "a", TCPTunnel: true, TCPE2EEOnly: true}, WithSelfSignedTLS())
	if err := a.Connect(t.Context()); !errors.Is(err, ErrE2EENoFixedTarget) {
		t.Fatalf("Connect without TCPForwardAddr: %v, want ErrE2EENoFixedTarget", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	a = New(Config{AgentID: "a", TCPTunnel: true, TCPE2EEOnly: true, TCPForwardAddr: "localhost:1"}, WithSelfSignedTLS())
	if err := a.Connect(ctx); err == nil || !strings.Contains(err.Error(), "organisation") {
		t.Fatalf("Connect without TCPE2EEOrg: %v, want the organisation-mode refusal", err)
	}
}

// An end-to-end encrypted session the relay cuts between two TLS records
// (its transport ends, no close_notify from the client) reaches the
// agent's target as a reset, never as the client's clean half close; with
// the client's close_notify it is a half close (claims review CLAIMS-A
// Q5, spec/proverif/e2ee_tcp.pv query 12, mutant agent-clear-end).
func TestOrgSessionCutIsResetAtTarget(t *testing.T) {
	for _, cut := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		ended := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				ended <- err
				return
			}
			defer c.Close() //nolint:errcheck
			b, err := io.ReadAll(c)
			if err == nil && string(b) != "hello" {
				err = errors.New("read " + string(b))
			}
			ended <- err
		}()
		l, o, cli := orgTunnel(t, ln.Addr().String())
		s, c := sessionPair(t)
		h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
		if err != nil {
			t.Fatal(err)
		}
		go l.accept("", h, s)
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("answer %v, %v", a, err)
		}
		tc := orgClient(c, o, cli)
		if _, err := io.WriteString(tc, "hello"); err != nil {
			t.Fatal(err)
		}
		if cut {
			_ = c.Close() // the relay's cut: no close_notify
		} else {
			_ = tc.CloseWrite()
		}
		select {
		case err := <-ended:
			if reset := err != nil; reset != cut {
				t.Errorf("cut %v: the target's read ended with %v, want a reset %v", cut, err, cut)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("cut %v: the target's read did not end", cut)
		}
	}
}

// An end-to-end encrypted session whose target resets its connection (an
// RST, or any read error but EOF) reaches the client as a reset, never as
// the agent's close_notify; the target's clean end is the client's clean
// end (lane TCPRESET, spec/proverif/e2ee_tcp.pv query 13, mutant
// abort-as-close).
func TestOrgSessionTargetResetIsResetAtClient(t *testing.T) {
	for _, reset := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*net.TCPConn)
			_, _ = io.ReadFull(tc, make([]byte, len("hello")))
			_, _ = io.WriteString(tc, "hi")
			if reset {
				_ = tc.SetLinger(0) // the target's reset
				_ = tc.Close()
				return
			}
			_ = tc.CloseWrite()
			_, _ = io.Copy(io.Discard, tc)
			_ = tc.Close()
		}()
		l, o, cli := orgTunnel(t, ln.Addr().String())
		s, c := sessionPair(t)
		h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
		if err != nil {
			t.Fatal(err)
		}
		go l.accept("", h, s)
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("answer %v, %v", a, err)
		}
		tc := orgClient(c, o, cli)
		if _, err := io.WriteString(tc, "hello"); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(tc)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("reset %v: the client's read did not end", reset)
		}
		if reset && err == nil {
			t.Errorf("reset: the client read %q and a clean end, want a reset", got)
		}
		if !reset && (err != nil || string(got) != "hi") {
			t.Errorf("clean end: the client read %q, %v; want hi and a clean end", got, err)
		}
		_ = tc.CloseWrite()
	}
}
