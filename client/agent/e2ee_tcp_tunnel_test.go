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
	"crypto/x509"
	"encoding/hex"
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

// With Config.TCPE2EEOnly (nfltr tcp --e2ee: TCPTunnel and an E2EE
// certificate, no service table) a pinned session is TLS ended by the
// agent and the plaintext bridged to the session's target, byte for byte
// as a raw session's; the relay's SNI marker stays an E2EE share's HTTP.
// Before: every pinned session was taken for an E2EE share's HTTP, so a
// byte stream got nothing back once the agent's request header wait ended
// (lane E2EETCP, VMSCALE1 follow-up 6). Without the option a pinned
// session to a target stays HTTP to the default route (relay-core
// TestCoreProcessTLSAndE2EE: an agent with a route and a forward).
func TestPinnedSessionToTunnelTargetCarriesBytes(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "agent")
	target := echoTarget(t)

	for _, tc := range []struct {
		name    string
		targets sessionTargets
		target  string
		kind    sessionKind
	}{
		{"bytes, forward", sessionTargets{e2eeOnly: true, forwardAddr: target, defaultBackend: "http://" + target}, "localhost:1", sessionE2EETCP},
		{"bytes, SNI share marker", sessionTargets{e2eeOnly: true, defaultBackend: "http://" + target}, "__e2ee__", sessionE2EE},
		{"bytes, no raw targets", sessionTargets{e2eeOnly: true, noRaw: true, defaultBackend: "http://" + target}, target, sessionE2EE},
		{"no option, a port's target", sessionTargets{forwardAddr: target, defaultBackend: "http://" + target}, "localhost:22", sessionE2EE},
		{"no option, SNI share marker", sessionTargets{defaultBackend: "http://" + target}, "__e2ee__", sessionE2EE},
	} {
		p, err := planSession(&pb.TCPData{Open: true, TargetAddr: tc.target, E2Ee: true, Answer: true}, tc.targets, e2ee)
		if err != nil || p.kind != tc.kind {
			t.Errorf("%s: kind %d, %v; want kind %d", tc.name, p.kind, err, tc.kind)
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
	pin := sha256.Sum256(cert.Certificate[0])

	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{e2eeOnly: true, forwardAddr: target, defaultBackend: "http://" + target}, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer %v, %v", a, err)
	}
	tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, //nolint:gosec // pinned below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if got := sha256.Sum256(raw[0]); !bytes.Equal(got[:], pin[:]) {
				return errors.New("pin mismatch")
			}
			return nil
		}})
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

// Without Config.TCPE2EEOnly a pinned session to a target of an agent
// with a route and a forward is HTTP to the route, never the forward's
// bytes (relay-core TestCoreProcessTLSAndE2EE's agent; the case the
// first cut of the byte path broke).
func TestPinnedSessionWithoutBytesOptionIsHTTP(t *testing.T) {
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
// end encrypted (an open without --pin, or one the agent cannot end TLS
// for) is refused with ERROR_REASON_E2EE_REQUIRED, never dialled: without
// a pin the relay could read its bytes (lane E2EEPIN). Its refusal names
// no fingerprint: the answer is not authenticated, the pin comes from the
// agent's own output.
func TestE2EEOnlyTunnelRefusesUnpinnedSessions(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "agent")
	target := echoTarget(t)
	only := sessionTargets{e2eeOnly: true, defaultBackend: "http://" + target}
	for _, tc := range []struct {
		name string
		open *pb.TCPData
		cert *e2eeTLSConfig
	}{
		{"plain open", &pb.TCPData{Open: true, TargetAddr: target, Answer: true}, e2ee},
		{"plain open, no answer asked", &pb.TCPData{Open: true, TargetAddr: target}, e2ee},
		{"pinned open, no certificate", &pb.TCPData{Open: true, TargetAddr: target, E2Ee: true, Answer: true}, nil},
	} {
		_, err := planSession(tc.open, only, tc.cert)
		if got := refusalReason(err); err == nil || got != relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED {
			t.Errorf("%s: %v (reason %v), want ERROR_REASON_E2EE_REQUIRED", tc.name, err, got)
		}
		if err != nil && strings.Contains(err.Error(), relaytrustFingerprint(cert.Certificate[0])) {
			t.Errorf("%s: the refusal names the fingerprint: %v", tc.name, err)
		}
	}

	// On the agent link: the opener reads the typed refusal.
	l := &linkSessions{ctx: t.Context(), targets: only, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
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

// With Config.TCPE2EEOnly a pinned session goes only to the target the
// agent fixed (Config.TCPForwardAddr): one the relay names is refused with
// ERROR_REASON_TARGET_REFUSED, never dialled, and an agent configured
// without a fixed target does not start. Before: the agent dialled the
// open's TargetAddr, which the relay writes, and sent it the pinned
// client's plaintext (E2EEPROOF finding 1, spec/proverif/e2ee_tcp.pv query 3).
func TestE2EEOnlyTunnelRefusesRelayNamedTarget(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "agent")
	relayTarget := echoTarget(t) // reachable: only the plan keeps it from being dialled
	only := sessionTargets{e2eeOnly: true, defaultBackend: "http://" + relayTarget}
	_, err = planSession(&pb.TCPData{Open: true, TargetAddr: relayTarget, E2Ee: true, Answer: true}, only, e2ee)
	if got := refusalReason(err); err == nil || got != relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED {
		t.Fatalf("pinned open to the relay's target: %v (reason %v), want ERROR_REASON_TARGET_REFUSED", err, got)
	}

	l := &linkSessions{ctx: t.Context(), targets: only, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: relayTarget, E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED {
		t.Fatalf("answer %v, %v; want ERROR_REASON_TARGET_REFUSED", a, err)
	}

	a := New(Config{AgentID: "a", TCPTunnel: true, TCPE2EEOnly: true}, WithSelfSignedTLS())
	if err := a.Connect(t.Context()); !errors.Is(err, ErrE2EENoFixedTarget) {
		t.Fatalf("Connect without TCPForwardAddr: %v, want ErrE2EENoFixedTarget", err)
	}
}

func relaytrustFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// A pinned session the relay cuts between two TLS records (its transport
// ends, no close_notify from the client) reaches the agent's target as a
// reset, never as the client's clean half close; with the client's
// close_notify it is a half close (claims review CLAIMS-A Q5,
// spec/proverif/README.md e2ee_tcp query 12, mutant agent-clear-end).
func TestPinnedSessionCutIsResetAtTarget(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
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
		target := ln.Addr().String()
		l := &linkSessions{ctx: t.Context(), targets: sessionTargets{e2eeOnly: true, forwardAddr: target, defaultBackend: "http://" + target},
			e2ee: newE2EETLSConfig(cert, "agent"), logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
		s, c := sessionPair(t)
		h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
		if err != nil {
			t.Fatal(err)
		}
		go l.accept("", h, s)
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("answer %v, %v", a, err)
		}
		tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) //nolint:gosec // only the end is under test
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

// A pinned session whose target resets its connection (an RST, or any
// read error but EOF) reaches the client as a reset, never as the agent's
// close_notify; the target's clean end is the client's clean end (lane
// TCPRESET, spec/proverif/README.md e2ee_tcp query 15, mutant
// abort-as-close).
func TestPinnedSessionTargetResetIsResetAtClient(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
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
		target := ln.Addr().String()
		l := &linkSessions{ctx: t.Context(), targets: sessionTargets{e2eeOnly: true, forwardAddr: target, defaultBackend: "http://" + target},
			e2ee: newE2EETLSConfig(cert, "agent"), logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
		s, c := sessionPair(t)
		h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
		if err != nil {
			t.Fatal(err)
		}
		go l.accept("", h, s)
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("answer %v, %v", a, err)
		}
		tc := tlsend.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) //nolint:gosec // only the end is under test
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
