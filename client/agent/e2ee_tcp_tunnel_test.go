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
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// With Config.TCPE2EEBytes (nfltr tcp --e2ee: TCPTunnel and an E2EE
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
		{"bytes, a port's target", sessionTargets{e2eeBytes: true, defaultBackend: "http://" + target}, target, sessionE2EETCP},
		{"bytes, forward", sessionTargets{e2eeBytes: true, forwardAddr: target, defaultBackend: "http://" + target}, "localhost:1", sessionE2EETCP},
		{"bytes, SNI share marker", sessionTargets{e2eeBytes: true, defaultBackend: "http://" + target}, "__e2ee__", sessionE2EE},
		{"bytes, no raw targets", sessionTargets{e2eeBytes: true, noRaw: true, defaultBackend: "http://" + target}, target, sessionE2EE},
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

	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{e2eeBytes: true, defaultBackend: "http://" + target}, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
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

// Without Config.TCPE2EEBytes a pinned session to a target of an agent
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
