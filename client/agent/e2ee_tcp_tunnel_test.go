// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
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
	"testing"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// A pinned session to a tunnel without a service table (nfltr tcp
// --e2ee: TCPTunnel and an E2EE certificate) is TLS ended by the agent
// and the plaintext bridged to the session's target, byte for byte as a
// raw session's; only the relay's SNI marker target goes to the HTTP
// proxy of E2EE shares. Before: every pinned session was taken for an
// E2EE share's HTTP, so a byte stream got nothing back once the agent's
// request header wait ended (lane E2EETCP, VMSCALE1 follow-up 6).
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
		{"tcp tunnel, a port's target", sessionTargets{defaultBackend: "http://" + target}, target, sessionE2EETCP},
		{"tcp tunnel, forward", sessionTargets{forwardAddr: target, defaultBackend: "http://" + target}, "localhost:1", sessionE2EETCP},
		{"SNI share marker", sessionTargets{defaultBackend: "http://" + target}, "__e2ee__", sessionE2EE},
		{"no raw targets", sessionTargets{noRaw: true, defaultBackend: "http://" + target}, target, sessionE2EE},
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

	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{defaultBackend: "http://" + target}, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
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
