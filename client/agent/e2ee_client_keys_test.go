// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// clientCert is a self-signed client certificate for a new key, and the
// key's fingerprint (relaytrust.ClientKeyFingerprint).
func clientCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, relaytrust.ClientKeyFingerprint(leaf)
}

// pinnedEcho opens a pinned session on l to "svc", runs TLS with cert as
// the client's certificate (none when cert is nil) and echoes one line:
// the error of the first step that failed.
func pinnedEcho(t *testing.T, l *linkSessions, target string, cert *tls.Certificate) error {
	t.Helper()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer %v, %v", a, err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} //nolint:gosec // the pin is not under test here
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	tc := tls.Client(c, cfg)
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return err
	}
	if _, err := io.WriteString(tc, "ping\n"); err != nil {
		return err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(tc, buf); err != nil {
		return err
	}
	if string(buf) != "ping\n" {
		t.Fatalf("echo %q", buf)
	}
	return nil
}

// An agent with an allow-list of client keys (Config.TCPE2EEClients, a
// service's E2EEClients) ends a pinned session's TLS only with a client
// whose certificate's key is listed: the relay, which holds no listed key,
// cannot open a pinned session of its own and reach the service
// (E2EEPROOF finding 2, spec/proverif/e2ee_tcp.pv query 7). A client with
// no certificate, or another key, is refused in the handshake and nothing
// reaches the target; without a list any client is served (no client
// authentication).
func TestE2EEClientKeysGateTheService(t *testing.T) {
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "agent")
	target := echoTarget(t)
	allowed, allowedFP := clientCert(t)
	other, _ := clientCert(t)
	keys, err := newClientKeys([]string{"SHA256:" + strings.ToUpper(allowedFP)})
	if err != nil {
		t.Fatal(err)
	}
	table, err := NewServiceTable([]Service{{Name: "db", Kind: agentservices.TCP, Target: target, E2EE: agentservices.E2EEOn, E2EEClients: []string{allowedFP}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		targets sessionTargets
		target  string
	}{
		{"tunnel", sessionTargets{e2eeOnly: true, forwardAddr: target, clients: keys}, "localhost:1"},
		{"service", sessionTargets{services: table}, "db"},
	} {
		l := &linkSessions{ctx: t.Context(), targets: tc.targets, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
		if err := pinnedEcho(t, l, tc.target, &allowed); err != nil {
			t.Errorf("%s: allowed client: %v", tc.name, err)
		}
		if err := pinnedEcho(t, l, tc.target, &other); err == nil {
			t.Errorf("%s: a key not on the list was served", tc.name)
		}
		if err := pinnedEcho(t, l, tc.target, nil); err == nil {
			t.Errorf("%s: a client without a certificate was served", tc.name)
		}
	}
	open := &linkSessions{ctx: t.Context(), targets: sessionTargets{e2eeOnly: true, forwardAddr: target}, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	if err := pinnedEcho(t, open, "localhost:1", nil); err != nil {
		t.Errorf("no list: %v", err)
	}
}

// A malformed fingerprint fails the configuration, never matches silently.
func TestE2EEClientKeysRefuseMalformed(t *testing.T) {
	if _, err := NewServiceTable([]Service{{Name: "db", Kind: agentservices.TCP, Target: "localhost:1", E2EE: agentservices.E2EEOn, E2EEClients: []string{"abc"}}}); err == nil {
		t.Error("NewServiceTable took a malformed client key")
	}
	if err := New(Config{TCPTunnel: true, TCPE2EEOnly: true, TCPForwardAddr: "localhost:1", TCPE2EEClients: []string{"abc"}}, WithSelfSignedTLS()).Connect(t.Context()); err == nil || !strings.Contains(err.Error(), "client key") {
		t.Errorf("Connect with a malformed client key: %v", err)
	}
	if _, err := NewServiceTable([]Service{{Name: "web", Kind: agentservices.HTTP, Target: "http://localhost:1", E2EEClients: []string{strings.Repeat("a", 64)}}}); err == nil {
		t.Error("NewServiceTable took client keys on an http service (its E2EE sessions are browsers')")
	}
}
