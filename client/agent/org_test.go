// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// testOrg is an organisation for the agent's tests: a root, and machine
// certificates (CN the name, DNS <name>.org.internal, OU the groups)
// under it. fakeOrg is its Org for one machine; nfltr's orgpki is the real
// one (its own tests, nfltr internal/application/orgpki).
type testOrg struct {
	root    *x509.Certificate
	rootKey ed25519.PrivateKey
	pool    *x509.CertPool
}

func newTestOrg(t *testing.T) *testOrg {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := mustCert(t, tmpl, tmpl, pub, key)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testOrg{root: root, rootKey: key, pool: pool}
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub ed25519.PublicKey, key ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// machine is a certificate of the organisation (signer nil) or a
// self-signed look-alike (signer the machine's own key).
func (o *testOrg) machine(t *testing.T, name string, groups []string, life time.Duration, selfSigned bool) tls.Certificate {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: name, OrganizationalUnit: groups}, DNSNames: []string{name + ".org.internal"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(life), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	parent, signer := o.root, o.rootKey
	if selfSigned {
		parent, signer = tmpl, key
	}
	c := mustCert(t, tmpl, parent, pub, signer)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

type fakeOrg struct {
	o       *testOrg
	cert    tls.Certificate
	mu      sync.Mutex
	revoked map[string]bool
	changed chan struct{}
}

func (o *testOrg) agentOrg(cert tls.Certificate) *fakeOrg {
	return &fakeOrg{o: o, cert: cert, revoked: map[string]bool{}, changed: make(chan struct{})}
}

func (f *fakeOrg) Certificate() (*tls.Certificate, error) { return &f.cert, nil }

func (f *fakeOrg) CheckClient(certs []*x509.Certificate, groups []string, now time.Time) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(certs) == 0 {
		return time.Time{}, errors.New("no certificate")
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: f.o.pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return time.Time{}, err
	}
	if f.revoked[certs[0].SerialNumber.String()] {
		return time.Time{}, errors.New("revoked")
	}
	if !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(certs[0].Subject.OrganizationalUnit, g) }) {
		return time.Time{}, fmt.Errorf("not in %v", groups)
	}
	return certs[0].NotAfter, nil
}

func (f *fakeOrg) Changed() <-chan struct{} { f.mu.Lock(); defer f.mu.Unlock(); return f.changed }

// change revokes serials (if any) and signals a change.
func (f *fakeOrg) change(revoke ...*x509.Certificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range revoke {
		f.revoked[c.SerialNumber.String()] = true
	}
	close(f.changed)
	f.changed = make(chan struct{})
}

// orgSession opens a session on l to target and runs the client's TLS of
// organisation mode: the server checked against the root and the name
// web, cert as the client's certificate (none when nil); then one echo.
func orgSession(t *testing.T, l *linkSessions, target string, cert *tls.Certificate) (*tls.Conn, error) {
	return orgSessionTo(t, l, target, l.targets.services.byName[target].org.(*fakeOrg).o.pool, cert)
}

func orgSessionTo(t *testing.T, l *linkSessions, target string, pool *x509.CertPool, cert *tls.Certificate) (*tls.Conn, error) {
	t.Helper()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		return nil, fmt.Errorf("answer %v, %v", a, err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "web.org.internal"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	tc := tls.Client(c, cfg)
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(tc, "ping\n"); err != nil {
		return nil, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(tc, buf); err != nil {
		return nil, err
	}
	if string(buf) != "ping\n" {
		t.Fatalf("echo %q", buf)
	}
	return tc, nil
}

func orgSessions(t *testing.T, org Org, groups ...string) *linkSessions {
	t.Helper()
	table, err := NewServiceTable([]Service{{Name: "db", Kind: agentservices.TCP, Target: echoTarget(t), E2EE: agentservices.E2EEOn, Org: org, AllowGroups: groups}})
	if err != nil {
		t.Fatal(err)
	}
	return &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
}

// A service in organisation mode serves its machine certificate (the
// client checks it against the root and the name it dialled) and admits a
// client certificate of the organisation in an allowed group only: not
// another group, not a self-signed look-alike, not a client without a
// certificate (spec/proverif/e2ee_tcp_org.pv queries 6-8; mutants
// ignore-check, downgrade-any-client, org-falls-back-to-pins).
func TestOrgServiceAdmitsGroup(t *testing.T) {
	o := newTestOrg(t)
	org := o.agentOrg(o.machine(t, "web", []string{"web"}, time.Hour, false))
	l := orgSessions(t, org, "db", "ops")
	// Config.TCPE2EEOrg: the tunnel of nfltr tcp --e2ee --allow-group.
	tunnel := &linkSessions{ctx: t.Context(), targets: sessionTargets{e2eeOnly: true, forwardAddr: echoTarget(t), org: org, groups: []string{"db", "ops"}},
		logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	for _, tc := range []struct {
		name string
		cert *tls.Certificate
		ok   bool
	}{
		{"group db", new(o.machine(t, "cli", []string{"db"}, time.Hour, false)), true},
		{"group ops", new(o.machine(t, "cli2", []string{"ci", "ops"}, time.Hour, false)), true},
		{"group web", new(o.machine(t, "eve", []string{"web"}, time.Hour, false)), false},
		{"self-signed in db", new(o.machine(t, "mal", []string{"db"}, time.Hour, true)), false},
		{"expired", new(o.machine(t, "old", []string{"db"}, -time.Second, false)), false},
		{"no certificate", nil, false},
	} {
		_, err := orgSession(t, l, "db", tc.cert)
		if (err == nil) != tc.ok {
			t.Errorf("%s: served %v, want %v (%v)", tc.name, err == nil, tc.ok, err)
		}
		_, err = orgSessionTo(t, tunnel, "localhost:1", o.pool, tc.cert)
		if (err == nil) != tc.ok {
			t.Errorf("tunnel, %s: served %v, want %v (%v)", tc.name, err == nil, tc.ok, err)
		}
	}
}

// The client of organisation mode refuses a service whose certificate is
// not the dialled machine's: another name, or not under the root (the
// agent side's half of query 1: what it serves is its Org's certificate).
func TestOrgServiceServesItsMachineCertificate(t *testing.T) {
	o := newTestOrg(t)
	cli := o.machine(t, "cli", []string{"db"}, time.Hour, false)
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		ok   bool
	}{
		{"web", o.machine(t, "web", nil, time.Hour, false), true},
		{"another name", o.machine(t, "eve", nil, time.Hour, false), false},
		{"self-signed web", o.machine(t, "web", nil, time.Hour, true), false},
	} {
		_, err := orgSession(t, orgSessions(t, o.agentOrg(tc.cert), "db"), "db", &cli)
		if (err == nil) != tc.ok {
			t.Errorf("%s: client took the service %v, want %v (%v)", tc.name, err == nil, tc.ok, err)
		}
	}
}

// One mode per service: organisation mode takes no pins (its own
// certificate, client keys), needs a tcp service with e2ee on and a
// group; groups without the organisation are refused; a plain session to
// it is refused, never dialled (mutant pins-beside-org).
func TestOrgServiceOneMode(t *testing.T) {
	o := newTestOrg(t)
	org := o.agentOrg(o.machine(t, "web", nil, time.Hour, false))
	_, fp := clientCert(t)
	setup, err := NewE2EESetup("web", "", "", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	base := Service{Name: "db", Kind: agentservices.TCP, Target: "localhost:1", E2EE: agentservices.E2EEOn, Org: org, AllowGroups: []string{"db"}}
	for name, mutate := range map[string]func(*Service){
		"client keys":  func(s *Service) { s.E2EEClients = []string{fp} },
		"own cert":     func(s *Service) { s.Cert = setup },
		"no group":     func(s *Service) { s.AllowGroups = nil },
		"e2ee default": func(s *Service) { s.E2EE = agentservices.E2EEDefault },
		"http": func(s *Service) {
			s.Kind, s.Target, s.E2EE = agentservices.HTTP, "http://localhost:1", agentservices.E2EEDefault
		},
		"groups no org": func(s *Service) { s.Org = nil },
	} {
		s := base
		mutate(&s)
		if _, err := NewServiceTable([]Service{s}); err == nil {
			t.Errorf("%s: NewServiceTable took it", name)
		}
	}
	l := orgSessions(t, org, "db")
	_, err = planSession(&pb.TCPData{TargetAddr: "db", Answer: true}, l.targets, nil)
	var refused *ServiceRefusedError
	if !errors.As(err, &refused) || refused.Answer != relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED {
		t.Errorf("plain session: %v, want E2EE_REQUIRED", err)
	}
	_, err = planSession(&pb.TCPData{TargetAddr: "localhost:1", Answer: true}, sessionTargets{e2eeOnly: true, forwardAddr: "localhost:1", org: org, groups: []string{"db"}}, nil)
	if !errors.As(err, &refused) || refused.Answer != relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED {
		t.Errorf("tunnel, plain session: %v, want E2EE_REQUIRED", err)
	}
	for name, cfg := range map[string]Config{
		"tunnel client keys": {TCPTunnel: true, TCPE2EEOnly: true, TCPForwardAddr: "localhost:1", TCPE2EEOrg: org, TCPE2EEAllowGroups: []string{"db"}, TCPE2EEClients: []string{fp}},
		"tunnel not e2ee":    {TCPTunnel: true, TCPForwardAddr: "localhost:1", TCPE2EEOrg: org, TCPE2EEAllowGroups: []string{"db"}},
		"tunnel no group":    {TCPTunnel: true, TCPE2EEOnly: true, TCPForwardAddr: "localhost:1", TCPE2EEOrg: org},
		"tunnel groups only": {TCPTunnel: true, TCPE2EEOnly: true, TCPForwardAddr: "localhost:1", TCPE2EEAllowGroups: []string{"db"}},
	} {
		// Bounded: a config wrongly taken goes on to dial a relay there is none of.
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		err := New(cfg, WithSelfSignedTLS()).Connect(ctx)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "organisation") {
			t.Errorf("%s: Connect: %v, want the organisation-mode refusal", name, err)
		}
	}
}

// cutWithin is whether tc's session ends (a read error other than the
// test's own deadline) within d.
func cutWithin(tc *tls.Conn, d time.Duration) bool {
	_ = tc.SetReadDeadline(time.Now().Add(d))
	_, err := tc.Read(make([]byte, 1))
	var ne interface{ Timeout() bool }
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// A session ends when its admission lapses: the client certificate's
// NotAfter (Identity.Until; Enrol.tla NoExpiredSession, mutant
// no-expiry-timer).
func TestOrgSessionEndsAtUntil(t *testing.T) {
	o := newTestOrg(t)
	l := orgSessions(t, o.agentOrg(o.machine(t, "web", nil, time.Hour, false)), "db")
	tc, err := orgSession(t, l, "db", new(o.machine(t, "cli", []string{"db"}, 2*time.Second, false)))
	if err != nil {
		t.Fatal(err)
	}
	if !cutWithin(tc, 10*time.Second) {
		t.Error("the session outlived its client's certificate")
	}
}

// A change (a newer CRL, a root) checks open sessions again: one it
// refuses ends at once, one it still admits goes on (Enrol.tla
// RevocationBound, mutant no-cut-on-update).
func TestOrgSessionCutOnUpdate(t *testing.T) {
	o := newTestOrg(t)
	org := o.agentOrg(o.machine(t, "web", nil, time.Hour, false))
	l := orgSessions(t, org, "db")
	keep, lost := o.machine(t, "cli", []string{"db"}, time.Hour, false), o.machine(t, "lost", []string{"db"}, time.Hour, false)
	tcKeep, err := orgSession(t, l, "db", &keep)
	if err != nil {
		t.Fatal(err)
	}
	tcLost, err := orgSession(t, l, "db", &lost)
	if err != nil {
		t.Fatal(err)
	}
	org.change() // a change that admits both
	org.change(lost.Leaf)
	if !cutWithin(tcLost, 10*time.Second) {
		t.Error("a revoked client's session went on after the update")
	}
	_ = tcKeep.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(tcKeep, "pong\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcKeep, make([]byte, 5)); err != nil {
		t.Errorf("an admitted client's session ended on the update: %v", err)
	}
	if _, err := orgSession(t, l, "db", &lost); err == nil {
		t.Error("a revoked client opened a new session")
	}
}
