// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
	"github.com/nfltr/relay/org/orgpki"
)

// Each test names the property of relay spec/proverif/e2ee_tcp_org.pv or
// spec/enrol/Enrol.tla it enforces; testdata/mutants.txt plants the bug
// that makes it fail (scripts/go-mutants.sh, make
// test-go-mutants).

func open(t *testing.T, dir string) *orgmachine.Machine {
	t.Helper()
	m, err := orgmachine.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// session runs a TLS session of organisation mode over a pipe: the server
// serves srv's certificate and admits groups (as the relay agent's
// org.go does through agent.Org), the client is cli's ClientTLS to name.
// It returns the client's handshake error.
func session(t *testing.T, srv, cli *orgmachine.Machine, name string, groups ...string) error {
	t.Helper()
	return sessionTLS(t, srv, cli.ClientTLS(name, func([]*x509.Certificate, time.Time) {}), groups...)
}

// sessionTLS is session with the client's TLS config cfg.
func sessionTLS(t *testing.T, srv *orgmachine.Machine, cfg *tls.Config, groups ...string) error {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	s := tls.Server(a, &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return srv.Certificate() },
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := srv.CheckClient(cs.PeerCertificates, groups, time.Now())
			return err
		},
	})
	go func() { _ = s.Handshake(); _, _ = io.Copy(s, s) }()
	c := tls.Client(b, cfg)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		return err
	}
	// TLS 1.3: the server's refusal of the client arrives on the first read.
	if _, err := c.Write([]byte("x")); err != nil {
		return err
	}
	_, err := c.Read(make([]byte, 1))
	return err
}

// A client reaches only the machine it names (e2ee_tcp_org.pv queries
// 1, 3: mutants client-no-name-check, client-skips-check), and a service
// admits only its groups (query 8: no-group-check).
func TestNamedMachineAndGroup(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	d := t.TempDir()
	o.Enrol(t, filepath.Join(d, "web"), "web", now, "web")
	o.Enrol(t, filepath.Join(d, "eve"), "eve", now, "web")
	o.Enrol(t, filepath.Join(d, "cli"), "cli", now, "db")
	web, eve, cli := open(t, filepath.Join(d, "web")), open(t, filepath.Join(d, "eve")), open(t, filepath.Join(d, "cli"))
	if err := session(t, web, cli, "web", "db"); err != nil {
		t.Fatalf("cli to web: %v", err)
	}
	if err := session(t, eve, cli, "web", "db"); err == nil {
		t.Error("the client took eve's certificate for web")
	}
	if err := session(t, web, eve, "web", "db"); err == nil {
		t.Error("the service admitted eve, outside its group")
	}
}

// A group dial (<service>@<group>) reaches any machine whose certificate
// holds the group and no other, whatever its name (BIND:org.group, relay
// spec/proverif/e2ee_tcp.pv mutant group-dial-no-group-check); a revoked
// member is refused as on a machine dial.
func TestGroupDialChecksTheGroup(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	d := t.TempDir()
	o.Enrol(t, filepath.Join(d, "web-1"), "web-1", now, "web", "db")
	o.Enrol(t, filepath.Join(d, "web-2"), "web-2", now, "db")
	o.Enrol(t, filepath.Join(d, "eve"), "eve", now, "web")
	o.Enrol(t, filepath.Join(d, "cli"), "cli", now, "db")
	cli := open(t, filepath.Join(d, "cli"))
	dial := func(srv string) error {
		var got []*x509.Certificate
		err := sessionTLS(t, open(t, filepath.Join(d, srv)), cli.GroupClientTLS("db", func(c []*x509.Certificate, _ time.Time) { got = c }), "db")
		if err == nil && (len(got) != 2 || got[0].Subject.CommonName != srv) {
			t.Errorf("admitted %v, want %s's chain", got, srv)
		}
		return err
	}
	for _, srv := range []string{"web-1", "web-2"} {
		if err := dial(srv); err != nil {
			t.Errorf("db to %s: %v", srv, err)
		}
	}
	if err := dial("eve"); err == nil || !strings.Contains(err.Error(), "not a machine of group db") {
		t.Errorf("db to eve, outside db: %v, want refused", err)
	}
	o.Revoke(t, "web-2", now.Add(time.Second))
	if _, err := cli.Reload(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := dial("web-2"); err == nil {
		t.Error("db to revoked web-2 admitted")
	}
}

// Another organisation's machine of the same name is refused: the chain
// is to this organisation's root (query 1, client-no-chain-check is
// orgpki's no-chain-check).
func TestOtherOrganisationRefused(t *testing.T) {
	now := time.Now()
	o, other := orgmachinetest.New(t, now), orgmachinetest.New(t, now)
	d := t.TempDir()
	o.Enrol(t, filepath.Join(d, "cli"), "cli", now, "db")
	other.Enrol(t, filepath.Join(d, "web"), "web", now, "web")
	if err := session(t, open(t, filepath.Join(d, "web")), open(t, filepath.Join(d, "cli")), "web", "db"); err == nil {
		t.Error("the client took another organisation's web")
	}
}

// Reload takes a newer CRL and signals a change; a revoked client is then
// refused and a held session cut (Enrol.tla RevocationBound; mutant
// no-cut-on-update); one not revoked is held on.
func TestRevocationCutsHeldSession(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	d := t.TempDir()
	o.Enrol(t, filepath.Join(d, "web"), "web", now, "web")
	lost := o.Enrol(t, filepath.Join(d, "lost"), "lost", now, "db")
	keep := o.Enrol(t, filepath.Join(d, "cli"), "cli", now, "db")
	web := open(t, filepath.Join(d, "web"))
	chain := func(c *x509.Certificate) []*x509.Certificate {
		crt, _ := web.Certificate()
		iss, _ := x509.ParseCertificate(crt.Certificate[1])
		return []*x509.Certificate{c, iss}
	}
	hold := func(c *x509.Certificate) <-chan struct{} {
		until, err := web.CheckClient(chain(c), []string{"db"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		cut := make(chan struct{})
		changed := web.Changed()
		go web.Hold(until, changed, func(now time.Time) (time.Time, error) {
			return web.CheckClient(chain(c), []string{"db"}, now)
		}, func() { close(cut) }, t.Context().Done())
		return cut
	}
	cutLost, cutKeep := hold(lost), hold(keep)
	o.Revoke(t, "lost", now.Add(time.Second))
	if changed, err := web.Reload(time.Now()); err != nil || !changed {
		t.Fatalf("Reload: changed %v, %v", changed, err)
	}
	select {
	case <-cutLost:
	case <-time.After(10 * time.Second):
		t.Fatal("the revoked client's session was not cut")
	}
	select {
	case <-cutKeep:
		t.Error("a client not revoked was cut")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := web.CheckClient(chain(lost), []string{"db"}, time.Now()); err == nil {
		t.Error("the revoked client is still admitted")
	}
}

// A held session ends at its admission's until (Enrol.tla
// NoExpiredSession; mutant no-expiry-timer).
func TestHoldEndsAtUntil(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	d := t.TempDir()
	o.Enrol(t, d, "web", now, "web")
	m := open(t, d)
	cut := make(chan struct{})
	go m.Hold(time.Now().Add(200*time.Millisecond), m.Changed(), func(time.Time) (time.Time, error) { return time.Now().Add(time.Hour), nil },
		func() { close(cut) }, t.Context().Done())
	select {
	case <-cut:
	case <-time.After(10 * time.Second):
		t.Fatal("the session outlived its until")
	}
}

// Organisation mode never runs unenrolled (the refusal names the fix, nfltr
// org join: nfltr cat serve --ssh and the TCP clients show it), and a key others can
// read is refused.
func TestOpenFailsClosed(t *testing.T) {
	if _, err := orgmachine.Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "nfltr org join") {
		t.Errorf("Open of an empty directory: %v, want a refusal naming nfltr org join", err)
	}
	now := time.Now()
	d := t.TempDir()
	orgmachinetest.New(t, now).Enrol(t, d, "web", now, "web")
	if err := os.Chmod(filepath.Join(d, orgmachine.KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := orgmachine.Open(d); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open with a 0644 key: %v", err)
	}
}

// Install keeps only a certificate for the key the machine made for the
// request (Enrol.tla MachineHoldsItsKey, mutant install-stale-answer): an
// issuer's genuine certificate of another key is refused and the machine's
// files stay a matching pair.
func TestInstallRefusesAnotherKey(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	dir := filepath.Join(t.TempDir(), "web")
	o.Enrol(t, dir, "web", now, "web")
	m := open(t, dir)
	cur, curKey := m.Current()
	renewal := func() ([]byte, ed25519.PrivateKey) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		der, err := o.Issuer.Renew(orgpki.NewRenewRequest(cur.Raw, curKey, csr), now)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	old, _ := renewal()
	_, mine := renewal()
	unlock, err := m.LockRenewal()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := m.Install(old, o.Issuer.Cert().Raw, nil, mine, now); !errors.Is(err, orgmachine.ErrNotForKey) {
		t.Fatalf("installed a certificate of another key: %v", err)
	}
	if _, err := m.Reload(now); err != nil {
		t.Fatalf("the files after a refused answer: %v", err)
	}
	if c, _ := m.Current(); !c.Equal(cur) {
		t.Fatal("the certificate changed")
	}
}

// A renewal comes with its own SSH host certificate: one for another
// machine's name is refused and the files stay as they were (mutant
// install-any-host-cert); the machine serves its own (HostSigner: its key,
// its principal, the issuer's signature).
func TestInstallChecksHostCert(t *testing.T) {
	now := time.Now()
	o := orgmachinetest.New(t, now)
	dir := filepath.Join(t.TempDir(), "web")
	o.Enrol(t, dir, "web", now, "web")
	other := o.Enrol(t, filepath.Join(t.TempDir(), "db"), "db", now, "db")
	m := open(t, dir)
	cur, curKey := m.Current()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.Issuer.Renew(orgpki.NewRenewRequest(cur.Raw, curKey, csr), now)
	if err != nil {
		t.Fatal(err)
	}
	otherHost, err := o.Issuer.HostCert(other.Raw, now)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := m.LockRenewal()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := m.Install(der, o.Issuer.Cert().Raw, otherHost, key, now); err == nil {
		t.Fatal("installed a renewal with db's host certificate")
	}
	if _, err := m.Reload(now); err != nil {
		t.Fatalf("the files after a refused answer: %v", err)
	}
	if c, _ := m.Current(); !c.Equal(cur) {
		t.Fatal("the certificate changed")
	}
	host, err := o.Issuer.HostCert(der, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Install(der, o.Issuer.Cert().Raw, host, key, now); err != nil {
		t.Fatal(err)
	}
	s, err := m.HostSigner()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := s.PublicKey().(*ssh.Certificate)
	want := orgid.MachineDNS("web", m.OrgID())
	if !ok || len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != want {
		t.Fatalf("host signer presents %v, want a certificate for %s", s.PublicKey().Type(), want)
	}
	ca, err := m.HostCA(now)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.SignatureKey.Marshal()) != string(ca.Marshal()) {
		t.Fatal("the host certificate is not signed by the CA nfltr org trust would write")
	}
}
