// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
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
)

// Each test names the property of spec/proverif/e2ee_tcp.pv or nfltr
// spec/enrol/Enrol.tla it enforces; testdata/mutants.txt plants the bug
// that makes it fail (make test-go-mutants). nfltr orgmachine's tests of
// the same names.

// session runs a TLS session of organisation mode over a pipe: the server
// serves srv's certificate and admits groups (as client/agent's org.go
// does through agent.Org), the client is cli's ClientTLS to name. It
// returns the client's handshake error.
func session(t *testing.T, srv, cli *Identity, name string, groups ...string) error {
	t.Helper()
	return sessionTLS(t, srv, cli.ClientTLS(name, func([]*x509.Certificate, time.Time) {}), groups...)
}

// sessionTLS is session with the client's TLS config cfg.
func sessionTLS(t *testing.T, srv *Identity, cfg *tls.Config, groups ...string) error {
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
	// TLS 1.3: the server's refusal of the client arrives on the first
	// read. The write goes beside it: on a pipe it waits for a server that
	// is sending its refusal.
	go func() { _, _ = c.Write([]byte("x")) }()
	_, err := c.Read(make([]byte, 1))
	return err
}

// A client reaches only the machine it names (e2ee_tcp.pv: mutants
// client-no-name-check, client-skips-check), and a service admits only
// its groups (mutant no-client-group-check).
func TestNamedMachineAndGroup(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	o.enrolDir(t, filepath.Join(d, "eve"), "eve", now, "web")
	o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web, eve, cli := load(t, filepath.Join(d, "web")), load(t, filepath.Join(d, "eve")), load(t, filepath.Join(d, "cli"))
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
// holds the group and no other, whatever its name (BIND:org.group,
// spec/proverif/e2ee_tcp.pv; mutant group-dial-skips-check); a revoked
// member is refused as on a machine dial.
func TestGroupDialChecksTheGroup(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web-1"), "web-1", now, "web", "db")
	web2 := o.enrolDir(t, filepath.Join(d, "web-2"), "web-2", now, "db")
	o.enrolDir(t, filepath.Join(d, "eve"), "eve", now, "web")
	o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	cli := load(t, filepath.Join(d, "cli"))
	dial := func(srv string) error {
		var got []*x509.Certificate
		err := sessionTLS(t, load(t, filepath.Join(d, srv)), cli.GroupClientTLS("db", func(c []*x509.Certificate, _ time.Time) { got = c }), "db")
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
	o.revoke(web2)
	o.publishCRL(t, now.Add(time.Second))
	if _, err := cli.Reload(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := dial("web-2"); err == nil {
		t.Error("db to revoked web-2 admitted")
	}
}

// Another organisation's machine of the same name is refused: the chain
// is to this organisation's root (mutant no-chain-check).
func TestOtherOrganisationRefused(t *testing.T) {
	now := time.Now()
	o, other := newTestOrg(t, now), newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	other.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	if err := session(t, load(t, filepath.Join(d, "web")), load(t, filepath.Join(d, "cli")), "web", "db"); err == nil {
		t.Error("the client took another organisation's web")
	}
}

// Reload takes a newer CRL and signals a change; a revoked client is then
// refused and a held session cut (Enrol.tla RevocationBound; mutants
// no-cut-on-update, reload-skips-crl); one not revoked is held on.
func TestRevocationCutsHeldSession(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	lost := o.enrolDir(t, filepath.Join(d, "lost"), "lost", now, "db")
	keep := o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web := load(t, filepath.Join(d, "web"))
	chain := func(c *x509.Certificate) []*x509.Certificate { return []*x509.Certificate{c, o.iss} }
	hold := func(c *x509.Certificate) <-chan struct{} {
		until, err := web.CheckClient(chain(c), []string{"db"}, time.Now())
		check(t, err)
		cut := make(chan struct{})
		changed := web.Changed()
		go web.Hold(until, changed, func(now time.Time) (time.Time, error) {
			return web.CheckClient(chain(c), []string{"db"}, now)
		}, func() { close(cut) }, t.Context().Done())
		return cut
	}
	cutLost, cutKeep := hold(lost), hold(keep)
	o.revoke(lost)
	o.publishCRL(t, now.Add(time.Second))
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
	d := t.TempDir()
	newTestOrg(t, now).enrolDir(t, d, "web", now, "web")
	m := load(t, d)
	cut := make(chan struct{})
	go m.Hold(time.Now().Add(200*time.Millisecond), m.Changed(), func(time.Time) (time.Time, error) { return time.Now().Add(time.Hour), nil },
		func() { close(cut) }, t.Context().Done())
	select {
	case <-cut:
	case <-time.After(10 * time.Second):
		t.Fatal("the session outlived its until")
	}
}

// Organisation mode never runs unenrolled (the refusal names the fix,
// nfltr org join), and a key others can read is refused.
func TestOpenFailsClosed(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "nfltr org join") {
		t.Errorf("Load of an empty directory: %v, want a refusal naming nfltr org join", err)
	}
	now := time.Now()
	d := t.TempDir()
	newTestOrg(t, now).enrolDir(t, d, "web", now, "web")
	check(t, os.Chmod(filepath.Join(d, KeyFile), 0o644))
	if _, err := Load(d); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load with a 0644 key: %v", err)
	}
}

// TakeCRL and TakeRotation keep only what the verifier takes, and keep it
// in the directory: a newer CRL revoking a peer, the recovery key's
// rotation; an older CRL and a rotation by anyone else change nothing.
func TestTakeKeepsWhatTheVerifierTakes(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web := o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	cli := load(t, filepath.Join(d, "cli"))
	old, err := os.ReadFile(filepath.Join(d, "cli", CRLFile))
	check(t, err)
	o.revoke(web)
	newer := o.crl(t, now.Add(time.Second))
	changed := cli.Changed()
	if took, err := cli.TakeCRL(newer, o.iss.Raw, time.Now()); err != nil || !took {
		t.Fatalf("TakeCRL of the newer CRL: %v, %v", took, err)
	}
	<-changed
	if _, err := cli.CheckServer([]*x509.Certificate{web, o.iss}, "web", time.Now()); err == nil {
		t.Error("web checks after the CRL revoking it")
	}
	if _, err := cli.TakeCRL(old, o.iss.Raw, time.Now()); err == nil {
		t.Error("TakeCRL took an older CRL")
	}
	if got, _ := os.ReadFile(filepath.Join(d, "cli", CRLFile)); string(got) != string(newer) {
		t.Error("crl.der is not the CRL taken")
	}

	thief := newTestOrg(t, now)
	if _, err := cli.TakeRotation(thief.root.Raw); err == nil {
		t.Error("TakeRotation took another organisation's root")
	}
	cross := o.rotate(t, now.Add(time.Minute))
	if took, err := cli.TakeRotation(cross.Raw); err != nil || !took {
		t.Fatalf("TakeRotation of the recovery key's rotation: %v, %v", took, err)
	}
	if again := load(t, filepath.Join(d, "cli")); !again.Verifier().Root().Equal(cross) {
		t.Error("root.pem is not the rotated root")
	}
}
