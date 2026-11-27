// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// grantFor is the issuer's grant to client's key of web/svc until until,
// put in the client's status.json (the copy its keeper writes).
func (o *testOrg) grantFor(t *testing.T, dir string, client *x509.Certificate, until time.Time) *x509.Certificate {
	t.Helper()
	g := mint(t, &x509.Certificate{SerialNumber: serialNumber(t), NotBefore: time.Now().Add(-time.Minute), NotAfter: until,
		BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{GrantURI(o.orgID, Grant{Request: "r-1", Who: KindMachine + ":" + client.Subject.CommonName, Where: "machine:web", Service: "svc", By: "alice@acme.com"})},
	}, o.iss, client.PublicKey, o.issKey)
	body, err := json.Marshal(map[string]any{"grants": []map[string]any{{"cert": g.Raw}}})
	check(t, err)
	msg, err := json.Marshal(map[string][]byte{"body": body})
	check(t, err)
	check(t, os.WriteFile(filepath.Join(dir, StatusFile), msg, 0o600))
	return g
}

// A client with no rule reaches a service by the grant its machine holds:
// its sessions to that service present it (ClientCertificate), the server
// admits by it (AdmitClient), and the session ends at the grant's end
// (Grant.tla Tick: mutant expiry-refuses-only) or when a CRL lists it
// (Deliver: revoke-refuses-only).
func TestGrantSessionAdmittedAndCut(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	cliCert := o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web, cli := load(t, filepath.Join(d, "web")), load(t, filepath.Join(d, "cli"))
	cfg := func(service string) *tls.Config {
		c := cli.ClientTLS("web", func([]*x509.Certificate, time.Time) {})
		c.GetClientCertificate = cli.ClientCertificate(service, "machine:web")
		return c
	}
	if err := sessionTLS(t, web, cfg("svc")); err == nil {
		t.Fatal("a client with neither rule nor grant admitted")
	}
	g := o.grantFor(t, filepath.Join(d, "cli"), cliCert, time.Now().Add(time.Hour))
	if err := sessionTLS(t, web, cfg("svc")); err != nil {
		t.Fatalf("the grant's session: %v", err)
	}
	if err := sessionTLS(t, web, cfg("other")); err == nil {
		t.Error("a session to another service admitted (no grant presented)")
	}
	chain := []*x509.Certificate{cliCert, o.iss, g}
	until, err := web.CheckClient(chain, []string{"svc"}, time.Now())
	check(t, err)
	if until.After(g.NotAfter) {
		t.Fatalf("admitted until %s, past the grant's %s", until, g.NotAfter)
	}
	hold := func(chain []*x509.Certificate) <-chan struct{} {
		until, err := web.CheckClient(chain, []string{"svc"}, time.Now())
		check(t, err)
		cut := make(chan struct{})
		go web.Hold(until, web.Changed(), func(now time.Time) (time.Time, error) {
			return web.CheckClient(chain, []string{"svc"}, now)
		}, func() { close(cut) }, t.Context().Done())
		return cut
	}
	short := o.grantFor(t, filepath.Join(d, "cli"), cliCert, time.Now().Add(1500*time.Millisecond))
	cutShort, cutRevoked := hold([]*x509.Certificate{cliCert, o.iss, short}), hold(chain)
	select {
	case <-cutShort:
	case <-time.After(10 * time.Second):
		t.Fatal("a grant session outlived its grant")
	}
	o.revoke(g)
	o.publishCRL(t, time.Now())
	if _, err := web.Reload(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cutRevoked:
	case <-time.After(10 * time.Second):
		t.Fatal("a revoked grant's session was not cut")
	}
}
