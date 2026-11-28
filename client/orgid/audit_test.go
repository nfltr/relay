// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
)

// The SDK's Identity audits the sessions it admits, as nfltr's
// orgmachine.Machine does, in the machine's one log (orgaudit.Log): the
// open with the client and the rule that admitted it, the close with its
// counts and reason (SA5 gap (b): it served with none).
func TestIdentitySessionAudited(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web, cli := load(t, filepath.Join(d, "web")), load(t, filepath.Join(d, "cli"))
	srvOrg(t, web).allow(t, web, "db")
	tc, err := cli.Certificate()
	check(t, err)
	var certs []*x509.Certificate // the chain the client presents: its leaf, its issuer's
	for _, der := range tc.Certificate[:2] {
		c, err := x509.ParseCertificate(der)
		check(t, err)
		certs = append(certs, c)
	}
	if _, err := web.CheckClient(certs, []string{"svc"}, now); err != nil {
		t.Fatal(err)
	}
	end := web.Audit(certs, "svc", []string{"svc"}, now) // as client/agent's org.go: admitted, then audited
	end(orgaudit.End{Closed: time.Now(), In: 3, Out: 4, Reason: orgaudit.ReasonClosed})
	data, err := os.ReadFile(filepath.Join(d, "web", orgaudit.LogFile))
	if err != nil {
		t.Fatal(err)
	}
	var rs []orgaudit.Record
	for l := range bytes.Lines(bytes.TrimSpace(data)) {
		r, err := orgaudit.Parse(bytes.TrimSuffix(l, []byte("\n")))
		check(t, err)
		rs = append(rs, r)
	}
	if len(rs) != 2 || rs[0].Kind != orgaudit.KindOpen || rs[0].Who.Name != "cli" || rs[0].Machine != "web" || rs[0].By == "" ||
		rs[1].Kind != orgaudit.KindClose || rs[1].Out != 4 || rs[1].Session != rs[0].Session {
		t.Fatalf("the log: %+v", rs)
	}
}

// A client the access rules refuse is recorded refused (no session),
// naming its certified person and the refusal's words; a chain the
// organisation did not issue writes nothing (its names are its own).
func TestIdentityRefusalAudited(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web, cli := load(t, filepath.Join(d, "web")), load(t, filepath.Join(d, "cli"))
	tc, err := cli.Certificate()
	check(t, err)
	var certs []*x509.Certificate
	for _, der := range tc.Certificate[:2] {
		c, err := x509.ParseCertificate(der)
		check(t, err)
		certs = append(certs, c)
	}
	_, why := web.CheckClient(certs, []string{"svc"}, now)
	if why == nil {
		t.Fatal("admitted with no rule")
	}
	web.AuditRefused(certs, "svc", why, now)
	web.AuditRefused([]*x509.Certificate{certs[1], certs[1]}, "svc", why, now) // not a leaf the organisation issued
	data, err := os.ReadFile(filepath.Join(d, "web", orgaudit.LogFile))
	check(t, err)
	var rs []orgaudit.Record
	for l := range bytes.Lines(bytes.TrimSpace(data)) {
		r, err := orgaudit.Parse(bytes.TrimSuffix(l, []byte("\n")))
		check(t, err)
		rs = append(rs, r)
	}
	if len(rs) != 1 || rs[0].Kind != orgaudit.KindRefused || rs[0].Who.Name != "cli" || rs[0].Service != "svc" || rs[0].Reason != why.Error() || rs[0].Session != "" {
		t.Fatalf("the log: %+v", rs)
	}
}
