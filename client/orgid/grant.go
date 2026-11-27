// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

// Grants: just-in-time, time-limited, approved access to one service (nfltr
// docs/decisions/service-access-2026-11-25.md "Grants"; spec/grant/Grant.tla
// Open, Tick, Deliver; spec/proverif/svc_access.pv query 1,
// BIND:svc.grantsig, BIND:svc.grantwho, BIND:svc.grantsvc). A grant is a
// short-lived certificate the organisation's issuer signs for the
// requester's own key once an approver approved the request (relay org
// orgpki Issuer.ApplyGrant), with one URI SAN
// nfltr://<org id>.internal/grant/<request>?who=..&where=..&service=..&by=..
// (a short-lived certificate carrying the access, as Teleport's access
// requests and SSH certificates' validity windows do). The client presents
// it after its own certificate and its issuer's, inside the session's TLS;
// the serving agent admits by it only for the grant's principal and
// service, under the organisation's root, before its NotAfter, while it is
// not on the issuer's CRL and that CRL is fresh. Verifier.check refuses a
// grant as a machine's certificate.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const grantURIPath = "/grant/"

// Grant is what a grant certificate grants: Who (the requester's
// principal, "person:<email>" or "machine:<name>") may use Service at
// Where (a "group:" or "machine:" place) until Until, by request Request
// that the person By approved.
type Grant struct {
	Request string
	Who     string
	Where   string
	Service string
	By      string
	Serial  string // hex
	Until   time.Time
}

// GrantURI is the URI SAN of a grant certificate of organisation orgID.
func GrantURI(orgID string, g Grant) *url.URL {
	return &url.URL{Scheme: "nfltr", Host: Domain(orgID), Path: grantURIPath + g.Request,
		RawQuery: url.Values{"who": {g.Who}, "where": {g.Where}, "service": {g.Service}, "by": {g.By}}.Encode()}
}

// GrantOf is the grant c carries, when it is a grant certificate: one
// nfltr URI SAN with the grant path, and nothing else naming a machine.
func GrantOf(c *x509.Certificate) (Grant, bool) {
	if len(c.URIs) != 1 || len(c.DNSNames) != 0 || len(c.EmailAddresses) != 0 {
		return Grant{}, false
	}
	u := c.URIs[0]
	req, ok := strings.CutPrefix(u.Path, grantURIPath)
	if !ok || u.Scheme != "nfltr" || req == "" {
		return Grant{}, false
	}
	q := u.Query()
	return Grant{Request: req, Who: q.Get("who"), Where: q.Get("where"), Service: q.Get("service"), By: q.Get("by"),
		Serial: hex.EncodeToString(c.SerialNumber.Bytes()), Until: c.NotAfter}, true
}

// isGrant: c has a grant URI SAN (any, however malformed): never a
// machine's certificate.
func isGrant(c *x509.Certificate) bool {
	return slices.ContainsFunc(c.URIs, func(u *url.URL) bool { return strings.HasPrefix(u.Path, grantURIPath) })
}

// PrincipalOf is a checked certificate's principal as a grant names it:
// its person, else its machine name.
func PrincipalOf(c Checked) string {
	if c.Person != "" {
		return KindPerson + ":" + c.Person
	}
	return KindMachine + ":" + c.Name
}

// CheckGrant admits client (leaf, checked: client) to one of services on
// self by the grant certificate g it presented, issued by issuer: under
// the root (BIND:svc.grantsig), for leaf's key and client's principal
// (BIND:svc.grantwho), for self and one of services (BIND:svc.grantsvc),
// before its NotAfter, not on the issuer's CRL, that CRL fresh (Grant.tla
// Open). until is the earliest of the grant's, the CRL's, the chain's and
// the client's ends: the session's timer (Grant.tla Tick).
func (v *Verifier) CheckGrant(g, issuer, leaf *x509.Certificate, client, self Checked, services []string, now time.Time) (Grant, time.Time, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	gr, until, why, err := v.checkGrant(g, issuer, leaf, client, self, services, now)
	l := map[string]any{"ev": "admit", "o": v.orgID, "sn": gr.Serial, "who": gr.Who, "cwho": PrincipalOf(client), "where": gr.Where,
		"svc": gr.Service, "svcs": append([]string{}, services...), "until": gr.Until.Unix(), "t": now.Unix(), "ok": err == nil, "why": why, "u": until.Unix(),
		"num": 0, "next": 0, "rev": false}
	if crl := v.crls[KeyFingerprint(issuer.PublicKey)]; crl != nil {
		l["num"], l["next"], l["rev"] = crl.number.Int64(), crl.next.Unix(), crl.revoked[g.SerialNumber.String()]
	}
	grantTrace(l)
	return gr, until, err
}

func (v *Verifier) checkGrant(g, issuer, leaf *x509.Certificate, client, self Checked, services []string, now time.Time) (Grant, time.Time, string, error) {
	gr, ok := GrantOf(g)
	if !ok {
		return gr, time.Time{}, "format", errors.New("not a grant certificate")
	}
	chains, err := v.verify(g, issuer, "", now) // BIND:svc.grantsig
	switch {
	case !now.Before(g.NotAfter): // Grant.tla Open: now < until (crypto/x509 admits at NotAfter itself)
		return gr, time.Time{}, "expired", fmt.Errorf("the grant ended at %s", g.NotAfter.UTC().Format(time.RFC3339))
	case err != nil:
		return gr, time.Time{}, "chain", fmt.Errorf("the grant is not the organisation's: %w", err)
	case g.URIs[0].Host != Domain(v.orgID):
		return gr, time.Time{}, "chain", errors.New("the grant is another organisation's")
	case !bytes.Equal(g.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo), gr.Who != PrincipalOf(client): // BIND:svc.grantwho
		return gr, time.Time{}, "who", fmt.Errorf("the grant is %s's, not %s's", gr.Who, PrincipalOf(client))
	case !slices.Contains(services, gr.Service) || !matches(gr.Where, self): // BIND:svc.grantsvc
		return gr, time.Time{}, "service", fmt.Errorf("the grant is for %s/%s, not %s/%s", gr.Where, gr.Service, self.Name, strings.Join(services, ","))
	}
	iss, err := issuerOf(chains[0])
	if err != nil {
		return gr, time.Time{}, "chain", err
	}
	crl := v.crls[KeyFingerprint(iss.PublicKey)]
	switch {
	case crl == nil:
		return gr, time.Time{}, "nocrl", errors.New("no CRL of the grant's issuer: fail closed")
	case !now.Before(crl.next):
		return gr, time.Time{}, "lapsed", errors.New("the issuer's CRL lapsed: fail closed for grants")
	case crl.revoked[g.SerialNumber.String()]:
		return gr, time.Time{}, "revoked", fmt.Errorf("grant %s was revoked", gr.Serial)
	}
	until := crl.next
	for _, t := range []time.Time{client.Until, chains[0][0].NotAfter, chains[0][1].NotAfter, chains[0][len(chains[0])-1].NotAfter} {
		if t.Before(until) {
			until = t
		}
	}
	return gr, until, "", nil
}

// AdmitClient is a serving machine's admission of a client (agent.Org
// CheckClient; Identity and relay org orgmachine.Machine): certs are the
// client's certificate, its issuer's and, when it holds one, a grant. The
// certificate is checked (chain, NotAfter, CRL), then a rule of rules
// admits it, else the grant does (CheckGrant).
func AdmitClient(ver *Verifier, rules *Rules, certs []*x509.Certificate, self Checked, services []string, now time.Time) (time.Time, error) {
	until, _, err := admitClient(ver, rules, certs, self, services, now)
	return until, err
}

// AdmittedBy is what admits certs at now, as AdmitClient decides it, in
// an audit record's words (relay client/orgaudit Record.By): "rule <who>
// <where> <service>" or "grant <request> by <approver>"; "" when nothing
// does.
func AdmittedBy(ver *Verifier, rules *Rules, certs []*x509.Certificate, self Checked, services []string, now time.Time) string {
	_, by, err := admitClient(ver, rules, certs, self, services, now)
	if err != nil {
		return ""
	}
	return by
}

// admitClient is AdmitClient with what admitted (AdmittedBy's words).
func admitClient(ver *Verifier, rules *Rules, certs []*x509.Certificate, self Checked, services []string, now time.Time) (time.Time, string, error) {
	if len(certs) != 2 && len(certs) != 3 {
		return time.Time{}, "", errNoChain
	}
	id, err := ver.Check(certs[0], certs[1], Peer{}, now)
	if err != nil {
		return time.Time{}, "", err
	}
	until, rule, err := rules.admit(id, self, services, now)
	if err == nil || len(certs) == 2 {
		return until, "rule " + rule.Who + " " + rule.Where + " " + rule.Service, err
	}
	g, until, gerr := ver.CheckGrant(certs[2], certs[1], certs[0], id, self, services, now)
	if gerr != nil {
		return time.Time{}, "", fmt.Errorf("%w; its grant: %v", err, gerr)
	}
	return until, "grant " + g.Request + " by " + g.By, nil
}

// grantsIn are the grant certificates a signed status (relay org
// orgpki.SignedStatus, JSON) lists; unchecked (the serving agent checks
// the one presented).
func grantsIn(msg []byte) []*x509.Certificate {
	var sm struct {
		Body []byte `json:"body"`
	}
	var st struct {
		Grants []struct {
			Cert []byte `json:"cert"`
		} `json:"grants"`
	}
	if json.Unmarshal(msg, &sm) != nil || json.Unmarshal(sm.Body, &st) != nil {
		return nil
	}
	var cs []*x509.Certificate
	for _, g := range st.Grants {
		if c, err := x509.ParseCertificate(g.Cert); err == nil {
			cs = append(cs, c)
		}
	}
	return cs
}

// grantFor is the newest grant of the organisation's status in this
// machine's directory (status.json, the machine's keeper writes it) for
// this machine's key and service, unexpired at now: for the place where
// when there is one, else for any place (the server checks it).
func (m *Identity) grantFor(leaf *x509.Certificate, service, where string, now time.Time) *x509.Certificate {
	msg, err := os.ReadFile(filepath.Join(m.dir, StatusFile)) // #nosec G304 -- a file of the machine's own directory
	if err != nil {
		return nil
	}
	var best *x509.Certificate
	bestExact := false
	for _, c := range grantsIn(msg) {
		g, ok := GrantOf(c)
		if !ok || g.Service != service || !now.Before(c.NotAfter) || !bytes.Equal(c.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
			continue
		}
		exact := g.Where == where
		if best == nil || exact && !bestExact || exact == bestExact && c.NotAfter.After(best.NotAfter) {
			best, bestExact = c, exact
		}
	}
	return best
}

// ClientCertificate is the client certificate of a session to service at
// where ("machine:<name>" or "group:<group>"): this machine's chain, and
// after it a grant it holds for that service (the newest unexpired one in
// the status of StatusFile), so a server's grant check sees it; without
// one, the chain alone (a rule admits it or nothing does).
func (m *Identity) ClientCertificate(service, where string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := m.Certificate()
		if err != nil || cert == nil || cert.Leaf == nil {
			return cert, err
		}
		g := m.grantFor(cert.Leaf, service, where, time.Now())
		if g == nil {
			return cert, nil
		}
		withGrant := *cert
		withGrant.Certificate = append(slices.Clip(cert.Certificate), g.Raw)
		return &withGrant, nil
	}
}
