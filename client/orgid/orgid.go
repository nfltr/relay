// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgid is the read side of an organisation's own certificate
// authority for its machines (nfltr docs/decisions/org-enrolment-2026-11-09.md;
// models spec/proverif/e2ee_tcp.pv and nfltr spec/proverif/enrol.pv,
// spec/enrol/Enrol.tla): the checks every client and service runs on an
// organisation peer (Verifier: the chain to the organisation's root, the
// issuer's name constraints, NotAfter, the machine name, the groups and
// the issuer's CRL), this machine's enrolment as `nfltr org join` wrote it
// (Load: an Identity, which serves both halves of an organisation session:
// agent.Org and agent.DirectMachine), and following the issuer's CRL
// through the relay (Follow).
//
// It issues nothing: making roots, issuers and machine certificates,
// enrolment, renewal and the issuer stay in nfltr. It reads this
// machine's key only to present its certificate in TLS.
package orgid

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
)

// The certificate profile's names (decision doc "Formats").
const (
	rootCNPrefix   = "nfltr org "
	recoverySuffix = " recovery"
	machineURIPath = "/machine/"
)

// Fingerprint is "sha256:" and the hex SHA-256 of a certificate's SPKI:
// the value provisioned beside a token (the root's, the recovery's).
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("sha256:%x", sum)
}

// KeyFingerprint is Fingerprint of a bare public key.
func KeyFingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("sha256:%x", sum)
}

// Domain is the DNS subtree the organisation's names live in.
func Domain(orgID string) string { return orgID + ".internal" }

// MachineDNS is a machine's DNS SAN, the TLS ServerName a client asks for.
func MachineDNS(name, orgID string) string { return name + "." + Domain(orgID) }

// OrgIDOfRoot reads the organisation's id from a root certificate's CN.
func OrgIDOfRoot(c *x509.Certificate) (string, error) {
	id, ok := strings.CutPrefix(c.Subject.CommonName, rootCNPrefix)
	if !ok || !strings.HasPrefix(id, "o-") || strings.HasSuffix(id, recoverySuffix) {
		return "", fmt.Errorf("certificate %q is not an organisation root", c.Subject.CommonName)
	}
	return id, nil
}

// MachineID is the A2A machine id a machine certificate carries (its URI
// SAN nfltr://<org id>.internal/machine/<id>: a URI with a host, which the
// issuer's name constraints cover), or "".
func MachineID(c *x509.Certificate) string {
	for _, u := range c.URIs {
		if id, ok := strings.CutPrefix(u.Path, machineURIPath); ok && u.Scheme == "nfltr" {
			return id
		}
	}
	return ""
}

func subset(a, of []string) bool {
	for _, x := range a {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}
