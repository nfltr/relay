// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgid is the read side of an organisation's own certificate
// authority for its machines (nfltr docs/decisions/org-enrolment-2026-11-09.md;
// models spec/proverif/e2ee_tcp.pv and spec/proverif/enrol.pv,
// spec/enrol/Enrol.tla): the checks every client and service runs on an
// organisation peer (Verifier: the chain to the organisation's root, the
// issuer's name constraints, NotAfter, the machine name, the groups and
// the issuer's CRL), this machine's enrolment as `nfltr org join` wrote it
// (Load: an Identity, which serves both halves of an organisation session:
// agent.Org and agent.DirectMachine), and following the issuer's CRL
// through the relay (Follow).
//
// It issues nothing: making roots, issuers and machine certificates,
// enrolment, renewal and the issuer stay in relay org (nfltr runs them). A
// machine where only an SDK program serves runs relay org orgenrol's
// Keeper itself: it renews, follows the CRL and ships the machine's audit
// log (Identity.Audit). It reads this machine's key only to present its
// certificate in TLS and sign its audit lines.
package orgid

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// The certificate profile's names (decision doc "Formats").
const (
	rootCNPrefix   = "nfltr org "
	recoverySuffix = " recovery"
	machineURIPath = "/machine/"
	appURIPath     = "/app/"
	nameURIPath    = "/name/"
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

var shortRE = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`) })

// ValidShortName reports whether s is an organisation's short name (nfltr
// docs/decisions/service-access-2026-11-25.md D2): one lowercase DNS label
// starting with a letter, at most 63 bytes, not "o-" (the id's prefix).
// org/orgpki keeps a copy of this rule (its tagged client may predate it).
func ValidShortName(s string) bool {
	return shortRE().MatchString(s) && !strings.HasPrefix(s, "o-")
}

// ShortName is the organisation's short name its root signs (the root's
// one URI SAN nfltr://<org id>.internal/name/<short>), or its id
// (OrgIDOfRoot) when it has none; "" when root is not an organisation
// root. The host goes unchecked: the root is the pinned anchor.
func ShortName(root *x509.Certificate) string {
	if s := uriID(root, nameURIPath); ValidShortName(s) {
		return s
	}
	id, _ := OrgIDOfRoot(root)
	return id
}

// MachineID is the A2A machine id a machine certificate carries (its URI
// SAN nfltr://<org id>.internal/machine/<id>), or "".
func MachineID(c *x509.Certificate) string { return uriID(c, machineURIPath) }

// AppOf is the app a device certificate was enrolled for (its URI SAN
// nfltr://<org id>.internal/app/<id>), or "" (nfltr
// docs/decisions/app-device-identity-2026-11-16.md).
func AppOf(c *x509.Certificate) string { return uriID(c, appURIPath) }

// PersonOf is the person a device certificate names (its one rfc822Name
// SAN, the IdP's verified email or the admin code's), or "": none, or more
// than one.
func PersonOf(c *x509.Certificate) string {
	if len(c.EmailAddresses) != 1 {
		return ""
	}
	return c.EmailAddresses[0]
}

// uriID is the id after path of the certificate's one nfltr URI SAN with
// that path, or "" (none, or more than one). The URI's host is checked
// against the organisation by Verifier.Check: the issuer's DNS name
// constraints do not cover URI SANs (crypto/x509 checks them against
// PermittedURIDomains only).
func uriID(c *x509.Certificate, path string) string {
	id := ""
	for _, u := range c.URIs {
		if v, ok := strings.CutPrefix(u.Path, path); ok && u.Scheme == "nfltr" {
			if id != "" {
				return ""
			}
			id = v
		}
	}
	return id
}

func subset(a, of []string) bool {
	for _, x := range a {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}
