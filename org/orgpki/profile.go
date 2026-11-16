// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgpki is an organisation's own certificate authority for its
// machines (models spec/proverif/enrol.pv and spec/enrol/Enrol.tla): the
// x509 profile, the
// issuer (single-use tokens, enrolment, renewal, revocation, CRLs, the
// hash-chained audit log) and root rotation by the recovery key. The
// verifier every client and service runs, and the profile's read side
// (fingerprints, names, a root's organisation id), are the relay client's
// orgid, which this package uses too. It is pure: keys and the log's
// storage come from the caller, the root primary behind crypto.Signer (a
// Secure Enclave key on the owner's Mac or a passphrase-encrypted file
// elsewhere, a software key in tests).
package orgpki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// Lifetimes.
const (
	RootLife    = 10 * 365 * 24 * time.Hour
	IssuerLife  = 30 * 24 * time.Hour
	MachineLife = 24 * time.Hour
	CRLLife     = time.Hour
)

const (
	rootCNPrefix   = "nfltr org "
	recoverySuffix = " recovery"
	machineURIPath = "/machine/"
	appURIPath     = "/app/"
)

var (
	labelRE = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`) })
	b32     = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// OrgID is "o-" and 26 base32 characters of SHA-256 over the root's SPKI.
// It is fixed at init: a rotated root keeps the organisation's id.
func OrgID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "o-" + strings.ToLower(b32.EncodeToString(sum[:16])), nil
}

// ValidLabel checks a machine name or a group: one lowercase DNS label.
func ValidLabel(kind, s string) error {
	if !labelRE().MatchString(s) {
		return fmt.Errorf("%s %q is not a lowercase DNS label (a-z, 0-9, -; at most 63)", kind, s)
	}
	return nil
}

func validGroups(groups []string) error {
	if len(groups) == 0 {
		return errors.New("at least one group")
	}
	for _, g := range groups {
		if err := ValidLabel("group", g); err != nil {
			return err
		}
	}
	return nil
}

// Device is the person and the app a device's certificate is for (nfltr
// docs/decisions/app-device-identity-2026-11-16.md): the person as an
// rfc822Name SAN, the app as the URI SAN nfltr://<org domain>/app/<app>.
// Either may be "" (none); a plain machine has neither.
type Device struct {
	Person string // an email address, lowercased
	App    string // a lowercase DNS label
}

// valid returns d with its person lowercased, or an error.
func (d Device) valid() (Device, error) {
	if d.Person != "" {
		d.Person = strings.ToLower(d.Person)
		if a, err := mail.ParseAddress(d.Person); err != nil || a.Address != d.Person || a.Name != "" {
			return d, fmt.Errorf("person %q is not a bare email address", d.Person)
		}
	}
	if d.App != "" {
		if err := ValidLabel("app", d.App); err != nil {
			return d, err
		}
	}
	return d, nil
}

// validMachineID: "" (none) or an id that needs no escaping in a URI path.
func validMachineID(id string) error {
	if len(id) > 128 || url.PathEscape(id) != id || strings.Contains(id, "/") {
		return fmt.Errorf("machine id %q: at most 128 characters that need no escaping in a URI path", id)
	}
	return nil
}

func subset(a, of []string) bool {
	for _, x := range a {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func rootName(orgID string) pkix.Name { return pkix.Name{CommonName: rootCNPrefix + orgID} }

func create(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewRoot makes the self-signed root under the root primary. orgID is
// OrgID(signer.Public()) at init.
func NewRoot(signer crypto.Signer, orgID string, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber: sn, Subject: rootName(orgID),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(RootLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	return create(t, t, signer.Public(), signer)
}

// NewRecovery makes the recovery key's self-signed certificate; its
// fingerprint is pinned beside the root's.
func NewRecovery(key ed25519.PrivateKey, orgID string, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: rootCNPrefix + orgID + recoverySuffix},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(RootLife),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	return create(t, t, key.Public(), key)
}

// CrossSign is a rotation: the recovery key certifies a new root primary
// (Subject the organisation's root name, Issuer the recovery). Verifiers
// take it as their new root (Verifier.TakeRotation).
func CrossSign(recovery *x509.Certificate, recoveryKey ed25519.PrivateKey, newRoot crypto.PublicKey, orgID string, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber: sn, Subject: rootName(orgID),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(RootLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	return create(t, recovery, newRoot, recoveryKey)
}

// CertifyIssuer is the owner's policy for the issuer, signed by the root
// primary: names under the organisation's domain only, the groups it may
// issue, IssuerLife.
func CertifyIssuer(root *x509.Certificate, rootSigner crypto.Signer, issuer ed25519.PublicKey, groups []string, now time.Time) (*x509.Certificate, error) {
	orgID, err := orgid.OrgIDOfRoot(root)
	if err != nil {
		return nil, err
	}
	if err := validGroups(groups); err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: rootCNPrefix + orgID + " issuer", OrganizationalUnit: slices.Clone(groups)},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(IssuerLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{orgid.Domain(orgID)},
		// URI SANs (machine and app ids) too: the DNS constraint does not
		// cover them (finding F1, docs/decisions/app-device-identity-2026-11-16.md).
		PermittedURIDomains: []string{orgid.Domain(orgID)},
	}
	return create(t, root, issuer, rootSigner)
}

// machineTemplate is a machine's leaf: CN the name, DNS SAN, OU the groups,
// the machine id and the device's app as URI SANs, its person as rfc822Name
// SAN, both TLS uses, NotAfter capped by the issuer's own.
func machineTemplate(orgID, name string, groups []string, machineID string, dev Device, issuer *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(MachineLife)
	if issuer.NotAfter.Before(notAfter) {
		notAfter = issuer.NotAfter
	}
	t := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: name, OrganizationalUnit: slices.Clone(groups)},
		DNSNames:     []string{orgid.MachineDNS(name, orgID)},
		NotBefore:    now.Add(-time.Minute), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if machineID != "" {
		if err := validMachineID(machineID); err != nil {
			return nil, err
		}
		t.URIs = []*url.URL{{Scheme: "nfltr", Host: orgid.Domain(orgID), Path: machineURIPath + machineID}}
	}
	if dev.App != "" {
		t.URIs = append(t.URIs, &url.URL{Scheme: "nfltr", Host: orgid.Domain(orgID), Path: appURIPath + dev.App})
	}
	if dev.Person != "" {
		t.EmailAddresses = []string{dev.Person}
	}
	return t, nil
}

// checkRotation checks a new root c as every verifier does
// (orgid.Verifier.TakeRotation, enrol.pv query 8): the recovery key's
// certificate of the organisation's root name, a CA, newer than current,
// for another key. The issuer takes no rotation its machines would refuse.
func checkRotation(c, recovery, current *x509.Certificate) error {
	v, err := orgid.NewVerifier(current, recovery, orgid.Fingerprint(current), orgid.Fingerprint(recovery))
	if err != nil {
		return err
	}
	return v.TakeRotation(c.Raw)
}
