// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"golang.org/x/crypto/ssh"
)

// SSH host certificates of the organisation's machines (`nfltr cat serve
// --ssh` serves them). The SSH CA is the issuer's own
// Ed25519 key: no second key, and the x509 chain (root -> issuer) already
// certifies it. A host certificate restates one machine certificate of the
// issuer's log: the same key, its DNS SAN as the only principal, the same
// lifetime. Signing both formats with one key is safe because no message is
// both: x509 and CRL to-be-signed bytes are DER (0x30 first), SSH
// certificate bytes begin with the uint32 length of their type (0x00), the
// checkpoint and the sealed-key messages with their ASCII labels.

// HostCert signs the SSH host certificate of leafDER, a certificate of this
// issuer's log (as issued, of a name not revoked, not expired at now). It
// never takes a name or key from anywhere else: a certificate for another
// machine's name is one the issuer would have to have issued.
func (i *Issuer) HostCert(leafDER []byte, now time.Time) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(leafDER)
	rec := i.certs[hex.EncodeToString(leaf.SerialNumber.Bytes())]
	switch {
	case rec == nil || rec.digest != hex.EncodeToString(sum[:]):
		return nil, fmt.Errorf("%w: the certificate is not in the issuer's log", ErrRefused)
	case i.names[rec.name].revoked:
		return nil, fmt.Errorf("%w: %s is revoked", ErrRefused, rec.name)
	case !now.Before(rec.notAfter):
		return nil, fmt.Errorf("%w: the certificate expired", ErrRefused)
	}
	pub, err := ssh.NewPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	c := &ssh.Certificate{
		Key:             pub,
		Serial:          HostSerial(leaf.SerialNumber),
		CertType:        ssh.HostCert,
		KeyId:           rec.name,
		ValidPrincipals: []string{orgid.MachineDNS(rec.name, i.orgID)},
		ValidAfter:      uint64(leaf.NotBefore.Unix()), // #nosec G115 -- a certificate's time, after 1970
		ValidBefore:     uint64(leaf.NotAfter.Unix()),  // #nosec G115 -- likewise
	}
	ca, err := ssh.NewSignerFromKey(i.key)
	if err != nil {
		return nil, err
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return c.Marshal(), nil
}

// HostCA is the SSH form of an issuer certificate's key: the key a
// known_hosts @cert-authority line names.
func HostCA(issuer *x509.Certificate) (ssh.PublicKey, error) {
	if _, ok := issuer.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("the issuer key is not Ed25519")
	}
	return ssh.NewPublicKey(issuer.PublicKey)
}

// CheckHostCert checks raw, an SSH host certificate a machine got with
// leaf: signed by issuer's key, for leaf's key, leaf's DNS name its only
// principal, leaf's lifetime. Time itself is not checked here (OpenSSH
// checks it; a machine renews before it).
func CheckHostCert(raw []byte, leaf, issuer *x509.Certificate) (*ssh.Certificate, error) {
	k, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	c, ok := k.(*ssh.Certificate)
	if !ok || c.CertType != ssh.HostCert {
		return nil, errors.New("not an SSH host certificate")
	}
	ca, err := HostCA(issuer)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(leaf.DNSNames) != 1 {
		return nil, errors.New("the machine certificate has no single DNS name")
	}
	switch {
	case !slices.Equal(c.Key.Marshal(), pub.Marshal()):
		return nil, errors.New("the host certificate is not for the machine's key")
	case !slices.Equal(c.ValidPrincipals, leaf.DNSNames):
		return nil, fmt.Errorf("the host certificate names %v, not %s", c.ValidPrincipals, leaf.DNSNames[0])
	case c.ValidAfter != uint64(leaf.NotBefore.Unix()) || c.ValidBefore != uint64(leaf.NotAfter.Unix()): // #nosec G115 -- certificate times
		return nil, errors.New("the host certificate's lifetime is not the machine certificate's")
	}
	checker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool { return slices.Equal(auth.Marshal(), ca.Marshal()) },
		Clock:           func() time.Time { return leaf.NotBefore },
	}
	if err := checker.CheckCert(leaf.DNSNames[0], c); err != nil {
		return nil, err
	}
	if !checker.IsHostAuthority(c.SignatureKey, "") {
		return nil, errors.New("the host certificate is not signed by the issuer")
	}
	return c, nil
}
