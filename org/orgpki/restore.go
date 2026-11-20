// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// A restore from a backup (spec/orgmove/OrgMove.tla Revive): a copy of the
// issuer directory of any age serves again only after it takes the newest
// CRL the fleet holds, so that what members saw never goes backwards. The
// restored line resumes the CRL Number at that CRL's (the next one is
// above every published one: CRLMonotone, mutant
// number-not-above-published), lists that CRL's serials in every CRL until
// they expire (RevokedStaysRevoked, merge-skipped; a serial is listed
// MachineLife on, which outlives every certificate issued before the
// restore), and voids every token made before it (TokenOnce,
// revive-keeps-tokens: the lost issuer may have redeemed it). A machine
// that renewed after the copy holds a certificate the copy never saw;
// Renew adopts it (adoptable) so it renews on its own.

// ErrNotLapsed: a restore takes only a CRL whose NextUpdate has passed, so
// no other issuer (the lost machine) still publishes.
var ErrNotLapsed = errors.New("the published CRL has not lapsed: an issuer may still publish (delete the old machine first; restore once it lapses)")

// Restore commits the restored line from crl, the newest CRL the relay
// holds for the organisation (orgenrol.PublishedRevocationList): it must
// be signed by this issuer's key and lapsed at now. Run before the fence
// (nfltr org move send --restored); after it commit refuses it.
func (i *Issuer) Restore(crlDER []byte, now time.Time) error {
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("the published CRL: %w", err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := crl.CheckSignatureFrom(i.cert); err != nil {
		return fmt.Errorf("the published CRL is not this issuer's (rotated or renewed to another key since the copy: not restorable): %w", err)
	}
	if crl.Number == nil || !crl.Number.IsInt64() || crl.Number.Sign() < 0 {
		return errors.New("the published CRL has no Number")
	}
	if crl.Number.Int64() < i.crlNumber {
		return fmt.Errorf("the relay holds CRL #%s, older than the copy's own #%d: not the newest the fleet holds; not restored", crl.Number, i.crlNumber)
	}
	if now.Before(crl.NextUpdate) {
		return fmt.Errorf("%w: CRL #%s lapses at %s", ErrNotLapsed, crl.Number, crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	sns := []string{}
	for _, e := range crl.RevokedCertificateEntries {
		sns = append(sns, hex.EncodeToString(e.SerialNumber.Bytes()))
	}
	return i.commit(Entry{Time: now, Act: ActRestored, Number: crl.Number.Int64(), NotAfter: crl.NextUpdate, Serials: sns})
}

// applyRestored is apply's restored line.
func (i *Issuer) applyRestored(e Entry) {
	i.crlNumber = max(i.crlNumber, e.Number)
	i.crlNext, i.crlDue, i.restoredAt = e.NotAfter, true, e.Time
	for _, t := range i.tokens {
		t.void = true
	}
	if i.carried == nil {
		i.carried = map[string]time.Time{}
	}
	for _, sn := range e.Serials {
		i.carried[sn] = e.Time.Add(MachineLife)
	}
}

// carriedSerials are the serials a restore took that are listed at now
// and not in listed already.
func (i *Issuer) carriedSerials(listed map[string]bool, now time.Time) []string {
	var out []string
	for sn, until := range i.carried {
		if now.Before(until) && !listed[sn] {
			out = append(out, sn)
		}
	}
	slices.Sort(out)
	return out
}

// adoptable: cur, a certificate not in the log, is one the lost issuer
// issued after the copy, which a restore accepts as the name's newest: the
// log holds a restore, cur predates it (every later certificate is in the
// log), this issuer's key signed it (no one else holds it), and it is of a
// name the log enrolled, not revoked, under the same relay machine id (a
// rebind after the copy is not adopted: its old serials are in the CRL
// the restore took, so the name re-binds with nfltr org token --rebind).
// Callers hold mu.
func (i *Issuer) adoptable(cur *x509.Certificate) (*nameRec, bool) {
	if i.restoredAt.IsZero() || !cur.NotBefore.Before(i.restoredAt) || cur.CheckSignatureFrom(i.cert) != nil {
		return nil, false
	}
	n := i.names[cur.Subject.CommonName]
	if n == nil || n.revoked || i.deniedDev(n.dev) || orgid.MachineID(cur) != n.machineID {
		return nil, false
	}
	return n, true
}

// adopt commits the adopted line of cur (der) for name n. Callers hold mu.
func (i *Issuer) adopt(cur *x509.Certificate, der []byte, n *nameRec, now time.Time) error {
	sum := sha256.Sum256(der)
	return i.commit(Entry{Time: now, Act: ActAdopted, Name: cur.Subject.CommonName, Groups: slices.Clone(n.groups), MachineID: n.machineID,
		Person: n.dev.Person, App: n.dev.App, Serial: hex.EncodeToString(cur.SerialNumber.Bytes()),
		Key: orgid.KeyFingerprint(cur.PublicKey), Digest: hex.EncodeToString(sum[:]), NotAfter: cur.NotAfter})
}
