// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

// Each test names the model property it enforces (nfltr
// spec/proverif/enrol.pv query, spec/enrol/Enrol.tla invariant) and the
// planted bug in testdata/mutants.txt that makes it fail
// (scripts/go-mutants.sh, make test-go-mutants). The verifier's halves of
// nfltr orgpki's tests of the same names; the issuer's halves stay there.

func TestHonestMachineChecks(t *testing.T) {
	o := newTestOrg(t, t0)
	web, _ := o.enrol(t, "web-1", "web")
	o.takeCRL(t, t0)
	id, err := o.ver.Check(web, o.iss, Peer{Name: "web-1"}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "web-1" || id.MachineID != "m-web-1" || !id.Until.Equal(t0.Add(crlLife)) {
		t.Fatalf("identity %+v", id)
	}
}

// enrol.pv 1 and 2 (no name without the root; web is web): mutants
// no-chain-check, no-name-check.
func TestForgedNameRefused(t *testing.T) {
	o := newTestOrg(t, t0)
	web, _ := o.enrol(t, "web-1", "web")
	other, _ := o.enrol(t, "web-2", "web")
	o.takeCRL(t, t0)
	at := t0.Add(time.Minute)

	// A peer with web-2's real certificate is not web-1.
	_, err := o.ver.Check(other, o.iss, Peer{Name: "web-1"}, at)
	refused(t, "web-2 as web-1", err)

	// A certificate for web-1 from an issuer the root never certified.
	rogue := newTestOrg(t, t0)
	rogue.orgID = o.orgID
	rogueRoot, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogue.root, rogue.rootKey = rootCert(t, o.orgID, rogueRoot.Public(), nil, rogueRoot, t0), rogueRoot
	rogue.certifyIssuer(t, t0)
	forged, _ := rogue.enrol(t, "web-1", "web")
	// The relay also carries the rogue issuer's own CRL.
	rogueCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: t0, NextUpdate: t0.Add(crlLife)}, rogue.iss, rogue.issKey)
	check(t, err)
	refused(t, "the rogue issuer's CRL", o.ver.TakeCRL(rogueCRL, rogue.iss, at))
	_, err = o.ver.Check(forged, rogue.iss, Peer{Name: "web-1"}, at)
	refused(t, "web-1 under a rogue issuer", err)

	// The issuer's own key signing a name outside the organisation's domain
	// (the root's NameConstraints bound a misbehaving or stolen issuer).
	outside := mint(t, leafTemplate(t, "o-elsewhere", "web-1", []string{"web"}, t0), o.iss, newKey(t).Public(), o.issKey)
	_, err = o.ver.Check(outside, o.iss, Peer{}, at)
	refused(t, "a name outside the organisation's domain", err)

	if _, err := o.ver.Check(web, o.iss, Peer{Name: "web-1"}, at); err != nil {
		t.Fatalf("honest web-1: %v", err)
	}
}

// enrol.pv 3, Enrol.tla NoExpiredSession: an expired certificate is
// refused (mutant no-expiry-check).
func TestExpiredRefused(t *testing.T) {
	o := newTestOrg(t, t0)
	web, _ := o.enrol(t, "web-1", "web")
	late := web.NotAfter.Add(time.Second)
	o.takeCRL(t, late)
	_, err := o.ver.Check(web, o.iss, Peer{Name: "web-1"}, late)
	refused(t, "an expired certificate", err)
}

// enrol.pv 4, Enrol.tla RevokedMachineRefused: every certificate of a
// revoked machine on the CRL is refused (mutant no-crl-check).
func TestRevokedRefused(t *testing.T) {
	o := newTestOrg(t, t0)
	first, _ := o.enrol(t, "lost", "db")
	second, _ := o.enrol(t, "lost", "db") // its renewal
	o.revoke(first)
	o.revoke(second)
	at := t0.Add(2 * time.Hour)
	o.takeCRL(t, at)
	for name, c := range map[string]*x509.Certificate{"the renewed certificate": second, "the certificate before the renewal": first} {
		_, err := o.ver.Check(c, o.iss, Peer{Group: "db"}, at)
		refused(t, name, err)
	}
}

// A machine is checked for a group its certificate holds, inside the
// issuer's policy (mutants no-group-check, leaf-group-outside-issuer).
func TestGroupOutsidePolicyRefused(t *testing.T) {
	o := newTestOrg(t, t0)
	web, _ := o.enrol(t, "web-1", "web")
	o.takeCRL(t, t0)
	at := t0.Add(time.Minute)
	_, err := o.ver.Check(web, o.iss, Peer{Group: "db"}, at)
	refused(t, "a web machine at a db service", err)

	// A leaf whose OU is outside the issuer's (an issuer bug): refused.
	bad, _ := o.enrol(t, "web-9", "ops")
	_, err = o.ver.Check(bad, o.iss, Peer{Name: "web-9"}, at)
	refused(t, "a group outside the issuer's policy", err)
}

// Enrol.tla RevocationBound (fail closed) and accept-older-crl, enrol.pv
// stale-crl: no CRL, a lapsed CRL and a replayed older CRL (mutants
// fail-open, accept-older-crl).
func TestLapsedCRLRefused(t *testing.T) {
	o := newTestOrg(t, t0)
	web, _ := o.enrol(t, "web-1", "web")
	_, err := o.ver.Check(web, o.iss, Peer{Name: "web-1"}, t0)
	refused(t, "no CRL", err)

	old := o.crl(t, t0)
	check(t, o.ver.TakeCRL(old, o.iss, t0))
	_, err = o.ver.Check(web, o.iss, Peer{Name: "web-1"}, t0.Add(crlLife))
	refused(t, "a CRL at its NextUpdate", err)
	refused(t, "taking a lapsed CRL", o.ver.TakeCRL(old, o.iss, t0.Add(crlLife)))

	// A revoke, then the relay replays the CRL from before it.
	at := t0.Add(10 * time.Minute)
	o.revoke(web)
	o.takeCRL(t, at)
	refused(t, "a replayed older CRL", o.ver.TakeCRL(old, o.iss, at))
	_, err = o.ver.Check(web, o.iss, Peer{Name: "web-1"}, at)
	refused(t, "the revoked machine after the replay", err)
}

// enrol.pv 8 and 9, Enrol.tla RootsAreOwners, SessionsOnTrustedRoot,
// MachinesFollowRotation: only the recovery key rotates the root, never
// back to an older one (mutants rotate-by-primary, replayed-rotation).
func TestRotationOnlyByRecoveryKey(t *testing.T) {
	o := newTestOrg(t, t0)
	web, _ := o.enrol(t, "web-1", "web")
	at := t0.Add(time.Hour)

	// The stolen primary: a "root" signed by a thief's own self-signed
	// recovery look-alike, and one signed by the old primary itself.
	thief := newTestOrg(t, t0)
	thief.orgID = o.orgID
	evilKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	evil := rootCert(t, o.orgID, evilKey.Public(), thief.rec, thief.recKey, at)
	refused(t, "a rotation not signed by the recovery key", o.ver.TakeRotation(evil.Raw))
	primSigned := rootCert(t, o.orgID, evilKey.Public(), o.root, o.rootKey, at)
	refused(t, "a rotation signed by the old primary", o.ver.TakeRotation(primSigned.Raw))

	// The owner's rotation, by the recovery key.
	oldIssuer := o.iss
	cross := o.rotate(t, at)
	check(t, o.ver.TakeRotation(cross.Raw))
	refused(t, "the same rotation again", o.ver.TakeRotation(cross.Raw))
	// A second rotation, then the relay replays the first.
	at2 := at.Add(time.Hour)
	cross2 := o.rotate(t, at2)
	check(t, o.ver.TakeRotation(cross2.Raw))
	refused(t, "a replayed older rotation", o.ver.TakeRotation(cross.Raw))
	o.takeCRL(t, at2)
	_, err := o.ver.Check(web, oldIssuer, Peer{Name: "web-1"}, at2)
	refused(t, "a certificate under the old root", err)

	// web renewed under the new root checks.
	renewed, _ := o.enrol(t, "web-1", "web")
	if _, err := o.ver.Check(renewed, o.iss, Peer{Name: "web-1"}, at2); err != nil {
		t.Fatalf("web-1 renewed under the new root: %v", err)
	}
	if !o.ver.Root().Equal(cross2) {
		t.Fatal("Root is not the rotated root")
	}
}
