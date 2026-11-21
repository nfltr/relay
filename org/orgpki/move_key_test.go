// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"bytes"
	"testing"
	"time"
)

// movedTo is web moved to mid by a renewal (its machine enrolled with the
// relay again), with its new key and the request.
func (o *org) movedTo(t *testing.T) (RenewRequest, []byte, []byte) {
	t.Helper()
	first, k := o.enrol(t, "web", "db")
	o.iss.SetMovePolicy(ownAccount)
	nk := newKey(t)
	rr := NewMoveRequest(first.Raw, k, csr(t, nk, "web"), mid)
	der, err := o.iss.Renew(rr, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return rr, der, nk
}

// a2a_keytransfer.pv Move (query 15, mutant move-unsigned-key; lane
// CERTGAPS): an issuer with an A2A root seals the new id's key into a
// move's answer, to the key it certified for that request, signed with
// the request; the moved machine opens it only as its own request's.
func TestMovedMachineOpensItsNewIDsKey(t *testing.T) {
	o := newOrg(t)
	rr, der, nk := o.movedTo(t)
	km := bytes.Repeat([]byte{9}, 32)
	sk, err := o.iss.SealMovedKey(rr, der, mid+".1", km)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenMachineKey(sk, MoveKeyID(rr), der, o.iss.Cert().Raw, o.rootCrt, nk, t0.Add(time.Hour))
	if err != nil || !bytes.Equal(got, km) {
		t.Fatalf("OpenMachineKey = %x, %v; want %x", got, err, km)
	}
	other := rr
	other.Sig = bytes.Repeat([]byte{1}, len(rr.Sig))
	if _, err := OpenMachineKey(sk, MoveKeyID(other), der, o.iss.Cert().Raw, o.rootCrt, nk, t0.Add(time.Hour)); err == nil {
		t.Fatal("opened as another request's answer")
	}
}

// The issuer seals a move's key only to the certificate it issued for that
// move request: not a plain renewal's, not the old certificate, not under
// another machine id (a2a_keytransfer.pv mv.sig, mv.new).
func TestSealMovedKeyOnlyForItsMove(t *testing.T) {
	o := newOrg(t)
	rr, der, _ := o.movedTo(t)
	km := bytes.Repeat([]byte{9}, 32)
	other := o.enrolKM(t, "web-2", "m-bbbbbbbbbbbbbbbbbbbbbbbbbb")
	renewed, err := o.iss.Renew(NewRenewRequest(other.cert, other.key, csr(t, newKey(t), "web-2")), t0)
	if err != nil {
		t.Fatal(err)
	}
	plain := NewRenewRequest(other.cert, other.key, csr(t, newKey(t), "web-2"))
	another := rr
	another.CSR = csr(t, newKey(t), "web")
	for _, tc := range []struct {
		name  string
		req   RenewRequest
		cert  []byte
		keyID string
	}{
		{"a plain renewal", plain, renewed, "m-bbbbbbbbbbbbbbbbbbbbbbbbbb.1"},
		{"another machine's certificate", rr, other.cert, mid + ".1"},
		{"another key than the request's", another, der, mid + ".1"},
		{"another machine's key id", rr, der, "m-bbbbbbbbbbbbbbbbbbbbbbbbbb.1"},
	} {
		if _, err := o.iss.SealMovedKey(tc.req, tc.cert, tc.keyID, km); err == nil {
			t.Errorf("%s: sealed; want refused", tc.name)
		}
	}
}
