// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// FreshMin is the least freshness bound a service may set (nfltr up
// fresh:, FreshBound): the age at which a machine warns its CRL is late.
// A shorter bound cuts the service's sessions at every hourly re-sign while
// the issuer is up (the re-sign comes at the CRL's age of an hour, the
// relay's copy up to FollowEvery and the issuer's put later:
// spec/enrol/CrlCarriers.tla FreshQuiet, mutant fresh-short).
const FreshMin = CRLWarnAge

// FreshBound bounds an admission (until, AdmitClient's for certs at now)
// by fresh: refused once the CRL of certs' issuer this machine holds was
// signed (its ThisUpdate) fresh ago or more, else until is no later than
// that ThisUpdate + fresh. A newer CRL taken is a change (Changed), whose
// check moves until again; a withheld one cuts the session at the bound
// (spec/enrol/CrlCarriers.tla FreshBound, mutant fresh-ignored).
func (v *Verifier) FreshBound(certs []*x509.Certificate, fresh time.Duration, until, now time.Time) (time.Time, error) {
	if len(certs) < 2 {
		return time.Time{}, errNoChain
	}
	v.mu.Lock()
	crl := v.crls[KeyFingerprint(certs[1].PublicKey)]
	v.mu.Unlock()
	if crl == nil {
		return time.Time{}, errors.New("no CRL of the issuer: fail closed")
	}
	end := crl.this.Add(fresh)
	if !now.Before(end) {
		return time.Time{}, fmt.Errorf("the organisation's CRL this machine holds was signed %s ago, past this service's bound (fresh: %s): fail closed until a newer one arrives (nfltr org status on the issuer's machine says why it is not re-signing or not reaching the relay)",
			now.Sub(crl.this).Round(time.Second), fresh)
	}
	if end.Before(until) {
		until = end
	}
	return until, nil
}
