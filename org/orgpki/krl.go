// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/stripe/krl"
)

// hostSerial is the SSH host certificate serial of a machine certificate's
// X.509 serial: its top 64 bits (of the 128 the issuer draws).
func hostSerial(sn *big.Int) uint64 {
	return binary.BigEndian.Uint64(sn.FillBytes(make([]byte, 16)))
}

// HostKRL is the OpenSSH key revocation list (PROTOCOL.krl) of crlDER, a
// CRL the verifier took from issuer: the host certificate serials of its
// entries under the issuer's SSH CA key, for ssh's RevokedHostKeys. Its
// version is the CRL's
// number and its date the CRL's ThisUpdate, so one CRL makes one KRL.
func HostKRL(crlDER []byte, issuer *x509.Certificate) ([]byte, error) {
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, err
	}
	if crl.Number == nil {
		return nil, errors.New("CRL has no number")
	}
	ca, err := HostCA(issuer)
	if err != nil {
		return nil, err
	}
	var serials krl.KRLCertificateSerialList
	for _, e := range crl.RevokedCertificateEntries {
		// ssh-keygen refuses serial 0, and ssh refuses every host when it
		// cannot read the KRL: leave it out (2^-64 per certificate).
		if s := hostSerial(e.SerialNumber); s != 0 {
			serials = append(serials, s)
		}
	}
	k := krl.KRL{
		Version:       crl.Number.Uint64(),
		GeneratedDate: uint64(crl.ThisUpdate.Unix()), // #nosec G115 -- a CRL's time, after 1970
		Sections:      []krl.KRLSection{&krl.KRLCertificateSection{CA: ca, Sections: []krl.KRLCertificateSubsection{&serials}}},
	}
	return k.Marshal(rand.Reader)
}

// KRLDate is a KRL's generated_date, 0 when data is not a KRL.
func KRLDate(data []byte) uint64 {
	k, err := krl.ParseKRL(data)
	if err != nil {
		return 0
	}
	return k.GeneratedDate
}
