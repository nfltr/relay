// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// Session audit at the issuer (nfltr docs/decisions/service-access-2026-11-25.md
// "SA5: the record, its check, the names"; spec/proverif/svc_access.pv
// query 7, BIND:svc.auditsig): a machine's keeper posts its audit lines
// (client/orgaudit) on the enrol drop box sealed to the issuer's key, so
// the relay carries ciphertext only; the issuer takes a line only when
// the key that signed it is one it certified for the machine the line
// names (AuditChecker), and logs what it refused (ActAuditRefused).

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/client/orgid"
)

// ActAuditRefused is a batch of a machine's audit lines the issuer did
// not take in part: Name the machine they name, Number the first seq
// refused, Reason the first finding and how many lines it refused.
const ActAuditRefused = "audit-refused"

// AuditRequest is a machine's audit post: an AuditBatch sealed
// (crypto/hpke) to the issuer certificate's key.
type AuditRequest struct {
	Sealed []byte `json:"sealed"`
}

// AuditBatch is what an AuditRequest seals: lines of the machine's log
// in order, then its signed head (orgaudit.SignHead; alone, a beat).
type AuditBatch struct {
	Lines [][]byte `json:"lines,omitempty"`
	Head  []byte   `json:"head"`
}

// AuditAnswer is where the issuer stands in the head's log after the
// batch: the seq of the last line it holds.
type AuditAnswer struct {
	Log string `json:"log"`
	Seq uint64 `json:"seq"`
}

const auditSealLabel = "nfltr-org-audit-v1\x00"

func auditInfo(issuerKey ed25519.PublicKey) []byte {
	return slices.Concat([]byte(auditSealLabel), []byte(orgid.KeyFingerprint(issuerKey)))
}

// SealAudit seals b to issuer's key (the issuer certificate of the
// machine's chain).
func SealAudit(issuer *x509.Certificate, b AuditBatch) ([]byte, error) {
	edpub, ok := issuer.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("the issuer's key is not Ed25519")
	}
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	pub, err := x25519Public(edpub)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, err
	}
	kdf, aead := hpkeSuite()
	return hpke.Seal(pk, kdf, aead, auditInfo(edpub), plain)
}

// OpenAudit opens a batch sealed to this issuer's key.
func (i *Issuer) OpenAudit(sealed []byte) (AuditBatch, error) {
	priv, err := x25519Private(i.key)
	if err != nil {
		return AuditBatch{}, err
	}
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return AuditBatch{}, err
	}
	kdf, aead := hpkeSuite()
	plain, err := hpke.Open(sk, kdf, aead, auditInfo(i.key.Public().(ed25519.PublicKey)), sealed)
	if err != nil {
		return AuditBatch{}, errors.New("not an audit batch sealed to this issuer's key")
	}
	var b AuditBatch
	return b, json.Unmarshal(plain, &b)
}

// AuditChecker is an orgaudit.Checker whose signers are the
// certificates this issuer issued (its log: serial, name, key).
func (i *Issuer) AuditChecker() *orgaudit.Checker {
	i.mu.Lock()
	known := make(map[string]orgaudit.Signer, len(i.certs))
	for serial, c := range i.certs {
		known[serial] = orgaudit.Signer{Machine: c.name, Key: c.key}
	}
	i.mu.Unlock()
	return LogChecker(known)
}

// LogChecker is an orgaudit.Checker over known signers.
func LogChecker(known map[string]orgaudit.Signer) *orgaudit.Checker {
	return &orgaudit.Checker{
		Signers: func(s string) (orgaudit.Signer, bool) { v, ok := known[s]; return v, ok },
		KeyOf:   func(k ed25519.PublicKey) string { return orgid.KeyFingerprint(k) },
	}
}

// AuditSigners are the signers a verified log's entries certified
// (VerifyLog's entries): what a reader of the issuer's sessions checks
// them against without the issuer's key.
func AuditSigners(entries []Entry) map[string]orgaudit.Signer {
	known := map[string]orgaudit.Signer{}
	for _, e := range entries {
		switch e.Act {
		case ActIssued, ActRenewed, ActRebound, ActAdopted:
			known[e.Serial] = orgaudit.Signer{Machine: e.Name, Key: e.Key}
		}
	}
	return known
}

// RefuseAudit logs that the issuer did not take lines of machine from
// seq on, for reason.
func (i *Issuer) RefuseAudit(machine string, seq uint64, reason string, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.commit(Entry{Time: now, Act: ActAuditRefused, Name: machine, Number: int64(seq), Reason: reason}) // #nosec G115 -- a line's seq, far under 2^63
}
