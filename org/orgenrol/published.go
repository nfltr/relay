// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgpki"
)

// What members read, as against what the issuer holds: the relay may
// refuse the issuer's publish while the issuer's own CRL stays current,
// and members fail closed once the CRL they read lapses.

const (
	// PublishGrace: how long a CRL the issuer signed may take to reach
	// the relay (Service.Run publishes each round, serveWait apart).
	PublishGrace = 2 * time.Minute
	// PublishAlarm: a publish failing this long is logged as alarmMsg.
	PublishAlarm = 5 * time.Minute
	// publishFailingFile, in the issuer directory: the failing publish's
	// PublishFailure while it fails; removed by the next publish.
	publishFailingFile = "publish-failing.json"
	alarmMsg           = "org issuer: PUBLISH FAILING: members refuse every organisation session once the CRL they hold lapses"
)

// PublishedCRL is the CRL of root's organisation as a member reads it
// from the relay (the broadcast orgid.CRLMailbox, newest message): its
// number and NextUpdate. It is an error unless the issuer certificate the
// message carries verifies under root at now and signed the CRL, as
// members check it (orgid.Verifier.TakeCRL): a relay's forged issuer, or
// an expired one members refuse while the CRL is still current. root is
// the organisation root the caller trusts (a member's
// orgid.Identity.Verifier().Root(), the issuer's Root()). mb declares
// member on an organisation's mailboxes (transportcli.DeclareOrg).
func PublishedCRL(ctx context.Context, mb Mailbox, root *x509.Certificate, now time.Time) (number int64, next time.Time, err error) {
	orgID, err := orgid.OrgIDOfRoot(root)
	if err != nil {
		return 0, time.Time{}, err
	}
	data, err := latest(ctx, mb, orgid.CRLMailbox(orgID), 0)
	if err == nil && data == nil {
		err = errNoMessage
	}
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("read the published CRL: %w", err)
	}
	var m orgid.CRLMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return 0, time.Time{}, fmt.Errorf("the published CRL: %w", err)
	}
	iss, err := x509.ParseCertificate(m.Issuer)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("the published CRL's issuer: %w", err)
	}
	crl, err := x509.ParseRevocationList(m.CRL)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("the published CRL: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := iss.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return 0, time.Time{}, fmt.Errorf("the published CRL's issuer certificate (valid %s to %s): members refuse it: %w (expired: nfltr org issuer renew)",
			iss.NotBefore.UTC().Format(time.RFC3339), iss.NotAfter.UTC().Format(time.RFC3339), err)
	}
	if err := crl.CheckSignatureFrom(iss); err != nil {
		return 0, time.Time{}, fmt.Errorf("the published CRL: %w", err)
	}
	return crl.Number.Int64(), crl.NextUpdate, nil
}

// PublishedLate is an error when a published CRL whose NextUpdate is next
// is lapsed at now, or was due to be replaced more than PublishGrace ago
// (the issuer signs its successor with orgpki.CRLLife/3 left,
// Service.maintain): its successor was not published.
func PublishedLate(next, now time.Time) error {
	left := next.Sub(now)
	switch {
	case left <= 0:
		return fmt.Errorf("the published CRL lapsed at %s: every organisation session is refused until the issuer publishes a new one", next.UTC().Format(time.RFC3339))
	case left < orgpki.CRLLife/3-PublishGrace:
		return fmt.Errorf("the published CRL lapses at %s and its successor, due %s ago, is not published: is the issuer serving and its publish accepted?", next.UTC().Format(time.RFC3339), (orgpki.CRLLife/3 - left).Round(time.Second))
	}
	return nil
}

// PublishFailure is a failing publish of the CRL or the root: since when,
// and the latest error.
type PublishFailure struct {
	Since time.Time `json:"since"`
	Error string    `json:"error"`
}

// PublishFailing is the issuer directory dir's failing publish, if one is
// failing now (as its serving process last recorded it).
func PublishFailing(dir string) (PublishFailure, bool) {
	var p PublishFailure
	data, err := os.ReadFile(filepath.Join(dir, publishFailingFile)) // #nosec G304 -- the issuer directory's own file
	return p, err == nil && json.Unmarshal(data, &p) == nil
}

// maintained records a round's maintain error (nil: the CRL and root are
// published): the first failure's time and the latest error in
// publishFailingFile, a warning, and alarmMsg once it has failed for
// PublishAlarm; a success removes the record.
func (s *service) maintained(err error, now time.Time) {
	if err == nil {
		if !s.failingSince.IsZero() {
			s.Logger.Info("org issuer: the CRL and root are published again", "failing_since", s.failingSince)
			s.failingSince = time.Time{}
			_ = os.Remove(filepath.Join(s.Dir, publishFailingFile))
		}
		return
	}
	if s.failingSince.IsZero() {
		s.failingSince = now
	}
	if data, jerr := json.Marshal(PublishFailure{Since: s.failingSince, Error: err.Error()}); jerr == nil {
		if werr := orgfiles.Write(filepath.Join(s.Dir, publishFailingFile), data, 0o600); werr != nil {
			err = errors.Join(err, werr)
		}
	}
	if now.Sub(s.failingSince) >= PublishAlarm {
		s.Logger.Error(alarmMsg, "failing_since", s.failingSince, "error", err)
		return
	}
	s.Logger.Warn("org issuer: CRL or root not published (again shortly)", "error", err)
}

// PublishIssuers publishes der, the root's CRL of issuers
// (orgpki.SignIssuerCRL), from the root's machine into the organisation's
// root mailbox beside the root and recovery the relay holds there, which
// must be root (a relay's other root, or a rotation since, is refused).
// For a revoke the revoked issuer would not publish; a running issuer
// service keeps the newer one it finds there.
func PublishIssuers(ctx context.Context, mb Mailbox, root *x509.Certificate, der []byte, wait time.Duration) error {
	orgID, err := orgid.OrgIDOfRoot(root)
	if err != nil {
		return err
	}
	data, err := latest(ctx, mb, orgpki.RootMailbox(orgID), wait)
	if err == nil && data == nil {
		err = errNoMessage
	}
	if err != nil {
		return fmt.Errorf("the organisation's root: %w", err)
	}
	var rm orgpki.RootMessage
	if err := json.Unmarshal(data, &rm); err != nil {
		return err
	}
	if !bytes.Equal(rm.Root, root.Raw) {
		return errors.New("the relay holds another root than this machine's: nothing was published")
	}
	n := issuersNumber(der, root)
	if n == nil {
		return errors.New("not a CRL of issuers this root signed: nothing was published")
	}
	if held := issuersNumber(rm.Issuers, root); held != nil && held.Cmp(n) >= 0 {
		return fmt.Errorf("the relay holds CRL of issuers %s, not older than this one (%s): nothing was published", held, n)
	}
	rm.Issuers = der
	out, err := json.Marshal(rm)
	if err != nil {
		return err
	}
	_, err = mb.Append(ctx, orgpki.RootMailbox(orgID), out, mailboxclient.AppendOptions{ReplaceKey: "current", ContentType: "application/json"})
	return err
}
