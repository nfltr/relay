// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
)

// An outage (2026-11-14): the relay refused the issuer's CRL publish while the issuer's own CRL
// stayed current, so the issuer's view said nothing of what members read.
// PublishedCRL is the CRL as a member reads it; PublishedLate judges it;
// a failing publish is recorded for nfltr org status (PublishFailing) and
// cleared by the next publish.
func TestPublishedCRLAndAFailingPublish(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { // a record a stopped server left
		check(t, os.WriteFile(filepath.Join(f.org.dir, publishFailingFile), []byte(`{"since":"2026-11-14T05:02:00Z","error":"old"}`), 0o600))
	})
	var num int64
	var next time.Time
	eventually(t, "the CRL published", func() bool {
		var err error
		num, next, err = PublishedCRL(f.ctx, f.relay, f.org.root(t), f.clk.Now())
		return err == nil
	})
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		if n, nx := iss.LastCRL(); n != num || !nx.Equal(next) {
			t.Fatalf("published CRL #%d next %s, the issuer's #%d next %s", num, next, n, nx)
		}
	})
	if err := PublishedLate(next, f.clk.Now()); err != nil {
		t.Fatalf("a fresh CRL is late: %v", err)
	}
	// The issuer signs the successor with CRLLife/3 left: a CRL still
	// published PublishGrace after that was not replaced.
	if err := PublishedLate(next, next.Add(-orgpki.CRLLife/3+PublishGrace+time.Second)); err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("an overdue CRL: %v", err)
	}
	if err := PublishedLate(next, next); err == nil || !strings.Contains(err.Error(), "lapsed") {
		t.Fatalf("a lapsed CRL: %v", err)
	}
	if p, ok := PublishFailing(f.org.dir); ok {
		t.Fatalf("a publish failure recorded before any, or a stopped server's left: %+v", p)
	}

	refused := errors.New(`mailbox "org.x.crl" is a broadcast another machine holds: this caller may only pull it`)
	f.relay.mu.Lock()
	f.relay.fail = func(box string) error {
		if box == orgid.CRLMailbox(f.org.id) {
			return refused
		}
		return nil
	}
	f.relay.mu.Unlock()
	_, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now()) // a new CRL to publish
	check(t, err)
	var p PublishFailure
	eventually(t, "the failing publish recorded", func() bool {
		var ok bool
		p, ok = PublishFailing(f.org.dir)
		return ok
	})
	if !strings.Contains(p.Error, "another machine holds") || p.Since.IsZero() {
		t.Fatalf("recorded %+v", p)
	}
	if n, _, err := PublishedCRL(f.ctx, f.relay, f.org.root(t), f.clk.Now()); err != nil || n != num {
		t.Fatalf("published while refused: #%d %v, want #%d", n, err, num)
	}
	f.relay.mu.Lock()
	f.relay.fail = nil
	f.relay.mu.Unlock()
	eventually(t, "the record cleared by the next publish", func() bool { _, ok := PublishFailing(f.org.dir); return !ok })
	if n, _, err := PublishedCRL(f.ctx, f.relay, f.org.root(t), f.clk.Now()); err != nil || n != num+1 {
		t.Fatalf("published after the refusal: #%d %v, want #%d", n, err, num+1)
	}
	// A restore's input (orgissuer.Restore): the same CRL, as DER.
	der, err := PublishedRevocationList(f.ctx, f.relay, f.org.root(t), f.clk.Now())
	check(t, err)
	if crl, err := x509.ParseRevocationList(der); err != nil || crl.Number.Int64() != num+1 {
		t.Fatalf("the published CRL's DER: %v, want #%d", err, num+1)
	}
}

// PublishedCRL judges the CRL as members take it (orgid.Verifier.TakeCRL):
// its issuer certificate verifies under the organisation root at now. An
// issuer certificate past its NotAfter (members refuse every CRL it
// signed, still current or not: the canary and nfltr org status read it as
// fine, 2026-11-15) and an issuer certificate another root certified (a
// relay's forgery) are errors.
func TestPublishedCRLRefusesAnIssuerMembersRefuse(t *testing.T) {
	f := newFleet(t)
	root := f.org.root(t)
	var notAfter time.Time
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) { notAfter = iss.Cert().NotAfter })
	eventually(t, "the CRL published", func() bool {
		_, _, err := PublishedCRL(f.ctx, f.relay, root, f.clk.Now())
		return err == nil
	})
	if _, _, err := PublishedCRL(f.ctx, f.relay, root, notAfter.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "renew") {
		t.Fatalf("issuer certificate expired: %v", err)
	}

	other := newOrg(t, f.clk.Now()) // its issuer signs a CRL; the relay serves it as this organisation's
	var m orgid.CRLMessage
	other.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		der, err := iss.CRL(f.clk.Now())
		check(t, err)
		m = orgid.CRLMessage{CRL: der, Issuer: iss.Cert().Raw}
	})
	data, err := json.Marshal(m)
	check(t, err)
	_, err = f.relay.Append(context.Background(), orgid.CRLMailbox(f.org.id), data, mailboxclient.AppendOptions{ReplaceKey: "current"})
	check(t, err)
	var x509Err x509.UnknownAuthorityError
	if _, _, err := PublishedCRL(f.ctx, f.relay, root, f.clk.Now()); !errors.As(err, &x509Err) {
		t.Fatalf("forged issuer: %v, want x509.UnknownAuthorityError", err)
	}
}

// Past the issuer certificate's NotAfter the service signs no CRL
// (orgpki.ErrIssuerExpired): it records why for nfltr org status
// (PublishFailing) and goes on publishing the root.
func TestServiceSignsNoCRLPastTheIssuerCertificate(t *testing.T) {
	f := newFleet(t)
	root := f.org.root(t)
	var num int64
	eventually(t, "the CRL published", func() bool {
		var err error
		num, _, err = PublishedCRL(f.ctx, f.relay, root, f.clk.Now())
		return err == nil
	})
	rootBox := orgpki.RootMailbox(f.org.id)
	f.relay.mu.Lock()
	roots := f.relay.seq[rootBox]
	f.relay.mu.Unlock()
	f.clk.Add(orgpki.IssuerLife)
	var p PublishFailure
	eventually(t, "the refusal recorded", func() bool {
		var ok bool
		p, ok = PublishFailing(f.org.dir)
		return ok
	})
	if !strings.Contains(p.Error, orgpki.ErrIssuerExpired.Error()) {
		t.Fatalf("recorded %+v, want %q", p, orgpki.ErrIssuerExpired)
	}
	eventually(t, "the root published again", func() bool {
		f.relay.mu.Lock()
		defer f.relay.mu.Unlock()
		return f.relay.seq[rootBox] > roots
	})
	if n, _, err := PublishedCRL(f.ctx, f.relay, root, f.clk.Now().Add(-orgpki.IssuerLife)); err != nil || n != num {
		t.Fatalf("published #%d %v, want #%d: a CRL signed past the issuer certificate", n, err, num)
	}
}

// A revocation the expired issuer could not sign a CRL for is signed at
// the renewal (orgpki.Issuer.CRLDue), not when the CRL held is next due.
func TestServiceSignsACRLAfterTheRenewal(t *testing.T) {
	f := newFleet(t)
	root := f.org.root(t)
	var notAfter time.Time
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) { notAfter = iss.Cert().NotAfter })
	f.clk.Add(notAfter.Sub(f.clk.Now()) - 10*time.Minute) // a CRL signed 10 minutes before the issuer expires
	var num int64
	eventually(t, "the CRL signed before the expiry", func() bool {
		n, next, err := PublishedCRL(f.ctx, f.relay, root, f.clk.Now())
		num = n
		return err == nil && next.Sub(f.clk.Now()) > orgpki.CRLLife-time.Minute
	})
	f.clk.Add(11 * time.Minute)
	if _, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now()); !errors.Is(err, orgpki.ErrIssuerExpired) {
		t.Fatalf("a revocation past the issuer certificate: %v, want its CRL refused", err)
	}
	f.org.do(t, func(iss *orgpki.Issuer, st *orgissuer.Store) {
		lines, err := st.Lines()
		check(t, err)
		pins, err := orgpki.ReadPins(lines)
		check(t, err)
		req, err := iss.RenewalRequest(iss.Groups())
		check(t, err)
		ans, err := orgpki.SignIssuerRenewal(pins, f.org.rootKey, req, false, f.clk.Now())
		check(t, err)
		check(t, iss.InstallRenewal(ans, f.clk.Now()))
	})
	eventually(t, "a CRL signed under the renewed certificate", func() bool {
		n, _, err := PublishedCRL(f.ctx, f.relay, root, f.clk.Now())
		return err == nil && n > num
	})
}

// A publish failing for PublishAlarm or longer is logged as its own
// error, which an operator's log alert can match; shorter failures stay
// warnings.
func TestPublishFailingLogsAnAlarm(t *testing.T) {
	var log bytes.Buffer
	s := &service{Service: Service{Dir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(&log, nil))}}
	t0 := time.Date(2026, 11, 14, 5, 2, 0, 0, time.UTC)
	refused := errors.New("refused")
	s.maintained(refused, t0)
	s.maintained(refused, t0.Add(PublishAlarm-time.Second))
	if strings.Contains(log.String(), "level=ERROR") {
		t.Fatalf("an error before PublishAlarm:\n%s", log.String())
	}
	s.maintained(refused, t0.Add(PublishAlarm))
	if !strings.Contains(log.String(), "level=ERROR") || !strings.Contains(log.String(), alarmMsg) {
		t.Fatalf("no alarm after PublishAlarm:\n%s", log.String())
	}
	if p, ok := PublishFailing(s.Dir); !ok || !p.Since.Equal(t0) {
		t.Fatalf("recorded %+v %v, since want %s", p, ok, t0)
	}
	s.maintained(nil, t0.Add(PublishAlarm+time.Minute))
	if _, ok := PublishFailing(s.Dir); ok {
		t.Fatal("a publish did not clear the record")
	}
}

// orgissuer's receive sets the issuer's files aside by name
// (orgissuer.tombstoneFiles): these two are orgenrol's.
func TestIssuerFilesTheReceiveSetsAside(t *testing.T) {
	if spoolDir != "answers" || publishFailingFile != "publish-failing.json" {
		t.Fatalf("spoolDir %q, publishFailingFile %q: update orgissuer.tombstoneFiles", spoolDir, publishFailingFile)
	}
}
