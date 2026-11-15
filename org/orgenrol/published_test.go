// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		num, next, err = PublishedCRL(f.ctx, f.relay, f.org.id)
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
	if n, _, err := PublishedCRL(f.ctx, f.relay, f.org.id); err != nil || n != num {
		t.Fatalf("published while refused: #%d %v, want #%d", n, err, num)
	}
	f.relay.mu.Lock()
	f.relay.fail = nil
	f.relay.mu.Unlock()
	eventually(t, "the record cleared by the next publish", func() bool { _, ok := PublishFailing(f.org.dir); return !ok })
	if n, _, err := PublishedCRL(f.ctx, f.relay, f.org.id); err != nil || n != num+1 {
		t.Fatalf("published after the refusal: #%d %v, want #%d", n, err, num+1)
	}
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
