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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
)

// session audits one session of f's machine (its own certificate as the
// client's: the check under test is the record's, not the admission's).
func (f *fleet) session(t *testing.T, service string, closed bool) {
	t.Helper()
	leaf, _ := f.m.Current()
	end := f.m.Audit([]*x509.Certificate{leaf, f.m.Issuer()}, service, []string{service}, f.clk.Now())
	if closed {
		end(orgaudit.End{Closed: f.clk.Now().Add(time.Second), In: 5, Out: 7, Reason: orgaudit.ReasonClosed, Path: "relayed"})
	}
}

func (f *fleet) audit(t *testing.T, now time.Time) AuditView {
	t.Helper()
	v, err := ReadAudit(f.org.dir, now)
	check(t, err)
	return v
}

func findings(v AuditView) string {
	var b []string
	for _, f := range v.Findings {
		b = append(b, f.What)
	}
	return strings.Join(b, "; ")
}

// TestAuditReachesTheIssuer is the path end to end in one process: a
// session's two lines go from the machine's log through the relay,
// sealed, to the issuer's sessions, which ReadAudit shows with no
// finding; the relay never carries a record's bytes.
func TestAuditReachesTheIssuer(t *testing.T) {
	f := newFleet(t)
	f.session(t, "pg", true)
	var posted [][]byte // every payload the relay carried (an acked one leaves its box)
	f.relay.rewrite = func(_ string, p []byte) []byte { posted = append(posted, p); return p }
	keep(t, f.ctx, f.keeper())
	eventually(t, "the session at the issuer", func() bool {
		v := f.audit(t, f.clk.Now())
		return len(v.Sessions) == 1 && v.Sessions[0].Close != nil
	})
	v := f.audit(t, f.clk.Now())
	s := v.Sessions[0]
	if s.Machine != "web-1" || s.Open.Service != "pg" || s.Close.Out != 7 || s.Close.Reason != orgaudit.ReasonClosed || v.Findings != nil {
		t.Fatalf("the issuer's view: %+v, findings %q", v, findings(v))
	}
	f.relay.mu.Lock()
	posts := 0
	for _, payload := range posted {
		var req orgpki.Request
		if json.Unmarshal(payload, &req) == nil && req.Audit != nil {
			posts++
			var clear orgpki.AuditBatch // sealed: no batch reads out of it
			if json.Unmarshal(req.Audit.Sealed, &clear) == nil && (clear.Lines != nil || clear.Head != nil) {
				t.Errorf("the relay carried a record in the clear: %s", req.Audit.Sealed)
			}
		}
		if bytes.Contains(payload, []byte(`"service"`)) {
			t.Errorf("the relay carried a record in the clear: %s", payload)
		}
	}
	f.relay.mu.Unlock()
	if posts == 0 {
		t.Fatal("no audit post on the relay")
	}
	// An open session, then silence: reported once SilentAfter passed.
	f.session(t, "ssh", false)
	eventually(t, "the open session at the issuer", func() bool { return len(f.audit(t, f.clk.Now()).Sessions) == 2 })
	if v := f.audit(t, f.clk.Now()); v.Findings != nil || v.Sessions[1].Close != nil {
		t.Fatalf("an open session: %+v, findings %q", v.Sessions[1], findings(v))
	}
	if got := findings(f.audit(t, f.clk.Now().Add(orgaudit.SilentAfter+time.Minute))); !strings.Contains(got, "silent since") {
		t.Fatalf("silent: findings %q", got)
	}
}

// TestAuditRefusalReachesTheIssuer: a client the machine refused is a
// refused entry of the issuer's view, with its person, service and
// reason; it opens no session, so the machine silent after it is not
// reported (Silent counts open sessions only).
func TestAuditRefusalReachesTheIssuer(t *testing.T) {
	f := newFleet(t)
	leaf, _ := f.m.Current()
	f.m.AuditRefused([]*x509.Certificate{leaf, f.m.Issuer()}, "pg", errors.New("no access rule lets it use web-1/pg"), f.clk.Now())
	keep(t, f.ctx, f.keeper())
	eventually(t, "the refusal at the issuer", func() bool { return len(f.audit(t, f.clk.Now()).Sessions) == 1 })
	v := f.audit(t, f.clk.Now().Add(orgaudit.SilentAfter+time.Minute))
	if s := v.Sessions[0]; s.Machine != "web-1" || s.Open.Kind != orgaudit.KindRefused || s.Open.Service != "pg" || s.Open.Who.Name != leaf.Subject.CommonName ||
		s.Open.Reason != "no access rule lets it use web-1/pg" || s.Close != nil || v.Findings != nil {
		t.Fatalf("the issuer's view: %+v, findings %q", v, findings(v))
	}
}

// TestAuditAlterationsFound: a line edited on the machine before it
// shipped is refused and reported (the machine starts a new log after
// it), and a line edited at rest in the issuer's sessions is reported by
// every later read.
func TestAuditAlterationsFound(t *testing.T) {
	f := newFleet(t)
	f.session(t, "pg", true)
	local := filepath.Join(f.dir, orgaudit.LogFile)
	b, err := os.ReadFile(local)
	check(t, err)
	check(t, os.WriteFile(local, bytes.Replace(b, []byte(`"out":7`), []byte(`"out":1`), 1), 0o600))
	f.session(t, "pg", true)
	keep(t, f.ctx, f.keeper())
	eventually(t, "the refusal and the new log", func() bool {
		got := findings(f.audit(t, f.clk.Now()))
		return strings.Contains(got, "refused at") && strings.Contains(got, "bad signature at seq 2") && strings.Contains(got, "new log")
	})
	if v := f.audit(t, f.clk.Now()); len(v.Sessions) != 2 || v.Sessions[0].Close != nil {
		t.Fatalf("the first session's close (edited) is not taken, the second is: %+v", v.Sessions)
	}
	sessions := filepath.Join(f.org.dir, SessionsFile)
	b, err = os.ReadFile(sessions)
	check(t, err)
	check(t, os.WriteFile(sessions, bytes.Replace(b, []byte(`"service":"pg"`), []byte(`"service":"pq"`), 1), 0o600))
	if got := findings(f.audit(t, f.clk.Now())); !strings.Contains(got, "bad signature at seq 1") {
		t.Fatalf("an edit at rest: findings %q", got)
	}
}

// TestAuditSinkTakesEveryLineOnce: the export appends each line to the
// file sink once, and an URL sink that fails takes them all on its
// return.
func TestAuditSinkTakesEveryLineOnce(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.wait = 20 * time.Millisecond })
	sink := filepath.Join(t.TempDir(), "audit.ndjson")
	check(t, SetAuditSink(f.org.dir, sink))
	if err := SetAuditSink(f.org.dir, "http://example.com/x"); err == nil {
		t.Fatal("a plain http sink beyond loopback was set")
	}
	f.session(t, "pg", true)
	keep(t, f.ctx, f.keeper())
	eventually(t, "two lines in the sink", func() bool {
		b, _ := os.ReadFile(sink)
		return bytes.Count(b, []byte("\n")) == 2
	})
	lines := func() int { b, _ := os.ReadFile(sink); return bytes.Count(b, []byte("\n")) }
	time.Sleep(10 * f.wait) // rounds of the issuer's export: nothing again
	if n := lines(); n != 2 {
		t.Fatalf("the file sink took %d lines", n)
	}
	var mu sync.Mutex
	var got []byte
	up, refused := false, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !up || r.Header.Get("Content-Type") != "application/x-ndjson" {
			refused++
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		got = append(got, b...)
	}))
	defer srv.Close()
	check(t, SetAuditSink(f.org.dir, srv.URL))
	eventually(t, "the URL sink refused", func() bool { mu.Lock(); defer mu.Unlock(); return refused > 0 })
	mu.Lock()
	up = true
	mu.Unlock()
	eventually(t, "the URL sink took the lines", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) > 0 })
	time.Sleep(10 * f.wait)
	mu.Lock()
	defer mu.Unlock()
	for l := range bytes.Lines(got) {
		var line struct{ Rec json.RawMessage }
		if json.Unmarshal(l, &line) != nil || line.Rec == nil {
			t.Fatalf("not a signed line: %s", l)
		}
	}
	if bytes.Count(got, []byte("\n")) != 2 {
		t.Fatalf("the URL sink took %q", got)
	}
}

// TestAuditFollowsTheMove: the lines the old issuer took (the machine's
// cursor past them) are the new issuer's after nfltr org move
// (spec/MoveAudit.tla AckedHeld, mutant bundle-no-sessions, the code
// before): a session after the move reaches the new issuer with no gap.
func TestAuditFollowsTheMove(t *testing.T) {
	f := newFleet(t)
	f.session(t, "pg", true)
	keep(t, f.ctx, f.keeper())
	eventually(t, "the machine's cursor past the session", func() bool {
		var at shipped
		return readJSON(filepath.Join(f.dir, shipFile), &at) == nil && at.Offset > 0
	})
	dir := moveTo(t, f.relay, f.org.id, f.org.dir, f.org.pins.Root, f.clk.Now())
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Service{Mailbox: f.mailbox(), Dir: dir, Logger: quiet(), Now: f.clk.Now, Wait: 50 * time.Millisecond}.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	f.session(t, "ssh", true)
	read := func() AuditView {
		v, err := ReadAudit(dir, f.clk.Now())
		check(t, err)
		return v
	}
	eventually(t, "both sessions at the new issuer", func() bool {
		v := read()
		return len(v.Sessions) == 2 && v.Sessions[1].Close != nil
	})
	if v := read(); v.Findings != nil || v.Sessions[0].Open.Service != "pg" {
		t.Fatalf("the new issuer's view: %+v, findings %q", v.Sessions, findings(v))
	}
}

// MoveAudit.tla take-after-fence: an audit post the old issuer reads after
// its fence is not answered (the machine's cursor stays; the new issuer
// answers it), for a line it took then would not be in the bundle. The
// store's Open refuses a fenced log (ErrMoved), so decide never reaches
// takeAudit.
func TestAuditNotTakenAfterTheFence(t *testing.T) {
	f := newFleet(t)
	f.session(t, "pg", true)
	line, err := orgaudit.Last(f.dir)
	check(t, err)
	lr, err := orgaudit.Parse(line)
	check(t, err)
	cert, key := f.m.Current()
	head, err := orgaudit.SignHead(orgaudit.Signing{Log: lr.Log, Seq: lr.Seq, Prev: orgaudit.Hash(line), Machine: lr.Machine, Cert: cert, Key: key, At: f.clk.Now()})
	check(t, err)
	sealed, err := orgpki.SealAudit(f.m.Issuer(), orgpki.AuditBatch{Lines: [][]byte{line}, Head: head})
	check(t, err)
	k, err := orgissuer.LoadReceiveKey(filepath.Join(t.TempDir(), orgissuer.ReceiveKeyFile))
	check(t, err)
	_, err = orgissuer.Send(filepath.Dir(f.org.dir), orgissuer.ReceiveKey{Pub: k.PublicKey()}, f.clk.Now())
	check(t, err)
	s := &service{Service: Service{Dir: f.org.dir, Logger: quiet()}}
	a, err := s.decide(f.ctx, orgpki.Request{ID: "audit-x", Audit: &orgpki.AuditRequest{Sealed: sealed}}, "", f.clk.Now())
	if !errors.Is(err, orgpki.ErrMoved) {
		t.Fatalf("an audit post after the fence: answered %s, %v; want ErrMoved", a, err)
	}
	if _, err := os.Stat(filepath.Join(f.org.dir, SessionsFile)); !os.IsNotExist(err) {
		t.Fatalf("the fenced issuer took lines: %v", err)
	}
}

// A process of the machine killed mid-session (its owner file left, its
// lock free) has its session closed lost by the keeper's next round, and
// the close reaches the issuer (spec/AuditLog.tla EveryOpenCloses; the
// code before left it open until silent).
func TestKeeperClosesAKilledProcesssSession(t *testing.T) {
	f := newFleet(t)
	leaf, key := f.m.Current()
	s := orgaudit.Session{ID: "killed1", Service: "pg", Who: orgaudit.Who{Name: "web-1"}, By: "rule", Opened: f.clk.Now().UTC()}
	owners := filepath.Join(f.dir, "sessions.owners")
	check(t, os.MkdirAll(owners, 0o700))
	check(t, os.WriteFile(filepath.Join(owners, "gone"), []byte(`["killed1"]`), 0o600))
	check(t, os.WriteFile(filepath.Join(owners, "gone.lock"), nil, 0o600))
	check(t, orgaudit.Append(f.dir, s.Open(), leaf, key, f.clk.Now()))
	keep(t, f.ctx, f.keeper())
	eventually(t, "the killed process's session closed at the issuer", func() bool {
		v := f.audit(t, f.clk.Now())
		return len(v.Sessions) == 1 && v.Sessions[0].Close != nil && v.Sessions[0].Close.Reason == orgaudit.ReasonLost
	})
	if v := f.audit(t, f.clk.Now()); v.Findings != nil {
		t.Fatalf("findings %q", findings(v))
	}
}

// backlog writes, before the keeper runs, a signed log just over size
// bytes of closed sessions (an issuer out of reach while the sessions went
// on); it returns the sessions, the file and its signing state.
func backlog(t *testing.T, f *fleet, size int) (int, string, orgaudit.Signing) {
	t.Helper()
	cert, key := f.m.Current()
	var buf bytes.Buffer
	s := orgaudit.Signing{Log: "backlog0123456789abcdef", Machine: cert.Subject.CommonName, Cert: cert, Key: key, At: f.clk.Now()}
	n := 0
	// Long lines (a rule named at length; a line stays under 2 KiB): fewer
	// to sign and check, so the test is quick under -race too.
	by := "rule group:ops " + strings.Repeat("x", 800)
	for buf.Len() <= size {
		n++
		ses := orgaudit.Session{ID: fmt.Sprintf("s%05d", n), Service: "pg", Who: orgaudit.Who{Name: "ci-1"}, By: by, Opened: f.clk.Now().UTC()}
		for _, r := range []orgaudit.Record{ses.Open(), ses.Close(orgaudit.End{Closed: f.clk.Now().UTC(), Reason: orgaudit.ReasonClosed})} {
			s.Seq++
			line, err := orgaudit.Line(r, s)
			check(t, err)
			if len(line) >= 2048 { // unshipped reads a log's first line in 2 KiB
				t.Fatalf("a line of %d bytes", len(line))
			}
			buf.Write(append(line, '\n'))
			s.Prev = orgaudit.Hash(line)
		}
	}
	local := filepath.Join(f.dir, orgaudit.LogFile)
	check(t, os.WriteFile(local, buf.Bytes(), 0o600))
	return n, local, s
}

// shippedWithin waits until the machine's cursor is at local's end (the
// backlog acknowledged), for at most d. The cursor, not ReadAudit: a read
// checks every line the issuer holds, too slow to poll under -race.
func shippedWithin(t *testing.T, f *fleet, local string, d time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(d); ; time.Sleep(10 * time.Millisecond) {
		var at shipped
		fi, err := os.Stat(local)
		if err == nil && readJSON(filepath.Join(f.dir, shipFile), &at) == nil && at.Offset == fi.Size() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: the machine's cursor at the file's end (the backlog acknowledged)", d)
		}
	}
}

// TestKeeperShipsABacklogPostAfterPost: a backlog over shipMax ships in
// posts one after another, not one per ShipEvery (the code before took
// 30 s a post; mutant audit-backlog-waits). Two posts, so the bound below
// ShipEvery holds on a loaded machine under -race: the backlog of
// TestKeeperShipsABacklogAndRotates took 18 s there at background
// priority, over hang (lane R85PREP).
func TestKeeperShipsABacklogPostAfterPost(t *testing.T) {
	f := newFleet(t)
	n, local, _ := backlog(t, f, shipMax+shipMax/2)
	keep(t, f.ctx, f.keeper())
	shippedWithin(t, f, local, orgaudit.ShipEvery-5*time.Second)
	if v := f.audit(t, f.clk.Now()); len(v.Sessions) != n || v.Findings != nil {
		t.Fatalf("the issuer holds %d of %d sessions, findings %q", len(v.Sessions), n, findings(v))
	}
}

// TestKeeperShipsABacklogAndRotates is the rotation end to end: a log over
// auditRotateAt ships (TestKeeperShipsABacklogPostAfterPost), every
// answered post rotating the file past what the issuer holds
// (spec/AuditLog.tla Ship, Rotate): the issuer holds every session with no
// finding (no gap, no new log: OneLog, NothingLost), the file is cut to
// under auditRotateAt with the log going on, and a session after the
// rotation chains on at the issuer. Its wait is bounded only against a
// hang, scaled to its four or five posts.
func TestKeeperShipsABacklogAndRotates(t *testing.T) {
	f := newFleet(t)
	n, local, s := backlog(t, f, auditRotateAt+shipMax/2)
	keep(t, f.ctx, f.keeper())
	shippedWithin(t, f, local, 5*hang)
	if v := f.audit(t, f.clk.Now()); len(v.Sessions) != n || v.Findings != nil {
		t.Fatalf("the issuer holds %d of %d sessions, findings %q", len(v.Sessions), n, findings(v))
	}
	fi, err := os.Stat(local)
	check(t, err)
	first, err := os.ReadFile(local)
	check(t, err)
	r, err := orgaudit.Parse(first[:bytes.IndexByte(first, '\n')])
	check(t, err)
	if fi.Size() > auditRotateAt || r.Seq == 1 || r.Log != s.Log {
		t.Fatalf("after the backlog: the file %d bytes (rotated past %d), its first line seq %d of log %s", fi.Size(), auditRotateAt, r.Seq, r.Log)
	}
	f.session(t, "ssh", true)
	eventually(t, "the session after the rotation acknowledged", func() bool {
		var at shipped
		fi, err := os.Stat(local)
		return err == nil && readJSON(filepath.Join(f.dir, shipFile), &at) == nil && at.Offset == fi.Size()
	})
	if v := f.audit(t, f.clk.Now()); len(v.Sessions) != n+1 || v.Sessions[n].Close == nil || v.Findings != nil {
		t.Fatalf("after the rotation: %d sessions, findings %q", len(v.Sessions), findings(v))
	}
}

// TestSDKOnlyMachineShipsItsAudit: on a machine where only an SDK program
// serves (relay client orgid.Identity through nfnet.Listen, no nfltr), the
// keeper that program runs ships Identity's lines: Keeper.Run, which it
// runs anyway (orgid renews nothing; the keeper renews and follows the
// CRL). Identity's sessions reach the issuer, and the keeper's round in
// the same process does not close the session Identity still serves
// (another owner lock of the process: AuditLog.tla LiveOpenNotClosed).
func TestSDKOnlyMachineShipsItsAudit(t *testing.T) {
	f := newFleet(t)
	id, err := orgid.Load(f.dir)
	check(t, err)
	leaf, _ := f.m.Current()
	certs := []*x509.Certificate{leaf, f.m.Issuer()}
	id.Audit(certs, "pg", []string{"pg"}, f.clk.Now())(orgaudit.End{Closed: f.clk.Now().Add(time.Second), In: 3, Reason: orgaudit.ReasonClosed})
	end := id.Audit(certs, "ssh", []string{"ssh"}, f.clk.Now())
	defer runtime.KeepAlive(end)
	keep(t, f.ctx, f.keeper())
	eventually(t, "the SDK's sessions at the issuer", func() bool { return len(f.audit(t, f.clk.Now()).Sessions) == 2 })
	v := f.audit(t, f.clk.Now())
	if v.Findings != nil || v.Sessions[0].Close == nil || v.Sessions[0].Close.In != 3 || v.Sessions[1].Open.Service != "ssh" || v.Sessions[1].Close != nil {
		t.Fatalf("the issuer's view: %+v, findings %q", v.Sessions, findings(v))
	}
}

// The SDK program's keeper talks to the relay with the SDK's mailbox
// client (orgid.go: a machine without nfltr runs Keeper itself).
var _ Mailbox = (*mailboxclient.Client)(nil)
