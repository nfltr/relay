// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// failingPulls fails its first n pulls and reports every pull's start.
type failingPulls struct {
	n     int
	calls chan int
}

func (f *failingPulls) Pull(ctx context.Context, _ string, _ uint64, _ int, _ time.Duration) ([]mailboxclient.Envelope, string, error) {
	f.calls <- 1
	if f.n > 0 {
		f.n--
		return nil, "", errors.New("http2: client connection lost")
	}
	<-ctx.Done()
	return nil, "", ctx.Err()
}

// A pull failed by a dead connection (a NAT that changed the port) is
// pulled again at once, not after retryWait, so a push lands near the
// mailbox client's ping bound. A second failure in a row waits retryWait:
// no hot loop.
func TestFollowPullsAgainAtOnceAfterAFailedPull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mb := &failingPulls{n: 2, calls: make(chan int, 8)}
	go follow(ctx, mb, "org.x.crl", time.Hour, func([]byte) error { return nil }, nil, quiet())
	<-mb.calls // the first pull, failed
	select {
	case <-mb.calls:
	case <-time.After(retryWait / 3):
		t.Fatalf("no pull within %s of a failed one (retryWait %s)", retryWait/3, retryWait)
	}
	select {
	case <-mb.calls:
		t.Fatal("a second failure in a row was pulled again at once")
	case <-time.After(300 * time.Millisecond):
	}
}

// box is a relay mailbox holding its newest message (a replace key), whose
// long-polls the next push wakes. withhold: the relay delivers nothing to
// a pull after a cursor (a push lost or withheld), only fresh reads.
type box struct {
	mu       sync.Mutex
	last     mailboxclient.Envelope
	wake     chan struct{}
	withhold bool
}

func newBox() *box { return &box{wake: make(chan struct{})} }

func (b *box) push(t testing.TB, m CRLMessage) {
	p, err := json.Marshal(m)
	check(t, err)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.last = mailboxclient.Envelope{Seq: b.last.Seq + 1, Payload: p}
	close(b.wake)
	b.wake = make(chan struct{})
}

func (b *box) Pull(ctx context.Context, _ string, after uint64, _ int, wait time.Duration) ([]mailboxclient.Envelope, string, error) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		b.mu.Lock()
		last, wake, hold := b.last, b.wake, b.withhold && after > 0
		b.mu.Unlock()
		if last.Seq > after && !hold {
			return []mailboxclient.Envelope{last}, "owner", nil
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-t.C:
			return nil, "owner", nil
		case <-wake:
		}
	}
}

// followRig: cli follows the CRL of an organisation with web in it.
type followRig struct {
	o   *testOrg
	dir string // cli's
	cli *Identity
	web *x509.Certificate
	box *box
}

func newFollowRig(t *testing.T) *followRig {
	now := time.Now()
	r := &followRig{o: newTestOrg(t, now), box: newBox()}
	d := t.TempDir()
	r.o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	r.web = r.o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	r.dir = filepath.Join(d, "cli")
	r.cli = load(t, r.dir)
	return r
}

func (r *followRig) checksWeb() error {
	_, err := r.cli.CheckServer([]*x509.Certificate{r.web, r.o.iss}, "web", time.Now())
	return err
}

// The issuer's revoke reaches a follower at the push, and through the
// backstop's fresh read when the relay withholds the push (Enrol.tla
// Fetch, TakesEffect; mutant push-only).
func TestFollowTakesTheRevokePushAndBackstop(t *testing.T) {
	for _, withhold := range []bool{false, true} {
		t.Run(map[bool]string{false: "push", true: "backstop"}[withhold], func(t *testing.T) {
			r := newFollowRig(t)
			r.box.withhold = withhold
			held, err := os.ReadFile(filepath.Join(r.dir, CRLFile))
			check(t, err)
			r.box.push(t, CRLMessage{CRL: held, Issuer: r.o.iss.Raw}) // the CRL the relay held at the start
			every := time.Hour                                        // the push alone
			if withhold {
				every = 300 * time.Millisecond
			}
			go followCRL(t.Context(), r.box, r.cli, every, time.Now, quiet())
			time.Sleep(200 * time.Millisecond) // the follow parks on its cursor
			if err := r.checksWeb(); err != nil {
				t.Fatalf("web before the revoke: %v", err)
			}
			changed := r.cli.Changed()
			r.o.revoke(r.web)
			r.box.push(t, CRLMessage{CRL: r.o.crl(t, time.Now()), Issuer: r.o.iss.Raw})
			select {
			case <-changed:
			case <-time.After(10 * time.Second):
				t.Fatal("the CRL did not reach the follower")
			}
			if r.checksWeb() == nil {
				t.Fatal("a revoked machine still checks")
			}
		})
	}
}

// signalWriter closes its channel once a write contains text.
type signalWriter struct {
	text string
	once sync.Once
	ch   chan struct{}
}

func (w *signalWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.text) {
		w.once.Do(func() { close(w.ch) })
	}
	return len(p), nil
}

// The new issuer's CRL that reaches a follower before the rotation that
// certifies it is not taken, then taken at once when the rotation is, not
// a retryWait later: until then the follower admits no one under the new
// issuer (Enrol.tla MachinesFollowRotation; mutant crl-no-wake-on-rotation).
func TestFollowTakesTheNewIssuersCRLAtTheRotation(t *testing.T) {
	r := newFollowRig(t)
	notTaken := &signalWriter{text: "message not taken", ch: make(chan struct{})}
	go followCRL(t.Context(), r.box, r.cli, time.Hour, time.Now, slog.New(slog.NewTextHandler(notTaken, nil)))
	cross := r.o.rotate(t, time.Now().Add(time.Minute))
	renewed := mint(t, leafTemplate(t, r.o.orgID, "web", []string{"web"}, time.Now()), r.o.iss, newKey(t).Public(), r.o.issKey)
	r.box.push(t, CRLMessage{CRL: r.o.crl(t, time.Now()), Issuer: r.o.iss.Raw})
	select {
	case <-notTaken.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("the new issuer's CRL was taken before the rotation")
	}
	if _, err := r.cli.TakeRotation(cross.Raw); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(retryWait / 3)
	for {
		if _, err := r.cli.CheckServer([]*x509.Certificate{renewed, r.o.iss}, "web", time.Now()); err == nil {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("web under the new issuer within %s of the rotation: %v", retryWait/3, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
