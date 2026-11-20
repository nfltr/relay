// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/client/orgid"

	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

// relay is an in-memory stand-in for the relay's mailboxes that the tests
// make misbehave: it may lose an append (drop), rewrite it (rewrite), or
// never wake a long-poll from a cursor of the mailboxes withhold names
// (the push lost).
type relay struct {
	mu       sync.Mutex
	boxes    map[string][]mailboxclient.Envelope
	seq      map[string]uint64
	keys     map[string]bool
	wake     chan struct{}
	fail     func(mailbox string) error
	drop     func(mailbox string, payload []byte) bool
	rewrite  func(mailbox string, payload []byte) []byte
	withhold func(mailbox string) bool
	// from is the sender the relay asserts on each append (the caller's
	// machine id, or <machine id>-<agent>).
	from string
	// late delays a pull's delivery from the mailboxes it names.
	late func(mailbox string) time.Duration
}

func newRelay() *relay {
	return &relay{boxes: map[string][]mailboxclient.Envelope{}, seq: map[string]uint64{}, keys: map[string]bool{}, wake: make(chan struct{})}
}

func (r *relay) Append(_ context.Context, box string, payload []byte, o mailboxclient.AppendOptions) (mailboxclient.Appended, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		if err := r.fail(box); err != nil {
			return mailboxclient.Appended{}, err
		}
	}
	if o.IdempotencyKey != "" {
		if r.keys[box+"\x00"+o.IdempotencyKey] {
			return mailboxclient.Appended{Duplicate: true}, nil
		}
		r.keys[box+"\x00"+o.IdempotencyKey] = true
	}
	if r.drop != nil && r.drop(box, payload) {
		return mailboxclient.Appended{}, nil
	}
	if r.rewrite != nil {
		payload = r.rewrite(box, payload)
	}
	if o.ReplaceKey != "" {
		r.boxes[box] = slices.DeleteFunc(r.boxes[box], func(e mailboxclient.Envelope) bool { return e.ReplaceKey == o.ReplaceKey })
	}
	r.seq[box]++
	r.boxes[box] = append(r.boxes[box], mailboxclient.Envelope{Seq: r.seq[box], ReplaceKey: o.ReplaceKey, Sender: r.from, Payload: payload})
	close(r.wake)
	r.wake = make(chan struct{})
	return mailboxclient.Appended{Seq: r.seq[box]}, nil
}

func (r *relay) Pull(ctx context.Context, box string, after uint64, _ int, wait time.Duration) ([]mailboxclient.Envelope, string, error) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		r.mu.Lock()
		var out []mailboxclient.Envelope
		if !(r.withhold != nil && r.withhold(box) && after > 0) {
			for _, e := range r.boxes[box] {
				if e.Seq > after {
					out = append(out, e)
				}
			}
		}
		wake, late := r.wake, r.late
		r.mu.Unlock()
		if len(out) > 0 {
			if late != nil {
				time.Sleep(late(box))
			}
			return out, "owner", nil
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

func (r *relay) Ack(_ context.Context, box string, through uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.boxes[box] = slices.DeleteFunc(r.boxes[box], func(e mailboxclient.Envelope) bool { return e.Seq <= through })
	return nil
}

// clock is a test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// org is an issuer directory in orgissuer's layout, with the keys a
// rotation needs.
type org struct {
	dir     string
	rootKey *ecdsa.PrivateKey
	recKey  ed25519.PrivateKey
	pins    Pins
	id      string
}

func check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newOrg(t *testing.T, now time.Time) *org {
	t.Helper()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	id, err := orgpki.OrgID(rk.Public())
	check(t, err)
	root, err := orgpki.NewRoot(rk, id, now)
	check(t, err)
	_, recKey, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	rec, err := orgpki.NewRecovery(recKey, id, now)
	check(t, err)
	ipub, ikey, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	ic, err := orgpki.CertifyIssuer(root, rk, ipub, []string{"web", "db"}, now)
	check(t, err)
	lines, err := orgpki.Genesis(root, rec, "test", orgpki.RootFile, ic, now)
	check(t, err)
	dir := filepath.Join(t.TempDir(), "org")
	check(t, os.MkdirAll(dir, 0o700)) // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
	check(t, os.WriteFile(filepath.Join(dir, orgissuer.LogFile), append(bytes.Join(lines, []byte("\n")), '\n'), 0o600))
	check(t, orgissuer.WriteKey(filepath.Join(dir, orgissuer.IssuerKeyFile), orgissuer.PEMIssuer, ikey, true))
	return &org{dir: dir, rootKey: rk, recKey: recKey, pins: Pins{Root: orgid.Fingerprint(root), Recovery: orgid.Fingerprint(rec)}, id: id}
}

// do runs f on the issuer under its directory's lock.
func (o *org) do(t *testing.T, f func(*orgpki.Issuer, *orgissuer.Store)) {
	t.Helper()
	s, err := orgissuer.Lock(o.dir)
	check(t, err)
	defer s.Unlock()
	iss, err := s.Open()
	check(t, err)
	f(iss, s)
}

// root is the organisation's root certificate.
func (o *org) root(t *testing.T) (root *x509.Certificate) {
	o.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) { root = iss.Root() })
	return root
}

func (o *org) token(t *testing.T, name string, now time.Time) string {
	var tok string
	o.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		var err error
		tok, err = iss.MakeToken(name, []string{"web"}, "m-"+name, time.Hour, now)
		check(t, err)
	})
	return tok
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fleet is a relay, a running issuer service and one joined machine.
type fleet struct {
	relay  *relay
	org    *org
	clk    *clock
	dir    string
	m      *orgmachine.Machine
	ctx    context.Context
	joined Joined
	keys   *machineKeys
	// machineOf, when set, is the issuer's account name resolution
	// (Service.MachineOf).
	machineOf func(ctx context.Context, name string) (string, error)
	noA2A     bool // the issuer has no A2A root (no MachineKey)
	// wait, when set, is the issuer's round (Service.Wait; 50ms when not).
	wait time.Duration
}

// machineKeys is the issuer's machine keys (the caller's shape: a
// new id only).
type machineKeys struct {
	mu    sync.Mutex
	made  map[string]bool
	names map[string]string // machine id -> the name it was made under
}

func (k *machineKeys) make(id, name string, _ time.Time) (string, []byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.made[id] {
		return "", nil, errors.New("issued before")
	}
	k.made[id], k.names[id] = true, name
	return id + ".1", []byte("km of " + id), nil
}

func newFleet(t *testing.T) *fleet { return newFleetWith(t, nil) }

// newFleetWith is newFleet with prep run before the machine joins.
func newFleetWith(t *testing.T, prep func(*fleet)) *fleet {
	t.Helper()
	clk := &clock{t: time.Now().Truncate(time.Second)}
	f := &fleet{relay: newRelay(), org: newOrg(t, clk.Now()), clk: clk, dir: filepath.Join(t.TempDir(), "machine")}
	if prep != nil {
		prep(f)
	}
	keys := &machineKeys{made: map[string]bool{}, names: map[string]string{}}
	f.keys = keys
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.ctx = ctx
	done := make(chan struct{})
	mk := keys.make
	if f.noA2A {
		mk = nil
	}
	go func() {
		defer close(done)
		_ = Service{Mailbox: f.relay, Dir: f.org.dir, Logger: quiet(), Now: clk.Now, Wait: cmp.Or(f.wait, 50*time.Millisecond), MachineKey: mk, MachineOf: f.machineOf}.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	var err error
	f.joined, err = Join(ctx, f.relay, f.dir, f.org.pins, f.org.token(t, "web-1", clk.Now()), hang, clk.Now)
	check(t, err)
	if f.joined.Cert.Subject.CommonName != "web-1" {
		t.Fatalf("enrolled as %q", f.joined.Cert.Subject.CommonName)
	}
	f.m, err = orgmachine.Open(f.dir)
	check(t, err)
	return f
}

// hang bounds every wait for something the test expects (an answer, a
// join, a CRL), only against a hang: a loaded machine gets there when it
// gets there (a 300 ms answer wait timed out under -race on the runner:
// TestStaleAnswerRefused). A test that needs a wait to run out (a lost
// request, a withheld answer) sets its own short one. Below retryWait, so
// a step a wake takes at once never passes by the machine's retry instead
// (mutant crl-no-wake-on-rotation).
const hang = retryWait / 2

func (f *fleet) keeper() Keeper {
	return Keeper{Mailbox: f.relay, Machine: f.m, Logger: quiet(), Now: f.clk.Now, AnswerWait: hang, RetryWait: 10 * time.Millisecond, FollowEvery: 100 * time.Millisecond}
}

// keep runs k until the test (or ctx) ends, joined before TempDir's
// cleanup removes the machine's directory.
func keep(t *testing.T, ctx context.Context, k Keeper) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); k.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

func serial(m *orgmachine.Machine) string { c, _ := m.Current(); return c.SerialNumber.String() }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(hang)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %s", hang, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A token enrols a machine through the relay; at 2/3 of its lifetime it
// renews into a new key, the issuer's log holding the serial it renews.
// The enrolment's answer carries the machine key sealed to its
// certified key, and the machine opens it (orgpki SealMachineKey,
// OpenMachineKey; a2a_keytransfer.pv's enrolment path).
func TestJoinOpensTheSealedA2AKey(t *testing.T) {
	f := newFleet(t)
	if f.joined.KeyID != "m-web-1.1" || string(f.joined.MachineKey) != "km of m-web-1" {
		t.Fatalf("machine key %q %q", f.joined.KeyID, f.joined.MachineKey)
	}
	// Under the enrolled name, so <name>.<service> reaches the machine.
	f.keys.mu.Lock()
	defer f.keys.mu.Unlock()
	if got := f.keys.names["m-web-1"]; got != "web-1" {
		t.Fatalf("machine key made under name %q, want web-1", got)
	}
}

// The relay fails the first post of the enrolment's answer: the issuer
// reads the request again and posts the answer it decided (its spool),
// so the enrolment completes with the A2A key it sealed (mutant no-spool:
// deciding again answers the token again, with no A2A key: one is sealed
// for a machine id once).
func TestEnrolAnsweredOnceAcrossARetry(t *testing.T) {
	var once sync.Once
	f := newFleetWith(t, func(f *fleet) {
		f.relay.fail = func(box string) error {
			var err error
			if box == orgpki.AnswersMailbox(f.org.id) {
				once.Do(func() { err = errors.New("relay unavailable") })
			}
			return err
		}
	})
	if f.joined.KeyID != "m-web-1.1" {
		t.Fatalf("machine key %q", f.joined.KeyID)
	}
	eventually(t, "the spool emptied after the ack", func() bool {
		left, _ := os.ReadDir(filepath.Join(f.org.dir, spoolDir))
		return len(left) == 0
	})
}

func TestJoinThenRenewThroughMailboxes(t *testing.T) {
	f := newFleet(t)
	before := serial(f.m)
	f.clk.Add(17 * time.Hour)
	check(t, f.keeper().renew(f.ctx, ""))
	if serial(f.m) == before {
		t.Fatal("the renewal did not install a new certificate")
	}
	f.org.do(t, func(iss *orgpki.Issuer, s *orgissuer.Store) {
		lines, err := s.Lines()
		check(t, err)
		if !bytes.Contains(lines[len(lines)-1], []byte(`"renewed"`)) && !bytes.Contains(bytes.Join(lines, nil), []byte(`"act":"renewed"`)) {
			t.Fatal("no renewed entry in the issuer's log")
		}
	})
	// Not due again: the machine leaves it.
	again := serial(f.m)
	check(t, f.keeper().renew(f.ctx, ""))
	if serial(f.m) != again {
		t.Fatal("renewed while not due")
	}
}

// The relay loses the first renewal request: the machine asks again with a
// new key and renews (Enrol.tla mutant no-retry).
func TestRenewAsksAgainAfterALoss(t *testing.T) {
	f := newFleet(t)
	var lost bool
	f.relay.mu.Lock()
	f.relay.drop = func(box string, p []byte) bool {
		if box == orgpki.EnrolMailbox(f.org.id) && !lost {
			lost = true
			return true
		}
		return false
	}
	f.relay.mu.Unlock()
	before := serial(f.m)
	f.clk.Add(17 * time.Hour)
	k := f.keeper()
	k.AnswerWait = 300 * time.Millisecond // the lost request's wait runs out
	keep(t, f.ctx, k)
	eventually(t, "renewed after a lost request", func() bool { return serial(f.m) != before })
}

// The relay hands back an old answer relabelled with the new request's id:
// the machine refuses it, keeps its certificate (Enrol.tla
// MachineHoldsItsKey, mutant install-stale-answer).
func TestStaleAnswerRefused(t *testing.T) {
	f := newFleet(t)
	f.clk.Add(17 * time.Hour)
	check(t, f.keeper().renew(f.ctx, ""))
	var old []byte
	f.relay.mu.Lock()
	for _, e := range f.relay.boxes[orgpki.AnswersMailbox(f.org.id)] {
		old = e.Payload // the last answer: the first renewal's
	}
	f.relay.rewrite = func(box string, p []byte) []byte {
		if box != orgpki.AnswersMailbox(f.org.id) {
			return p
		}
		var a, o orgpki.Answer
		_ = json.Unmarshal(p, &a)
		_ = json.Unmarshal(old, &o)
		o.ID = a.ID
		out, _ := json.Marshal(o)
		return out
	}
	f.relay.mu.Unlock()
	held := serial(f.m)
	f.clk.Add(17 * time.Hour)
	err := f.keeper().renew(f.ctx, "")
	if !errors.Is(err, orgmachine.ErrNotForKey) || serial(f.m) != held {
		t.Fatalf("installed a stale answer: err %v", err)
	}
	if _, err := orgmachine.Open(f.dir); err != nil {
		t.Fatalf("the machine's files after a refused answer: %v", err)
	}
}

// A revoke reaches the machine through the push (a parked long-poll woken
// by the issuer's publish), and through the backstop read when the relay
// withholds the push (Enrol.tla Fetch, mutant push-only). The revoke here
// is an account-revocation tie-in (orgissuer.RevokeMachines).
func TestRevokePushAndBackstop(t *testing.T) {
	for _, withhold := range []bool{false, true} {
		t.Run(map[bool]string{false: "push", true: "backstop"}[withhold], func(t *testing.T) {
			f := newFleet(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			k := f.keeper()
			if !withhold {
				k.FollowEvery = time.Hour // the push alone
			}
			keep(t, ctx, k)
			time.Sleep(200 * time.Millisecond) // the follows park on their cursors
			f.relay.mu.Lock()
			if withhold {
				f.relay.withhold = func(string) bool { return true }
			}
			f.relay.mu.Unlock()
			cur, _ := f.m.Current()
			changed := f.m.Changed()
			names, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now())
			check(t, err)
			if !slices.Equal(names, []string{"web-1"}) {
				t.Fatalf("revoked %v", names)
			}
			select {
			case <-changed:
			case <-time.After(hang):
				t.Fatal("the CRL did not reach the machine")
			}
			if _, err := f.m.CheckServer([]*x509.Certificate{cur, issuerOf(t, f.dir)}, "web-1", f.clk.Now()); err == nil {
				t.Fatal("a revoked machine still checks")
			}
		})
	}
}

func issuerOf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, orgmachine.CertFile), filepath.Join(dir, orgmachine.KeyFile))
	check(t, err)
	iss, err := x509.ParseCertificate(pair.Certificate[1])
	check(t, err)
	return iss
}

// The owner rotates with the recovery key: the machine takes the new root
// from the relay and renews into the new issuer at once (Enrol.tla
// TakeRoot, MachinesFollowRotation). At once also when the relay withholds
// the new issuer's CRL: the old root's CRL on disk does not hold the
// renewal back (a fleet test found it waiting for the
// backstop), and no renewal fails on the way (no retry here). And the
// new issuer's CRL is taken at once also when it reaches the machine
// before the rotation that certifies it (root-late): until the machine
// holds it, it admits no one under the new issuer.
func TestRotationMovesTheMachine(t *testing.T) {
	for _, mode := range []string{"push", "crl-withheld", "root-late"} {
		t.Run(mode, func(t *testing.T) { rotationMoves(t, mode) })
	}
}

func rotationMoves(t *testing.T, mode string) {
	f := newFleet(t)
	k := f.keeper()
	if mode != "push" {
		k.RetryWait, k.FollowEvery = time.Hour, time.Hour
	}
	f.relay.mu.Lock()
	switch mode {
	case "crl-withheld":
		f.relay.withhold = func(box string) bool { return box == orgid.CRLMailbox(f.org.id) }
	case "root-late":
		f.relay.late = func(box string) time.Duration {
			if box == orgpki.RootMailbox(f.org.id) {
				return 300 * time.Millisecond
			}
			return 0
		}
	}
	f.relay.mu.Unlock()
	keep(t, f.ctx, k)
	time.Sleep(200 * time.Millisecond) // the follows park on their cursors
	newRoot := f.rotate(t)
	eventually(t, "the machine renewed under the new root", func() bool {
		c, _ := f.m.Current()
		roots := x509.NewCertPool()
		roots.AddCert(newRoot)
		pair, err := tls.LoadX509KeyPair(filepath.Join(f.dir, orgmachine.CertFile), filepath.Join(f.dir, orgmachine.KeyFile))
		if err != nil {
			return false // between the key's write and the chain's
		}
		iss, err := x509.ParseCertificate(pair.Certificate[1])
		check(t, err)
		inter := x509.NewCertPool()
		inter.AddCert(iss)
		_, err = c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: f.clk.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		return err == nil
	})
	if mode == "crl-withheld" {
		return // no CRL of the new issuer until the backstop: it admits no one
	}
	eventually(t, "the machine admits sessions under the new issuer", func() bool {
		cur, _ := f.m.Current()
		pair, err := tls.LoadX509KeyPair(filepath.Join(f.dir, orgmachine.CertFile), filepath.Join(f.dir, orgmachine.KeyFile))
		if err != nil {
			return false
		}
		iss, err := x509.ParseCertificate(pair.Certificate[1])
		if err != nil {
			return false
		}
		_, err = f.m.CheckServer([]*x509.Certificate{cur, iss}, "web-1", f.clk.Now())
		return err == nil
	})
}

// rotate rotates the organisation with the recovery key (nfltr org
// rotate's steps) and returns the new root.
func (f *fleet) rotate(t *testing.T) *x509.Certificate {
	t.Helper()
	o := f.org
	var newRoot *x509.Certificate
	o.do(t, func(iss *orgpki.Issuer, s *orgissuer.Store) {
		nk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		check(t, err)
		now := f.clk.Now().Add(time.Second)
		cross, err := orgpki.CrossSign(iss.Recovery(), o.recKey, nk.Public(), iss.OrgID(), now)
		check(t, err)
		_, ikey, err := ed25519.GenerateKey(rand.Reader)
		check(t, err)
		check(t, orgissuer.WriteKey(s.Path(orgissuer.IssuerKeyFile+".new"), orgissuer.PEMIssuer, ikey, false))
		check(t, iss.Rotate(cross, "test2", nk, ikey, iss.Groups(), now))
		check(t, os.Rename(s.Path(orgissuer.IssuerKeyFile+".new"), s.Path(orgissuer.IssuerKeyFile)))
		newRoot = iss.Root()
	})
	return newRoot
}

// A machine new after a rotation joins with a token pinned on the current
// root (the fingerprint nfltr org status and nfltr org token print): the
// token names the organisation's mailboxes, which keep the id of the
// first root (a join that derived it from the pin read an empty
// mailbox).
func TestNewMachineJoinsAfterRotation(t *testing.T) {
	f := newFleet(t)
	newRoot := f.rotate(t)
	// The issuer service publishes the new root and its new issuer's CRL
	// (a join before then is refused: the root is not the pinned one).
	eventually(t, "the relay holds the new root and the new issuer's CRL", func() bool {
		f.relay.mu.Lock()
		defer f.relay.mu.Unlock()
		var rm orgpki.RootMessage
		var cm orgid.CRLMessage
		roots, crls := f.relay.boxes[orgpki.RootMailbox(f.org.id)], f.relay.boxes[orgid.CRLMailbox(f.org.id)]
		if len(roots) == 0 || len(crls) == 0 || json.Unmarshal(roots[len(roots)-1].Payload, &rm) != nil || json.Unmarshal(crls[len(crls)-1].Payload, &cm) != nil {
			return false
		}
		iss, err := x509.ParseCertificate(cm.Issuer)
		return bytes.Equal(rm.Root, newRoot.Raw) && err == nil && iss.CheckSignatureFrom(newRoot) == nil
	})
	pins := Pins{Root: orgid.Fingerprint(newRoot), Recovery: f.org.pins.Recovery}
	j, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "late"), pins, f.org.token(t, "web-late", f.clk.Now()), hang, f.clk.Now)
	check(t, err)
	if j.Cert.Subject.CommonName != "web-late" {
		t.Fatalf("enrolled as %q", j.Cert.Subject.CommonName)
	}
	// Pinned on the first root, a join takes the new one too: the pinned
	// recovery key certifies it, as a running machine takes a rotation
	// (Join.tla Trusts, mutant pin-root-only).
	j, err = Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "old"), f.org.pins, f.org.token(t, "web-old", f.clk.Now()), hang, f.clk.Now)
	check(t, err)
	if j.Cert.Subject.CommonName != "web-old" {
		t.Fatalf("enrolled as %q", j.Cert.Subject.CommonName)
	}
}

// A join pinned on the first root refuses a root another recovery key
// certifies, also one the relay pairs with the pinned recovery
// certificate (Join.tla JoinRootsAreOwners, mutant any-root).
func TestJoinRefusesARootOfAnotherRecoveryKey(t *testing.T) {
	f := newFleet(t)
	_, otherRec, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	otherRecCert, err := orgpki.NewRecovery(otherRec, f.org.id, f.clk.Now())
	check(t, err)
	nk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	evil, err := orgpki.CrossSign(otherRecCert, otherRec, nk.Public(), f.org.id, f.clk.Now().Add(time.Second))
	check(t, err)
	var rm orgpki.RootMessage
	f.relay.mu.Lock()
	roots := f.relay.boxes[orgpki.RootMailbox(f.org.id)]
	check(t, json.Unmarshal(roots[len(roots)-1].Payload, &rm))
	f.relay.mu.Unlock()
	for name, rec := range map[string][]byte{"its own recovery": otherRecCert.Raw, "the pinned recovery": rm.Recovery} {
		// The relay replaces the root message (the service publishes it
		// again only when its root changes, or a day on).
		msg, err := json.Marshal(orgpki.RootMessage{Root: evil.Raw, Recovery: rec})
		check(t, err)
		_, err = f.relay.Append(f.ctx, orgpki.RootMailbox(f.org.id), msg, mailboxclient.AppendOptions{ReplaceKey: "current"})
		check(t, err)
		_, err = Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "evil"), f.org.pins, f.org.token(t, "web-evil-"+strconv.Itoa(len(name)), f.clk.Now()), hang, f.clk.Now)
		if err == nil || !strings.Contains(err.Error(), "pinned") {
			t.Fatalf("a root of another recovery key with %s: %v, want refused", name, err)
		}
	}
}

// A token's second redemption, by another machine (another key), is
// refused with its cause named: the token was redeemed (Join.tla
// RefusedOnlyForCause: another key, a cause).
func TestReplayedTokenNamesTheCause(t *testing.T) {
	f := newFleet(t)
	tok := f.org.token(t, "web-2", f.clk.Now())
	if _, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "a"), f.org.pins, tok, hang, f.clk.Now); err != nil {
		t.Fatal(err)
	}
	_, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "b"), f.org.pins, tok, hang, f.clk.Now)
	if err == nil || !strings.Contains(err.Error(), "the token was redeemed") {
		t.Fatalf("replayed token: %v", err)
	}
}

// A join whose answer comes after it gave up (the issuer answered late:
// its lock held), run again with the token, joins with the key it kept,
// taking the first answer, the sealed A2A key with it (Join.tla, mutant
// new-key-per-join); one whose answer the relay lost, run again, is
// answered again for that key (mutant burn-name).
func TestJoinRunAgainAfterALateOrLostAnswer(t *testing.T) {
	f := newFleet(t)
	for _, lost := range []bool{false, true} {
		name := map[bool]string{false: "web-late", true: "web-lost"}[lost]
		tok := f.org.token(t, name, f.clk.Now())
		dir := filepath.Join(t.TempDir(), name)
		var dropped atomic.Bool
		answers := orgpki.AnswersMailbox(f.org.id)
		f.relay.mu.Lock()
		if lost {
			f.relay.drop = func(box string, _ []byte) bool { return box == answers && dropped.CompareAndSwap(false, true) }
		} else {
			f.relay.late = func(box string) time.Duration {
				if box == answers {
					return 1500 * time.Millisecond
				}
				return 0
			}
		}
		f.relay.mu.Unlock()
		if _, err := Join(f.ctx, f.relay, dir, f.org.pins, tok, time.Second, f.clk.Now); err == nil {
			t.Fatalf("%s: joined with its answer withheld", name)
		}
		f.relay.mu.Lock()
		f.relay.late, f.relay.drop = nil, nil
		f.relay.mu.Unlock()
		kept, err := os.ReadFile(filepath.Join(dir, JoinKeyFile))
		check(t, err)
		j, err := Join(f.ctx, f.relay, dir, f.org.pins, tok, hang, f.clk.Now)
		if err != nil {
			t.Fatalf("%s: run again: %v", name, err)
		}
		m, err := orgmachine.Open(dir)
		check(t, err)
		c, key := m.Current()
		b, _ := pem.Decode(kept)
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		check(t, err)
		if c.Subject.CommonName != name || !key.Equal(k) || j.Cert.SerialNumber.Cmp(c.SerialNumber) != 0 {
			t.Fatalf("%s: enrolled as %q, key kept %v", name, c.Subject.CommonName, key.Equal(k))
		}
		if _, err := os.Stat(filepath.Join(dir, JoinKeyFile)); !os.IsNotExist(err) {
			t.Fatalf("%s: the join key is left after the join: %v", name, err)
		}
		if !lost && j.KeyID != "m-"+name+".1" {
			t.Fatalf("%s: the first answer's A2A key not taken: %q", name, j.KeyID)
		}
	}
}

// An enrolment whose token names another machine of the account than the
// one that posted it is refused before the token is redeemed, naming both
// machines: its certificate's name routes to that machine, so a client
// dialling <machine>.<agent> would be refused (exit 7). A sender with an
// agent after its machine id is its machine.
func TestEnrolOnAnotherMachineIsRefused(t *testing.T) {
	const web1, web2 = "m-aaaaaaaaaaaaaaaaaaaaaaaaaa", "m-bbbbbbbbbbbbbbbbbbbbbbbbbb"
	account := map[string]string{"web-1": web1, "web-2": web2}
	f := newFleetWith(t, func(f *fleet) {
		f.relay.from = web1
		f.machineOf = func(_ context.Context, name string) (string, error) { return account[name], nil }
	})
	join := func(name, from string) error {
		f.relay.mu.Lock()
		f.relay.from = from
		f.relay.mu.Unlock()
		_, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), name), f.org.pins, f.org.token(t, name, f.clk.Now()), hang, f.clk.Now)
		return err
	}
	err := join("web-2", web1)
	if err == nil || !strings.Contains(err.Error(), "web-2") || !strings.Contains(err.Error(), web1) || !strings.Contains(err.Error(), web2) {
		t.Fatalf("web-2's token from web-1's machine: %v", err)
	}
	if err := join("web-2", web2+"-node"); err != nil { // not redeemed: a new token for the name enrols it
		t.Fatalf("web-2's token from its own machine: %v", err)
	}
}

// An enrolment under a name the account has no machine of is refused too,
// naming the token's name and the sender's machine (DISCOVERY-DX, the
// strict rule: an organisation machine's name is its account machine's
// name, so machines that share one key cannot enrol under other names).
func TestEnrolUnderANameTheAccountHasNotIsRefused(t *testing.T) {
	const web1 = "m-aaaaaaaaaaaaaaaaaaaaaaaaaa"
	f := newFleetWith(t, func(f *fleet) {
		f.relay.from = web1
		f.machineOf = func(_ context.Context, name string) (string, error) {
			return map[string]string{"web-1": web1}[name], nil
		}
	})
	_, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "lab-1"), f.org.pins, f.org.token(t, "lab-1", f.clk.Now()), hang, f.clk.Now)
	if err == nil || !strings.Contains(err.Error(), "lab-1") || !strings.Contains(err.Error(), web1) || !strings.Contains(err.Error(), "no machine named lab-1") {
		t.Fatalf("lab-1's token from web-1's machine: %v", err)
	}
}

// The Keeper's CRL follow alone takes a revoke's push: its machine's
// Changed fires and the revoked machine no longer checks (a held
// session to a revoked agent ends at the push).
func TestFollowCRLTakesTheRevokePush(t *testing.T) {
	f := newFleet(t)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	// The push alone; joined, so its CRL write ends before TempDir
	// removes the machine directory.
	go func() { defer close(done); followCRL(ctx, f.relay, f.m, time.Hour, f.clk.Now, quiet()) }()
	defer func() { cancel(); <-done }()
	time.Sleep(200 * time.Millisecond) // the follow parks on its cursor
	cur, _ := f.m.Current()
	changed := f.m.Changed()
	if _, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(hang):
		t.Fatal("the CRL did not reach the follower")
	}
	if _, err := f.m.CheckServer([]*x509.Certificate{cur, issuerOf(t, f.dir)}, "web-1", f.clk.Now()); err == nil {
		t.Fatal("a revoked machine still checks")
	}
}

// A revoke another process writes into the issuer's directory is
// published at its file-change notice, not at the issuer's next round
// (an hour here): the machine's follow takes it within the network's
// latency (spec/enrol/RevokePush.tla EventBound; mutant poll-only is the
// code before, which waited serveWait).
func TestRevokePublishedAtItsNotice(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.wait = time.Hour })
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { defer close(done); followCRL(ctx, f.relay, f.m, time.Hour, f.clk.Now, quiet()) }()
	defer func() { cancel(); <-done }()
	time.Sleep(200 * time.Millisecond) // the follow parks on its cursor
	cur, _ := f.m.Current()
	changed := f.m.Changed()
	start := time.Now()
	if _, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
		t.Logf("the CRL reached the machine %v after the revoke", time.Since(start))
	case <-time.After(3 * time.Second):
		t.Fatal("the CRL did not reach the machine within 3s of the revoke (the issuer's round is an hour)")
	}
	if _, err := f.m.CheckServer([]*x509.Certificate{cur, issuerOf(t, f.dir)}, "web-1", f.clk.Now()); err == nil {
		t.Fatal("a revoked machine still checks")
	}
}

// The owner revokes the issuer with the root (OrgHosted.tla RevokeIssuer,
// Deliver): the root's CRL of issuers kept in the issuer's directory is
// published with the root, the machine's keeper takes it into
// issuers.crl, and nothing under that issuer checks any more (mutant
// root-message-drops-issuers).
func TestRootRevocationOfTheIssuerReachesTheMachine(t *testing.T) {
	f := newFleet(t)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	keep(t, ctx, f.keeper())
	cur, _ := f.m.Current()
	iss := issuerOf(t, f.dir)
	if _, err := f.m.CheckServer([]*x509.Certificate{cur, iss}, "web-1", f.clk.Now()); err != nil {
		t.Fatalf("before the revocation: %v", err)
	}
	changed := f.m.Changed()
	f.org.do(t, func(i *orgpki.Issuer, s *orgissuer.Store) {
		der, err := orgpki.SignIssuerCRL(i.Root(), f.org.rootKey, nil, []*x509.Certificate{i.Cert()}, f.clk.Now())
		check(t, err)
		check(t, s.WriteIssuers(der))
	})
	// Refused and kept: the machine's verifier takes the CRL before
	// issuers.crl is written, and Changed only follows the write, so a
	// wake by another change can see the refusal before the file.
	deadline := time.After(hang)
	for {
		_, err := f.m.CheckServer([]*x509.Certificate{cur, iss}, "web-1", f.clk.Now())
		_, kept := os.Stat(filepath.Join(f.dir, orgmachine.IssuersFile))
		if err != nil && kept == nil {
			break
		}
		select {
		case <-changed: // a change, not necessarily this one
			changed = f.m.Changed()
		case <-deadline:
			t.Fatalf("the root's CRL of issuers did not reach the machine: check %v, issuers.crl %v", err, kept)
		}
	}
}

// The owner's machine publishes the root's CRL of issuers itself (the
// revoked issuer would not): PublishIssuers puts it beside the root the
// relay holds, refuses an older one, and the issuer service keeps it at
// its next republish of the root instead of overwriting it (mutant
// service-overwrites-issuers).
func TestOwnerPublishedIssuersKept(t *testing.T) {
	f := newFleet(t)
	root := f.org.root(t)
	var cert *x509.Certificate
	f.org.do(t, func(i *orgpki.Issuer, _ *orgissuer.Store) { cert = i.Cert() })
	first, err := orgpki.SignIssuerCRL(root, f.org.rootKey, nil, []*x509.Certificate{cert}, f.clk.Now())
	check(t, err)
	second, err := orgpki.SignIssuerCRL(root, f.org.rootKey, first, nil, f.clk.Now())
	check(t, err)
	check(t, PublishIssuers(f.ctx, f.relay, root, second, hang))
	if err := PublishIssuers(f.ctx, f.relay, root, first, hang); err == nil {
		t.Fatal("an older CRL of issuers published over a newer one")
	}
	f.clk.Add(rootEvery) // the service publishes the root again
	deadline := time.After(hang)
	for {
		data, err := os.ReadFile(filepath.Join(f.org.dir, orgissuer.IssuersFile))
		if err == nil && bytes.Equal(data, second) {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the issuer service did not keep the owner's CRL of issuers")
		case <-time.After(20 * time.Millisecond):
		}
	}
	data, err := latest(f.ctx, f.relay, orgpki.RootMailbox(f.org.id), hang)
	check(t, err)
	var rm orgpki.RootMessage
	check(t, json.Unmarshal(data, &rm))
	if !bytes.Equal(rm.Issuers, second) {
		t.Fatal("the root message lost the owner's CRL of issuers")
	}
}

// A join takes the root's CRL of issuers the relay holds beside the root,
// before it checks the issuer's answer: the new machine keeps it, and
// refuses an issuer it lists from its first session (OrgHosted.tla
// Deliver; mutant join-skips-issuers).
func TestJoinTakesTheRootsCRLOfIssuers(t *testing.T) {
	f := newFleet(t)
	root := f.org.root(t)
	var cert *x509.Certificate
	f.org.do(t, func(i *orgpki.Issuer, _ *orgissuer.Store) { cert = i.Cert() })
	none, err := orgpki.SignIssuerCRL(root, f.org.rootKey, nil, nil, f.clk.Now())
	check(t, err)
	check(t, PublishIssuers(f.ctx, f.relay, root, none, hang))
	dir := filepath.Join(t.TempDir(), "first")
	_, err = Join(f.ctx, f.relay, dir, f.org.pins, f.org.token(t, "web-first", f.clk.Now()), hang, f.clk.Now)
	check(t, err)
	if data, err := os.ReadFile(filepath.Join(dir, orgmachine.IssuersFile)); err != nil || !bytes.Equal(data, none) {
		t.Fatalf("the joined machine does not keep the CRL of issuers: %v", err)
	}
	revoked, err := orgpki.SignIssuerCRL(root, f.org.rootKey, none, []*x509.Certificate{cert}, f.clk.Now())
	check(t, err)
	check(t, PublishIssuers(f.ctx, f.relay, root, revoked, hang))
	if _, err := Join(f.ctx, f.relay, filepath.Join(t.TempDir(), "late"), f.org.pins, f.org.token(t, "web-late", f.clk.Now()), hang, f.clk.Now); err == nil {
		t.Fatal("a join took an answer from an issuer the root revoked")
	}
}

// The host sleeps under the keeper's wait for the renewal (its monotonic
// clock, which timers run on, stands still; the wall clock moves): the
// keeper reads the clock again at least every WakeEvery, so it renews when
// the wall clock reaches 2/3 of the lifetime, not as late as the host
// slept (incident 2026-11-18: the account certificate's single timer).
func TestKeeperRenewsOnTimeAfterTheHostSlept(t *testing.T) {
	f := newFleet(t)
	before := serial(f.m)
	k := f.keeper()
	// The machine's own clock: the issuer's stays, so no new CRL wakes
	// the keeper (a follow would, as in production; this checks the wait).
	mclk := &clock{t: f.clk.Now()}
	k.Now, k.WakeEvery = mclk.Now, 10*time.Millisecond
	keep(t, f.ctx, k)
	time.Sleep(50 * time.Millisecond) // the keeper waits for the renewal
	mclk.Add(17 * time.Hour)          // the host slept
	eventually(t, "renewed after the host slept", func() bool { return serial(f.m) != before })
}

// The issuer is out of reach (its mailbox down) from before the renewal
// until past the certificate's NotAfter, then back: the keeper, never
// restarted, renews within the grace (Enrol.tla RenewsAfterExpiry,
// mutant no-renew-after-expiry; incident 2026-11-19, the canary's
// machines expired during the mailbox outage and never renewed).
func TestKeeperRenewsAfterAnIssuerOutagePastExpiry(t *testing.T) {
	f := newFleet(t)
	before := serial(f.m)
	down := errors.New("the mailbox service is offline")
	var appends atomic.Int32
	f.relay.mu.Lock()
	f.relay.fail = func(box string) error {
		if box == orgpki.EnrolMailbox(f.org.id) {
			appends.Add(1)
		}
		return down
	}
	f.relay.mu.Unlock()
	keep(t, f.ctx, f.keeper())
	f.clk.Add(orgpki.MachineLife + time.Hour) // the outage outlasts the certificate
	eventually(t, "the keeper asks while the issuer is down", func() bool { return appends.Load() > 2 })
	if serial(f.m) != before {
		t.Fatal("renewed while the issuer was down")
	}
	f.relay.mu.Lock()
	f.relay.fail = nil
	f.relay.mu.Unlock()
	eventually(t, "renewed once the issuer is back", func() bool { return serial(f.m) != before })
	if cur, _ := f.m.Current(); !cur.NotAfter.After(f.clk.Now()) {
		t.Fatalf("the renewed certificate ends %s, before now %s", cur.NotAfter, f.clk.Now())
	}
}
