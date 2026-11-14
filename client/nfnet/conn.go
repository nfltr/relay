// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/rpcclient"
	"github.com/nfltr/relay/client/tlsend"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// session is what a Conn carries: a link session (plain), or TLS on one
// (organisation mode, nf1: *tlsend.Conn).
type session interface {
	net.Conn
	CloseWrite() error
	Reset() error
}

// Conn is one session: a net.Conn with a half close (CloseWrite) and a
// failed end (Reset). Read returns io.EOF only at the peer's half close
// (under end-to-end TLS, after its close_notify); a session cut is an
// *Error CodeReset (Reason "drain_deadline" when a leaving relay's drain
// cut it, CodeAuth when the relay revoked the key, CodeBalanceExhausted).
// Write blocks on the session's credit and buffers nothing beyond it.
type Conn struct {
	s       session
	done    <-chan struct{}
	tc      *tlsend.Conn         // the end-to-end TLS; nil when plain
	ds      *agent.DirectSession // a direct-path session; nil: relayed only
	refused atomic.Pointer[string]
	target  Target
	id      string
	trace   string
	events  func(Event)
	answer  chan error // Early: the open's outcome; nil: answered before Dial returned
	e2ee    bool       // an accepted session the agent ended end-to-end TLS for
	caller  *Caller    // an accepted session's caller, as the relay named it
	remote  string     // an accepted session's RemoteAddr: the caller's machine
	closers []func()   // what ends with the Conn: an nf1 session's data connection, a one-shot Dialer

	readMu   sync.Mutex // a link session reads one at a time: net.Conn's concurrent Reads take turns
	in, out  atomic.Int64
	failure  atomic.Pointer[Error]
	endOnce  sync.Once
	answerMu sync.Mutex
	answered error
	answerOK bool
}

func (d *Dialer) newConn(t Target, trace string) *Conn {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return &Conn{target: t, id: "s-" + hex.EncodeToString(b[:]), trace: trace, events: d.cfg.Events}
}

// answerEarly waits for ls's answer in the background, for Answered: until
// it comes or the session ends (Close ends it), not bounded by the dial's
// ctx, which bounds only Dial; a refusal closes ls.
func (c *Conn) answerEarly(ctx context.Context, ls *dataplane.Session) {
	c.answer = make(chan error, 1)
	ctx = context.WithoutCancel(ctx)
	go func() { c.answer <- answered(ctx, ls) }()
}

// Answered is an Early dial's outcome: nil once the agent accepted, else
// the refusal Dial would have returned (the session is closed then); ctx
// bounds the wait. A dial without Early has its answer: nil at once.
func (c *Conn) Answered(ctx context.Context) error {
	if c.answer == nil {
		return nil
	}
	c.answerMu.Lock()
	defer c.answerMu.Unlock()
	if !c.answerOK {
		select {
		case c.answered = <-c.answer:
			c.answerOK = true
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.answered
}

// Read reads the peer's bytes: io.EOF at its half close, a typed *Error at
// a cut or refusal, os.ErrDeadlineExceeded past a read deadline.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	n, err := c.s.Read(p)
	if n == 0 && err == io.EOF {
		// ponytail: link v0.12.11's Session.Read can return io.EOF on a live
		// session when a SetReadDeadline clears a passed deadline as that
		// deadline wakes the Read; a second Read tells (a real end is EOF
		// again at once). Drop once link's Read reports the wakeup itself.
		n, err = c.s.Read(p)
	}
	c.readMu.Unlock()
	c.in.Add(int64(n))
	if err != nil {
		err = c.early(err)
	}
	if err != nil && err != io.EOF {
		err = c.fail(err)
	}
	return n, err
}

// early is an Early session's refusal when it ended unanswered (no byte
// comes before the accept, so the answer is in by the end), else err.
func (c *Conn) early(err error) error {
	if c.answer != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		if aerr := c.Answered(context.Background()); aerr != nil {
			return aerr
		}
	}
	return err
}

// Write sends p, blocking on the session's credit.
func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.s.Write(p)
	c.out.Add(int64(n))
	if err != nil {
		err = c.fail(c.early(err))
	}
	return n, err
}

// CloseWrite is our half close: the peer reads EOF after our bytes, its
// own still arrive (link END; under TLS close_notify first).
func (c *Conn) CloseWrite() error { return c.s.CloseWrite() }

// Close ends both directions cleanly (under TLS close_notify first) and
// what the Conn owns.
func (c *Conn) Close() error {
	err := c.s.Close()
	c.end()
	return err
}

// Reset ends the session as failed: the peer reads a reset, never a clean
// end (no close_notify under TLS).
func (c *Conn) Reset() error {
	err := c.s.Reset()
	c.end()
	return err
}

func (c *Conn) end() {
	c.endOnce.Do(func() {
		for _, f := range c.closers {
			f()
		}
		c.emit(Event{Kind: "close", BytesIn: c.in.Load(), BytesOut: c.out.Load(), Err: c.failure.Load()})
	})
}

// Done is closed once the session has ended: the peer ended it whole, or
// both sides half-closed; an accepted Conn's at its Close or Reset.
func (c *Conn) Done() <-chan struct{} { return c.done }

// SetDeadline, SetReadDeadline and SetWriteDeadline are the session's: a
// read or write past one fails with os.ErrDeadlineExceeded.
func (c *Conn) SetDeadline(t time.Time) error      { return c.s.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.s.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

// Addr is a session end's address: the target as dialled.
type Addr struct{ Target string }

func (Addr) Network() string  { return "nfltr" }
func (a Addr) String() string { return a.Target }

// LocalAddr is this end's (the session id); RemoteAddr the target dialled,
// or for an accepted Conn the caller's machine (its name; "" when the
// relay named none).
func (c *Conn) LocalAddr() net.Addr { return Addr{Target: c.id} }
func (c *Conn) RemoteAddr() net.Addr {
	if c.caller != nil {
		return Addr{Target: c.remote}
	}
	return Addr{Target: c.target.String()}
}

// Info describes a session.
type Info struct {
	Target   string // redacted for nf1: "nf1:<rid prefix>@<relay>"
	Session  string // "s-7f3a91c2", the events' id
	Trace    string // the relays' trace id
	E2EE     bool
	Instance string  // the machine the server's certificate names (a group dial: the relay's pick)
	Path     string  // "relayed" | "direct"
	Caller   *Caller // an accepted session's caller, as the relay authenticated it; nil for a dial
}

// Info is the session's description now (Path follows its moves).
func (c *Conn) Info() Info {
	i := Info{Target: c.target.String(), Session: c.id, Trace: c.trace, E2EE: c.tc != nil || c.e2ee, Path: agent.PathRelayed, Caller: c.caller}
	if c.tc != nil && c.target.Kind != AddressTarget {
		if certs := c.tc.ConnectionState().PeerCertificates; len(certs) > 0 {
			i.Instance = certs[0].Subject.CommonName
		}
	}
	if c.ds != nil {
		i.Path = c.ds.Path()
	}
	return i
}

// Event is one of a session's events, as nfltr cat pipe prints them: open,
// path (a move: Path, and Err's Reason why when relayed), close (the byte
// counts; Err the session's failure, nil for a clean end), error (a dial
// that failed).
type Event struct {
	Kind              string
	Time              time.Time
	Target, Session   string
	E2EE              bool
	Instance, Path    string
	Reason            string // a path event's: why it is relayed ("" when direct)
	BytesIn, BytesOut int64
	Err               *Error
}

func (c *Conn) emit(e Event) {
	if c.events == nil {
		return
	}
	i := c.Info()
	e.Time, e.Target, e.Session, e.E2EE, e.Instance = time.Now(), i.Target, i.Session, i.E2EE, i.Instance
	if e.Path == "" {
		e.Path = i.Path
	}
	c.events(e)
}

// onPath reports a direct path's move as a path event.
func (c *Conn) onPath(p agent.PathEvent) { c.emit(Event{Kind: "path", Path: p.Path, Reason: p.Reason}) }

// fail types a read's or write's error: a deadline and our own Close come
// back unchanged, the rest is the session's failure (the first is kept
// for the close event).
func (c *Conn) fail(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return err
	}
	e := resetError(clientRefused(err))
	c.failure.CompareAndSwap(nil, e)
	return e
}

// ReasonDrainDeadline is the Reason of a CodeReset whose session a leaving
// relay cut at its drain's deadline (link.CodeDrainDeadline): a new
// session opens on another connection.
const ReasonDrainDeadline = "drain_deadline"

// resetError types a session's cut: CodeReset, with its reason when a
// leaving relay's drain deadline cut it; CodeAuth when the relay revoked
// the session's key, CodeBalanceExhausted when the account's balance ran
// out.
func resetError(err error) *Error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e // typed already (clientRefused)
	}
	if a, ok := errors.AsType[*link.Abort](err); ok {
		if a.Code == link.CodeDrainDeadline {
			return &Error{Code: CodeReset, Reason: ReasonDrainDeadline, Err: err,
				Message: fmt.Sprintf("session cut at a leaving relay's drain deadline (hop %d): open a new session", a.Hops)}
		}
		switch reason, _ := dataplane.AbortReason(a); reason {
		case relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED:
			return &Error{Code: CodeAuth, Reason: reason.String(), Message: "session cut by the relay: " + a.Msg, Err: err}
		case relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED:
			return &Error{Code: CodeBalanceExhausted, Reason: reason.String(), Message: "session cut by the relay: " + rpcclient.BalanceExhaustedHint, Err: err}
		}
	}
	return &Error{Code: CodeReset, Message: "session reset: " + err.Error(), Err: err}
}

// clientRefused is the *Error of a service's refusal of this machine's
// certificate (the bad_certificate alert of its check, or
// certificate_required without one): TLS 1.3 completes the handshake here
// first, so it arrives on the first read. Other errors unchanged.
func clientRefused(err error) error {
	op, ok := errors.AsType[*net.OpError](err)
	if !ok || op.Op != "remote error" {
		return err
	}
	if msg := op.Err.Error(); msg != "tls: bad certificate" && msg != "tls: certificate required" {
		return err
	}
	return &Error{Code: CodeE2EEClientRefused, Message: "the service refused this machine's organisation certificate (not in its allowed groups, revoked or expired): " + err.Error(), Err: err}
}

// handshake runs the end-to-end TLS handshake: a failure is
// CodeE2EEPinMismatch (a certificate that is not the one the target names,
// or no TLS from the far side: a relay that stripped it), naming the
// refused machine for a group dial's next pick; within ctx, else
// CodeUnreachable.
func (c *Conn) handshake(ctx context.Context) error {
	err := c.tc.HandshakeContext(ctx)
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return &Error{Code: CodeUnreachable, Message: "no answer within the open timeout (trace " + c.trace + ")", Err: ctx.Err()}
	}
	return &Error{Code: CodeE2EEPinMismatch, Message: "end-to-end TLS with the agent failed: " + err.Error(), Err: err, peer: c.refusedPeer()}
}

func (c *Conn) refusedPeer() string {
	if p := c.refused.Load(); p != nil {
		return *p
	}
	return ""
}

// recordRefused makes cfg record the machine whose certificate its check
// refused (a group dial excludes it from the next pick).
func (c *Conn) recordRefused(cfg *tls.Config) {
	verify := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		err := verify(cs)
		if err != nil && len(cs.PeerCertificates) > 0 {
			c.refused.Store(&cs.PeerCertificates[0].Subject.CommonName)
		}
		return err
	}
}

// asError is err as an *Error (a typed one, else CodeOf's class).
func asError(err error) *Error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	return &Error{Code: CodeOf(err), Message: err.Error(), Err: err}
}
