// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// Dialer opens sessions through one relay (Config.Relay) and to nf1
// addresses at theirs. It owns its data connections, its direct paths and
// their goroutines; Close ends them, which resets every Conn riding them.
type Dialer struct {
	cfg Config

	poolOnce sync.Once
	pool     *link.Pool
	poolErr  error
	policy   atomic.Value // the latest 101's E2EE policy

	mu      sync.Mutex
	closed  bool
	direct  map[string]*agent.DirectClient // by QAD relay: "" the organisation's, else an nf1 address's relay
	nf1Muxs map[*dataplane.Mux]struct{}    // each nf1 session's own data connection
}

// NewDialer checks cfg and returns its Dialer; it connects nothing yet.
func NewDialer(cfg Config) (*Dialer, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &Dialer{cfg: cfg, direct: map[string]*agent.DirectClient{}, nf1Muxs: map[*dataplane.Mux]struct{}{}}, nil
}

// Dial is a one-shot Dialer's Dial: its Conn's Close closes the Dialer.
func Dial(ctx context.Context, cfg Config, target string) (*Conn, error) {
	d, err := NewDialer(cfg)
	if err != nil {
		return nil, err
	}
	c, err := d.Dial(ctx, target, DialOptions{})
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	c.closers = append(c.closers, func() { _ = d.Close() })
	return c, nil
}

// Dial parses target (ParseTarget) and opens a session to it (DialTarget).
func (d *Dialer) Dial(ctx context.Context, target string, o DialOptions) (*Conn, error) {
	t, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	return d.DialTarget(ctx, t, o)
}

// DialTarget opens a session to t and waits for its answer (o.Early: not
// for the answer). ctx bounds the open only: an agent offline, a relay that
// cannot route for now, a path lost before the agent answered are asked
// again until ctx ends, then the last such refusal (CodeNotFound,
// CodeUnreachable) is returned, wrapping ctx's error. The Conn outlives
// ctx.
func (d *Dialer) DialTarget(ctx context.Context, t Target, o DialOptions) (*Conn, error) {
	var c *Conn
	err := hold(ctx, !o.Early, func() (err error) {
		c, err = d.dialOnce(ctx, t, o)
		return err
	})
	if err != nil {
		d.emit(Event{Kind: "error", Target: t.String(), Err: asError(err)})
		return nil, err
	}
	c.emit(Event{Kind: "open"})
	return c, nil
}

// Close ends the Dialer's data connections and direct paths: every open
// Conn of it is reset, and no session opens after it.
func (d *Dialer) Close() error {
	d.mu.Lock()
	d.closed = true
	muxs, direct := d.nf1Muxs, d.direct
	d.nf1Muxs, d.direct = nil, nil
	d.mu.Unlock()
	d.poolOnce.Do(func() { d.poolErr = net.ErrClosed }) // no Pool after Close
	if d.pool != nil {
		_ = d.pool.Close()
	}
	for m := range muxs {
		_ = m.Close()
	}
	for _, dc := range direct {
		_ = dc.Close()
	}
	return nil
}

// DirectStats are the direct-path counts of the Dialer's sessions that
// asked for one, organisation and nf1 sessions summed; ok is false before
// a session asked.
func (d *Dialer) DirectStats() (agent.DirectStats, bool) {
	d.mu.Lock()
	dcs := make([]*agent.DirectClient, 0, len(d.direct))
	for _, dc := range d.direct {
		dcs = append(dcs, dc)
	}
	d.mu.Unlock()
	sum := agent.DirectStats{Punches: map[string]uint64{}, Sessions: map[string]int{}, QAD: map[string]uint64{}}
	for _, dc := range dcs {
		s := dc.Stats()
		sum.DirectSent += s.DirectSent
		sum.DirectReceived += s.DirectReceived
		sum.RelayedSent += s.RelayedSent
		sum.RelayedReceived += s.RelayedReceived
		for k, v := range s.Punches {
			sum.Punches[k] += v
		}
		for k, v := range s.Sessions {
			sum.Sessions[k] += v
		}
		for k, v := range s.QAD {
			sum.QAD[k] += v
		}
	}
	return sum, len(dcs) > 0
}

func (d *Dialer) emit(e Event) {
	if d.cfg.Events != nil {
		e.Time = time.Now()
		d.cfg.Events(e)
	}
}

// errClosed is a dial on a closed Dialer.
var errClosed = &Error{Code: CodeUsage, Message: "nfnet: the Dialer is closed", Err: net.ErrClosed}

// dialOnce is one open of t.
func (d *Dialer) dialOnce(ctx context.Context, t Target, o DialOptions) (*Conn, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, errClosed
	}
	if t.Kind == AddressTarget {
		return d.dialNF1(ctx, t, o)
	}
	org := d.cfg.Org
	if o.Plain {
		org = nil
	}
	switch {
	case d.cfg.Relay == "":
		return nil, usage("Config.Relay is empty: only an nf1 address names its own relay")
	case t.Kind == GroupTarget && org == nil:
		return nil, usage(fmt.Sprintf("service names (%s) need this machine in an organisation (Config.Org) and no Plain; or dial one machine: <machine>.<agent>/%s", t, t.Service))
	case o.Direct != DirectOff && org == nil:
		return nil, usage("a direct path needs organisation mode (Config.Org, not Plain) or an nf1 address")
	}
	var c *Conn
	err := retryGroup(ctx, t, func(exclude []string) (err error) {
		c, err = d.open(ctx, t, org, o, exclude)
		return err
	})
	return c, err
}

// agentID is the open's agent_id: the agent as the relay resolves it, or a
// group dial's <service>@<group>.
func agentID(t Target) string {
	switch t.Kind {
	case MachineTarget:
		return t.Machine + "." + t.Agent
	case GroupTarget:
		return t.Service + "@" + t.Group
	}
	return t.Agent
}

// open is one open of t through the relay, the instances exclude names left
// out (a group dial): answered before it returns unless o.Early; with org,
// TLS of organisation mode with the machine t names (or any machine of its
// group) on it.
func (d *Dialer) open(ctx context.Context, t Target, org *orgid.Identity, o DialOptions, exclude []string) (*Conn, error) {
	ls, err := d.openData(ctx, &pb.TCPData{AgentId: agentID(t), TargetAddr: t.Service, E2Ee: org != nil, Exclude: exclude})
	if err != nil {
		return nil, err
	}
	if !ls.Answers() {
		_ = ls.Close()
		return nil, &Error{Code: CodeRefused, Message: "the relay does not answer session opens (relay-server before v0.22.0): update the relay"}
	}
	c := d.newConn(t, traceOf(ls))
	if o.Early {
		c.answerEarly(ctx, ls)
	} else if err := answered(ctx, ls); err != nil {
		return nil, err
	}
	if org == nil {
		c.s, c.done = ls, ls.Done()
		return c, nil
	}
	run := c.orgSession(d, ls, t, org, o.Direct)
	if err := c.handshake(ctx); err != nil {
		_ = ls.Close()
		if aerr := c.Answered(context.Background()); aerr != nil { // Early: a refusal says more than the handshake
			return nil, aerr
		}
		return nil, err
	}
	run()
	return c, nil
}

// answered waits for ls's answer: nil once the agent accepted, else the
// refusal (ls closed) or, with ctx ended or the session gone first, why.
func answered(ctx context.Context, ls *dataplane.Session) error {
	err := ls.Answered(ctx)
	if err == nil {
		return nil
	}
	_ = ls.Close()
	if a, ok := errors.AsType[*link.Abort](err); ok && a.Refused {
		return answerError(a, traceOf(ls))
	}
	return openFailure(ctx, ls, err)
}

// openFailure types an open's failure that is no *Error: no answer within
// ctx, or the session's end before one.
func openFailure(ctx context.Context, ls *dataplane.Session, err error) error {
	if _, ok := err.(*Error); ok {
		return err
	}
	if ctx.Err() != nil {
		return &Error{Code: CodeUnreachable, Message: "no answer within the open timeout (trace " + traceOf(ls) + ")", Err: ctx.Err()}
	}
	return &Error{Code: CodeReset, Message: "session ended before its answer: " + err.Error(), Err: err}
}

// traceOf is the session's trace id as the relays log it.
func traceOf(ls *dataplane.Session) string {
	t := ls.Chain().Trace
	return hex.EncodeToString(t[:])
}

// answerError is the *Error of a refusal: its reason (an ErrorReason from
// the relay or the agent), or link's own code from a hop on the way (a
// draining relay, a connection lost, no route). The answer is
// unauthenticated: it names the way, never changes the mode.
func answerError(a *link.Abort, trace string) *Error {
	e := &Error{Code: CodeRefused, Err: a}
	where := fmt.Sprintf("hop %d, trace %s", a.Hops, trace)
	reason, ok := dataplane.AbortReason(a)
	if !ok {
		if a.Code != link.CodeHopLimit && a.Code != link.CodeRefused {
			e.Code = CodeUnreachable // draining, a connection lost, no route, a timeout: try again
		}
		e.Unopened = a.Code == link.CodeConnLost || a.Code == link.CodeNoRoute || a.Code == link.CodeDraining
		e.Message = fmt.Sprintf("%v (%s)", a, where)
		return e
	}
	switch reason {
	case relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED:
		e.Code = CodeAuth
	case relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED:
		e.Code = CodeBalanceExhausted
	case relayv1.ErrorReason_ERROR_REASON_AGENT_NOT_FOUND, relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE,
		relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE:
		e.Code = CodeNotFound
	case relayv1.ErrorReason_ERROR_REASON_TARGET_UNREACHABLE, relayv1.ErrorReason_ERROR_REASON_RELAY_DRAINING,
		relayv1.ErrorReason_ERROR_REASON_DIRECTORY_UNAVAILABLE: // the relay could not read its agent directory: try again
		e.Code = CodeUnreachable
	case relayv1.ErrorReason_ERROR_REASON_INVALID_ARGUMENT:
		e.Code = CodeUsage
	case relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE:
		e.Code = CodeE2EEPinMismatch // an organisation session to a plain service fails closed
	}
	e.Reason = reason.String()
	e.Message = fmt.Sprintf("%s (%s)", a.Msg, where)
	switch reason {
	case relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE:
		e.Message += ": the service is not in organisation mode; DialOptions.Plain reaches a plain service on purpose"
	case relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED:
		e.Message += ": the service is in organisation mode; open it from a machine enrolled in its organisation, without Plain"
	}
	return e
}

// holdInterval is the least time between two held opens. A relay that
// holds the open itself (relay-server v0.33.5+: it wakes it when the agent
// registers, up to 500 ms) answers offline only after its hold, so the
// next open goes out at once; one that answers at once is asked again
// after holdInterval.
const holdInterval = 250 * time.Millisecond

var heldReasons = map[string]bool{
	relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE.String():         true,
	relayv1.ErrorReason_ERROR_REASON_DIRECTORY_UNAVAILABLE.String(): true,
}

// hold runs open until its answer is not one to hold for: the agent
// offline (or unknown: the relay does not tell them apart), a relay that
// cannot route the open for now, a path lost before the agent answered
// (Unopened). Asking again is safe: an open sends no byte before the
// answer and the far end none before it accepted (link spec/Link.tla
// DataOK). When ctx ends it returns the last such refusal, wrapping ctx's
// error. Without again (an early open, whose bytes went with it) it runs
// open once.
func hold(ctx context.Context, again bool, open func() error) error {
	var held *Error // the last refusal held for
	last := func() error {
		held.Err = errors.Join(held.Err, ctx.Err())
		return held
	}
	for {
		asked := time.Now()
		err := open()
		e, ok := errors.AsType[*Error](err)
		switch {
		case again && ok && (heldReasons[e.Reason] || e.Unopened):
			held = e
		case err != nil && held != nil && ctx.Err() != nil:
			return last() // ctx cut an attempt while held
		default:
			return err
		}
		select {
		case <-ctx.Done():
			return last()
		case <-time.After(holdInterval - time.Since(asked)):
		}
	}
}
