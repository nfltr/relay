// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Direct paths for capability-address (nf1) sessions (nfltr
// docs/decisions/nf1-direct-2026-11-14.md, direct-once-2026-11-22.md):
// the organisation's direct paths (direct.go, direct_server.go,
// direct_client.go) with an nf1 identity, the path layer over per-epoch
// channels (relay spec/proverif/direct_once.pv). A listener that takes
// them says so in its signed hints (nf1.HintDirect); after its answer
// frame the client's first byte picks the stream's kind: a TLS record (a
// session: plain, or framed for direct paths by the TLS's ALPN, pathswitch
// inside it), nf1MarkControl (a control exchange inside the address's
// pinned, admitted TLS) or nf1MarkAttach (a relayed re-attach: a fresh TLS
// to the pinned key, the OPEN inside it). The direct QUIC connection shows
// the address's certificate, which the client pins as the relayed TLS
// (BIND:nf1direct.pin); the tokens are the organisation's, keyed by the
// address session's exporter and bound to each epoch's channel.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// The client's first byte after an nf1 answer that took direct paths:
// neither a TLS record nor a path frame.
const (
	nf1MarkControl = 'C'
	nf1MarkAttach  = 'A'
	nf1MarkBrowser = 'B' // a browser visitor's control session (HintBrowser)
)

// BrowserDirect serves the direct path of an nf1 service's browser
// visitors (Service.BrowserDirect): client/p2p's BrowserDirect, an
// interface here so an agent that serves none links no WebRTC.
// ServeBrowser takes a control session after the answer and the mark,
// admits it and serves its connection's data channels, each an nf1
// session of l handed to serve once admitted; it closes ctl and returns
// once the control session, its connection and every stream ended.
type BrowserDirect interface {
	ServeBrowser(ctx context.Context, ctl net.Conn, l *nf1.Listener, serve func(ctx context.Context, tc net.Conn))
}

// nf1SNIPrefix starts the server name of an nf1 session's direct
// connection: nf1SNIPrefix + hex(HMAC(session key, nf1SNILabel)[:16]),
// fresh per session, so it links nothing without the session's key; the
// agent finds the session's listener by it (a wrong certificate is the pin's
// refusal whatever the name, so it needs no binding).
const (
	nf1SNIPrefix = "nf1-"
	nf1SNILabel  = "nf1-direct-sni"
)

func nf1SNI(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(nf1SNILabel))
	return nf1SNIPrefix + hex.EncodeToString(m.Sum(nil)[:16])
}

func isNF1SNI(name string) bool { return strings.HasPrefix(name, nf1SNIPrefix) }

// serveNF1Direct serves a session of an nf1 service whose listener takes
// direct paths or browser visitors' data channels, its open accepted: the
// answer, then by the client's first byte a session (a TLS record: the
// address's TLS, proof and kind: serveNF1Session), a control exchange, a
// re-attach (reattachNF1) or a browser visitor's control session
// (p.browser; d nil without direct paths). Any other first byte is
// refused: a path frame there was the layering before direct_once.pv
// (pathswitch under the session's TLS), frames outside every channel
// (BIND:once.plain). A control exchange or a re-attach never reaches the
// service's target, and never fails because it is busy or down.
func serveNF1Direct(ctx context.Context, s net.Conn, p sessionPlan, logger *slog.Logger) {
	l, d := p.nf1, p.direct
	if err := l.WriteAnswer(s); err != nil {
		_ = s.Close()
		return
	}
	first, ps, err := peekFirst(s, e2eeHeaderTimeout)
	if err != nil {
		_ = s.Close()
		return
	}
	if l.Anonymous() && first == nf1MarkAttach {
		// served with no account: a session that comes back to the relay
		// is refused
		_ = nf1.AbortDirectRequired(s)
		return
	}
	if first != tlsRecordHandshake && first != nf1MarkBrowser && d == nil {
		_ = s.Close() // the listener takes no direct paths: a mark of theirs is no session
		return
	}
	switch first {
	case tlsRecordHandshake:
		serveNF1Session(ctx, s, ps, p, logger)
	case nf1MarkBrowser:
		if p.browser == nil {
			_ = s.Close()
			return
		}
		p.browser.ServeBrowser(ctx, s, l, func(ctx context.Context, tc net.Conn) { // s: the mark consumed
			target, _, err := p.dial(ctx)
			if err != nil {
				logger.Warn("nf1 browser direct path: dial target failed", "target", p.target, "error", err)
				_ = tc.Close()
				return
			}
			_ = peerlink.Join(tc, target)
		})
	case nf1MarkControl:
		tc := admitNF1(ctx, l, s, logger) // s: the mark consumed
		if tc == nil {
			return
		}
		defer tc.Close() //nolint:errcheck
		_ = tc.SetDeadline(time.Now().Add(directControlBound))
		mode := d.modes[p.bind.service]
		if err := d.control(tc, p.relay, "", func(string) DirectMode { return mode }); err != nil {
			logger.Info("nf1 direct path: control exchange ended", "error", err)
		}
	case nf1MarkAttach:
		d.reattachNF1(l, s) // s: the mark consumed
	default:
		_ = pathStream{Conn: s}.Reset()
	}
}

// serveNF1Session serves an nf1 session (its first byte a TLS record, ps
// with it put back): the address's TLS, proof and kind (nf1.AdmitKind;
// framed only when the listener takes direct paths), then a plain session
// bridged to its target, or a framed one (direct_once.pv epoch 0): link
// pathswitch inside this TLS, movable by its exporter's tokens. The
// target is dialled before the admission (as a plain session's always
// was); for an address served with no account only once the session is
// on its direct path (serveNF1Anon).
func serveNF1Session(ctx context.Context, s, ps net.Conn, p sessionPlan, logger *slog.Logger) {
	l, d := p.nf1, p.direct
	done := func() {}
	if d != nil {
		// a framed session's OPEN on its direct path can come before it is
		// registered (TestDirectOpenBeforeTheAgentsHandshake): find waits
		done = d.handshaking()
		defer done()
	}
	var target net.Conn
	if !l.Anonymous() {
		if target = dialNF1Target(ctx, p, ps, logger); target == nil {
			return
		}
	}
	tc, kind, err := admitNF1Kind(ctx, l, ps, d != nil, logger)
	switch {
	case errors.Is(err, nf1.ErrDirectRequired):
		// served with no account: a plain session, which could never
		// leave the relay, refused before its verdict
		_ = nf1.AbortDirectRequired(s)
	case tc == nil:
		if target != nil {
			dropTarget(target)
		}
	case kind == nf1.KindPlain && target == nil: // AdmitKind refused it already: no target to serve
		_ = nf1.AbortDirectRequired(s)
	case kind == nf1.KindPlain:
		done()
		join(tc, nil, target)
	case l.Anonymous():
		serveNF1Anon(ctx, s, tc, p, done, logger)
	default:
		key, err := sessionKey(tc.ConnectionState())
		if err != nil {
			_ = tc.Reset()
			dropTarget(target)
			return
		}
		c := pathswitch.Server(pathStream{Conn: tc}, PathRelayed, pathswitch.Config{Detach: d.detach, Window: tcpDataWindow, MaxWindow: directMaxWindow})
		pc := newPSConn(c, s)
		setDirect(target, d.registerSession(&directSession{c: c, key: key, nf1: l, sni: nf1SNI(key)}))
		done()
		_ = joinTarget(pc, pc, target)
	}
}

// serveNF1Anon serves a framed session of an address served with no
// account (nfltr docs/decisions/nf1-anon-2026-11-16.md section 2), tc its
// admitted TLS: the service's target is dialled only once the session is
// on a direct path, so no byte of the service crosses the relay; none
// within nf1AnonDirectBound ends the session with
// ERROR_REASON_ACCOUNT_REQUIRED. The direct path's loss ends it too (the
// client never re-attaches it relayed): the target reads the same reason.
func serveNF1Anon(ctx context.Context, s net.Conn, tc *tlsend.Conn, p sessionPlan, done func(), logger *slog.Logger) {
	d := p.direct
	key, err := sessionKey(tc.ConnectionState())
	if err != nil {
		_ = tc.Reset()
		return
	}
	relayed := pathStream{Conn: tc, end: &streamEnd{}}
	c := pathswitch.Server(relayed, PathRelayed, pathswitch.Config{Detach: d.detach, Window: tcpDataWindow, MaxWindow: directMaxWindow})
	tap := &detachTap{Conn: newPSConn(c, s)}
	gone := make(chan struct{})
	lost := sync.OnceFunc(func() { tap.detached.Store(true); close(gone); c.Abort() })
	relayed.end.set(anonLost(c, relayed, lost))
	ds := d.registerSession(&directSession{c: c, key: key, nf1: p.nf1, sni: nf1SNI(key), lost: lost})
	done()
	if !onPathWithin(c, PathDirect, nf1AnonDirectBound, gone) {
		if c.Path() == PathRelayed {
			_ = nf1.AbortDirectRequired(s)
		}
		c.Abort()
		return
	}
	target, _, err := p.dial(ctx)
	if err != nil {
		logger.Warn("nf1: dial target failed", "target", p.target, "error", err)
		c.Abort()
		return
	}
	setDirect(target, ds)
	if q, ok := target.(*QueueConn); ok {
		target = &anonTarget{QueueConn: q, tap: tap}
	}
	_ = joinTarget(tap, ackerOf(tap.Conn), target)
}

// reattachNF1 takes a relayed re-attach of a session of l whose path died
// (direct_once.pv ReattachAgent, BIND:once.reattach): a fresh TLS 1.3
// handshake under l's key on the new stream (the client presents no
// certificate: the token proves the session), then, inside it, the OPEN
// with the client's token over that handshake's own exporter
// (BIND:once.channel) for a session of l's address; this end's token for
// the epoch goes first after the attach (the client binds the stream only
// on it). Every frame of the epoch is inside this TLS (BIND:once.offset).
func (d *directServer) reattachNF1(l *nf1.Listener, s net.Conn) {
	_ = s.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	tc := tlsend.Server(s, nf1ReattachTLS(l))
	if err := tc.Handshake(); err != nil {
		_ = pathStream{Conn: s}.Reset()
		return
	}
	x, err := reattachKey(tc.ConnectionState())
	if err != nil {
		_ = tc.Reset()
		return
	}
	ps := pathStream{Conn: tc, first: new(firstWrite)}
	o, err := pathswitch.ReadOpen(ps)
	_ = s.SetDeadline(time.Time{})
	if err != nil {
		_ = tc.Reset()
		return
	}
	sess := d.findBy(reattachMatch(o, x, l))
	if sess == nil {
		// ABORT inside the channel, before any token of this end's: the
		// client takes it as no answer and tries again until its bound
		d.logger.Info("nf1 direct path: a relayed re-attach no session's token names, refused")
		pathswitch.Refuse(o)
		return
	}
	ps.first.b = pathToken(sess.key, roleServer, o.Epoch, x)
	if err := sess.c.Attach(o, PathRelayed); err != nil {
		d.logger.Info("nf1 direct path: a relayed re-attach refused", "error", err)
		_ = tc.Reset()
		return
	}
	if err := ps.first.send(tc); err != nil {
		_ = tc.Reset() // the session's stream ended: it re-attaches or ends
	}
}

// reattachMatch is a session of l's address whose client token for o's
// epoch, over the re-attach's exporter x, o carries.
func reattachMatch(o pathswitch.Open, x []byte, l *nf1.Listener) func(*directSession) bool {
	m := tokenMatch(o, x)
	rid := l.Address().RID
	return func(s *directSession) bool { return s.nf1 != nil && s.nf1.Address().RID == rid && m(s) }
}

// nf1ReattachTLS is a re-attach's TLS at the agent: l's certificate (the
// address's key, which the client pins), no client certificate.
func nf1ReattachTLS(l *nf1.Listener) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{l.Certificate()},
		NextProtos:             []string{nf1ReattachALPN},
		SessionTicketsDisabled: true,
	}
}

// nf1ReattachALPN names a re-attach's TLS (a session's TLS offers none).
const nf1ReattachALPN = "nf1-reattach"

// onPathWithin waits until c is on path, false once d passed, c ended or
// gone closed.
// ponytail: polls every 50 ms (pathswitch has no move event on the
// server); an event when one exists.
func onPathWithin(c *pathswitch.Conn, path string, d time.Duration, gone <-chan struct{}) bool {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	end := time.After(d)
	for c.Path() != path {
		select {
		case <-c.Done():
			return false
		case <-gone:
			return false
		case <-end:
			return false
		case <-t.C:
		}
	}
	return true
}

// anonLost is the end hook of an anonymous session's stream st (its
// relayed one, or a direct one): the session ends at once (lost) when st
// ends while current and not cleanly, instead of after the detach bound,
// which waits for a re-attach that an anonymous session never gets (the
// client ends it at the same point: nf1-anon section 2; spec
// NF1Anon.tla GiveUp from detached). A stream that a move left, a clean
// end (EOF) and a session already over do not end it.
func anonLost(c *pathswitch.Conn, st pathStream, lost func()) func(error) {
	return func(err error) {
		if !errors.Is(err, io.EOF) && c.Current() == pathswitch.Stream(st) {
			lost()
		}
	}
}

// detachTap is an anonymous session's conn below its TLS: it notes a read
// that ended with no stream within the detach bound (its direct path died
// and no other came: the client does not re-attach it relayed).
type detachTap struct {
	net.Conn
	detached atomic.Bool
}

// CloseWrite and Reset are the session's (psConn's), as pathStream's:
// tlsend's CloseWrite ends the stream after the close_notify, its Reset
// aborts it. Hidden behind net.Conn, tlsend's Reset of an anonymous
// session was psConn's clean Close (lane ENDTRACE, as nf1.AnswerConn's in
// lane PIPERESET; TestSessionWrappersPassTheEndOn). No CloseWriteSync: a
// direct path's conn acknowledges no end (tlsend Close's exemption).
func (t *detachTap) CloseWrite() error { return pathStream{Conn: t.Conn}.CloseWrite() }
func (t *detachTap) Reset() error      { return pathStream{Conn: t.Conn}.Reset() }

func (t *detachTap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if errors.Is(err, pathswitch.ErrDetached) {
		t.detached.Store(true)
	}
	return n, err
}

// anonTarget is an anonymous session's queued target: a reset after its
// direct path died reads as ERROR_REASON_ACCOUNT_REQUIRED (nfnet's
// CodeDirectRequired), the client's end's reason.
type anonTarget struct {
	*QueueConn
	tap *detachTap
}

func (t *anonTarget) Reset() error {
	if t.tap.detached.Load() {
		t.end(&link.Abort{Code: dataplane.AbortCode(relayv1.ErrorReason_ERROR_REASON_ACCOUNT_REQUIRED), Msg: nf1.ErrDirectRequired.Error()})
		return nil
	}
	return t.QueueConn.Reset()
}

// dialNF1Target dials p's target for session s; nil (s reset) when it
// cannot be reached. A queued service's session enters its queue here,
// after its answer (the address's direct paths answer first): a full
// backlog resets it.
func dialNF1Target(ctx context.Context, p sessionPlan, s net.Conn, logger *slog.Logger) net.Conn {
	target, _, err := p.dial(ctx)
	if err != nil {
		logger.Warn("nf1: dial target failed", "target", p.target, "error", err)
		_ = pathStream{Conn: s}.Reset()
		return nil
	}
	return target
}

// admitNF1 runs l's TLS, proof and verdict on conn within the header
// bound, for a plain session (a control exchange's): the admitted TLS, its
// end checked and its Reset sending no close_notify (tlsend: Join passes
// a target's reset on as a reset, TestNF1TargetResetIsResetAtClient), or
// nil with conn closed.
func admitNF1(ctx context.Context, l *nf1.Listener, conn net.Conn, logger *slog.Logger) *tlsend.Conn {
	tc, _, _ := admitNF1Kind(ctx, l, conn, false, logger)
	return tc
}

// admitNF1Kind is admitNF1 that takes a framed session too when framed:
// the admitted TLS and the session's kind, or nil and why.
func admitNF1Kind(ctx context.Context, l *nf1.Listener, conn net.Conn, framed bool, logger *slog.Logger) (*tlsend.Conn, byte, error) {
	hctx, cancel := context.WithTimeout(ctx, e2eeHeaderTimeout)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	w, bind := tlsend.Wrap(conn)
	admit := func() (*tls.Conn, byte, error) {
		tc, err := l.Admit(hctx, w)
		return tc, nf1.KindPlain, err
	}
	if framed {
		admit = func() (*tls.Conn, byte, error) { return l.AdmitKind(hctx, w) }
	}
	tc, kind, err := admit()
	if err != nil {
		logger.Debug("nf1: session refused", "error", err)
		if !errors.Is(err, nf1.ErrDirectRequired) {
			_ = conn.Close() // else the caller aborts it with the reason
		}
		return nil, 0, err
	}
	_ = conn.SetDeadline(time.Time{})
	return bind(tc), kind, nil
}

// join bridges an admitted session to its target (a: what acknowledges
// its bytes, joinTarget); tc nil: the target is closed unused.
func join(tc *tlsend.Conn, a acker, target net.Conn) {
	if tc == nil {
		dropTarget(target)
		return
	}
	_ = joinTarget(tc, a, target)
}

// nf1ListenTLS is the direct listener's TLS for a connection whose server
// name a registered nf1 session asked for: its listener's certificate, no
// client certificate (the tokens bind the session). Another name: the
// organisation's (nil: listenTLS's own). An nf1 name no session holds is
// refused.
func (d *directServer) nf1ListenTLS(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if !isNF1SNI(hello.ServerName) {
		return nil, nil
	}
	s := d.findBy(func(s *directSession) bool { return s.nf1 != nil && s.sni == hello.ServerName && !s.ended.Load() })
	if s == nil {
		return nil, errors.New("nf1 direct path: no session asked for this name")
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{s.nf1.Certificate()},
		NextProtos:             nf1DirectALPNs(),
		SessionTicketsDisabled: true,
	}, nil
}

// nf1DirectALPNs is what an nf1 direct listener offers, in its order of
// preference: quiclink.ALPNEndAck (a session's CloseWriteSync waits for
// the far end), then ALPNChain and ALPN, which a client with an older
// quiclink negotiates as before.
func nf1DirectALPNs() []string {
	return []string{quiclink.ALPNEndAck, quiclink.ALPNChain, quiclink.ALPN}
}

// dropAddressesNotIn resets the nf1 sessions of addresses t does not serve
// (ServiceTable.Continue: a table that continues d's direct paths without
// an address revokes it for the sessions on them too).
func (d *directServer) dropAddressesNotIn(t *ServiceTable) {
	served := map[[capaddr.RIDSize]byte]bool{}
	for _, e := range t.byName {
		if e.nf1 != nil {
			served[e.nf1.Address().RID] = true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for s := range d.sessions {
		if s.nf1 != nil && !served[s.nf1.Address().RID] {
			if srv := s.revoke.Load(); srv != nil {
				go func() { // its flows told why, then the session ends cleanly; reset if held on
					srv.CloseWith(dgram.ReasonRevoked)
					time.AfterFunc(directCutGrace, s.c.Abort)
				}()
				continue
			}
			s.c.Abort()
		}
	}
}

// NF1Route is a client's way to a capability address's agent for its
// direct paths: the address, and Open, which opens a session to it through
// its relay, answered by the relay (the agent's answer frame not read).
type NF1Route struct {
	Addr capaddr.Address
	Open func(ctx context.Context) (net.Conn, error)
	// Anonymous: the address's answer said it is served with no account
	// (nf1.HintAnonymous): the session is direct only (WaitDirect).
	Anonymous bool
}

// nf1AnonDirectBound is how long a session to an address served with no
// account waits for its direct path: a control exchange and its punch
// (directControlBound), the pair's backoff and one more, below the relay's
// 2 min for a relayed leg of such a session (nfltr
// docs/decisions/nf1-anon-2026-11-16.md section 2).
const nf1AnonDirectBound = 2*directControlBound + 20*time.Second + 5*time.Second // 20 s: directBackoff[0]

// RunNF1 is Run for a session to a capability address (its first stream
// opened at r.Addr's relay and framed by Start, the address's TLS state
// cs): its pair is the address, its control exchanges and re-attaches go
// through r.Open.
func (s *DirectSession) RunNF1(cs tls.ConnectionState, r NF1Route, mode DirectMode, on func(PathEvent)) error {
	key, err := sessionKey(cs)
	if err != nil {
		return err
	}
	pair := s.d.nf1Pair(r)
	s.mu.Lock()
	s.key, s.service, s.mode, s.on = key, "", mode, on
	s.pair, s.anon = pair, r.Anonymous
	s.mu.Unlock()
	s.d.mu.Lock()
	s.d.sessions[s] = struct{}{}
	s.d.mu.Unlock()
	if r.Anonymous {
		t := time.AfterFunc(s.d.anonBound, func() {
			select {
			case <-s.direct: // the move landed as the bound passed
			default:
				s.directRequired()
			}
		})
		go func() {
			select {
			case <-s.direct:
				t.Stop()
			case <-s.c.Done():
				t.Stop()
			}
		}()
	}
	go s.loop(s.c.Written())
	return nil
}

// directRequired ends a session to an address served with no account
// that has no direct path (none formed in time, or it died): its relayed
// stream, if it is on one, is aborted with ERROR_REASON_ACCOUNT_REQUIRED
// (the agent reads the same reason), and Err is nf1.ErrDirectRequired.
func (s *DirectSession) directRequired() {
	err := nf1.ErrDirectRequired
	s.err.CompareAndSwap(nil, &err)
	s.gaveUpOnce.Do(func() { close(s.gaveUp) })
	if ps, ok := s.c.Current().(pathStream); ok && s.c.Path() == PathRelayed {
		c := ps.Conn
		if ps == s.first && s.raw != nil {
			c = s.raw // epoch 0: its relayed stream, under the TLS, carries the reason
		}
		_ = nf1.AbortDirectRequired(c)
	}
	s.c.Abort()
}

// WaitDirect waits until the session is on its first direct path: nil,
// or Err (nf1.ErrDirectRequired) once it ended without one, or ctx's
// error. A session to an address served with no account sends no byte of
// the service before it returns nil.
func (s *DirectSession) WaitDirect(ctx context.Context) error {
	select {
	case <-s.direct:
		return nil
	case <-s.gaveUp:
		return s.Err()
	case <-s.c.Done():
		if err := s.Err(); err != nil {
			return err
		}
		return pathswitch.ErrReset
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Err is why the session ended when this end ended it for the address's
// rule (nf1.ErrDirectRequired), else nil.
func (s *DirectSession) Err() error {
	if p := s.err.Load(); p != nil {
		return *p
	}
	return nil
}

// nf1Pair is the client's pair toward an address.
func (d *DirectClient) nf1Pair(r NF1Route) *directPair {
	key := "nf1:" + hex.EncodeToString(r.Addr.RID[:])
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.pairs[key]
	if p == nil {
		p = &directPair{key: key, nf1: &r}
		d.pairs[key] = p
	}
	return p
}

// nf1Open opens a session to p's address with mark as its first byte, the
// answer checked and taking direct paths.
func (d *DirectClient) nf1Open(ctx context.Context, p *directPair, mark byte) (net.Conn, error) {
	raw, err := p.nf1.Open(ctx)
	if err != nil {
		return nil, errors.Join(errNoOpen, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	hints, err := nf1.ReadAnswer(raw, p.nf1.Addr)
	if err == nil && !nf1.TakesDirect(hints) {
		err = errors.New("nf1 direct path: the listener takes no direct paths now")
	}
	if err == nil {
		_, err = raw.Write([]byte{mark})
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return raw, nil
}

// nf1Control is control for an address's pair: a session marked
// nf1MarkControl, then the address's TLS, proof and verdict.
func (d *DirectClient) nf1Control(ctx context.Context, p *directPair) (*tls.Conn, error) {
	raw, err := d.nf1Open(ctx, p, nf1MarkControl)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	tc, err := nf1.ClientTLS(ctx, raw, p.nf1.Addr)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// nf1Reattach opens a relayed re-attach of a session (its token key key)
// toward p's address (direct_once.pv ReattachClient, BIND:once.reattach):
// marked nf1MarkAttach, then a fresh TLS 1.3 handshake to the address's
// pinned key, no certificate of the client's, never the session's TLS
// continued (its key with a restarted record counter: a nonce reuse).
// The OPEN's token and the agent's, which the stream must start with
// before any frame is taken (tokenCheck: BIND:once.channel), are over
// that handshake's own exporter; heard is set by the agent's token.
func (d *DirectClient) nf1Reattach(ctx context.Context, p *directPair, key []byte, heard *atomic.Bool) (pathswitch.Stream, func(uint64) []byte, error) {
	raw, err := d.nf1Open(ctx, p, nf1MarkAttach)
	if err != nil {
		return nil, nil, err
	}
	tc := tlsend.Client(raw, nf1ReattachClientTLS(p.nf1.Addr))
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	err = tc.HandshakeContext(ctx)
	if !stop() && err == nil {
		err = ctx.Err()
	}
	var x []byte
	if err == nil {
		x, err = reattachKey(tc.ConnectionState())
	}
	if err != nil {
		_ = pathStream{Conn: raw}.Reset()
		return nil, nil, err
	}
	chk := &tokenCheck{pathStream: pathStream{Conn: tc, sent: &d.relayedSent, recv: &d.relayedRecv}, ready: make(chan struct{}), ok: func() { heard.Store(true) }}
	return chk, func(e uint64) []byte {
		chk.want = pathToken(key, roleServer, e, x)
		close(chk.ready)
		return pathToken(key, roleClient, e, x)
	}, nil
}

// nf1ReattachClientTLS is a re-attach's TLS at the client: the address's
// key pinned (as its session's TLS, nf1.ClientTLS), no certificate.
func nf1ReattachClientTLS(addr capaddr.Address) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         "nf1",
		NextProtos:         []string{nf1ReattachALPN},
		InsecureSkipVerify: true, // #nosec G402 -- the pin replaces the CA: VerifyConnection
		VerifyConnection:   addr.VerifyConnection,
	}
}

// nf1PunchTLS is a direct connection's TLS toward an address: the server
// name of the session that punches (p.sni), the answer's key pinned as the
// relayed TLS's (BIND:nf1direct.pin) whatever address it came from, no
// certificate of the client's.
func (d *DirectClient) nf1PunchTLS(p *directPair) *tls.Config {
	addr := p.nf1.Addr
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         p.sni,
		InsecureSkipVerify: true, // #nosec G402 -- the pin replaces the CA: VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := addr.VerifyConnection(cs); err != nil {
				p.refused.Store(true)
				return errors.Join(errDirectRefused, err)
			}
			return nil
		},
	}
}
