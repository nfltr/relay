// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Direct paths for capability-address (nf1) sessions (nfltr
// docs/decisions/nf1-direct-2026-11-14.md): the organisation's direct paths
// (direct.go, direct_server.go, direct_client.go) with an nf1 identity. A
// listener that takes them says so in its signed hints (nf1.HintDirect);
// after its answer frame the client's first byte picks the session's kind:
// a TLS record (plain, as before), nf1MarkControl (a control exchange inside
// the address's pinned, admitted TLS), nf1MarkAttach (a relayed re-attach:
// pathswitch OPEN with tokR) or a path frame (a session framed for direct
// paths, the address's TLS above it). The direct QUIC connection shows the
// address's certificate, which the client pins as the relayed TLS
// (BIND:nf1direct.pin); the tokens are the organisation's, keyed by the
// address session's exporter.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/client/nf1"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// The client's first byte after an nf1 answer that took direct paths:
// neither a TLS record nor a path frame.
const (
	nf1MarkControl = 'C'
	nf1MarkAttach  = 'A'
)

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
// direct paths, its open accepted: the answer, then by the client's first
// byte a plain session, a framed one (movable once admitted), a control
// exchange or a re-attach. The service's target is dialled only for the
// first two, after that byte: a control exchange or a re-attach never
// reaches it, and never fails because it is busy or down (a target that
// cannot be reached resets the session, since its open was accepted).
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
	if l.Anonymous() && first != nf1MarkControl && !framed(first) {
		// served with no account: a session that cannot leave the relay
		// (plain) or comes back to it (a re-attach) is refused
		_ = nf1.AbortDirectRequired(s)
		return
	}
	switch first {
	case tlsRecordHandshake:
		target := dialNF1Target(ctx, p, ps, logger)
		if target == nil {
			return
		}
		join(admitNF1(ctx, l, ps, logger), target)
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
		d.reattach(pathStream{Conn: s})
	default: // a path frame: the session framed for direct paths
		if l.Anonymous() {
			serveNF1Anon(ctx, s, ps, p, logger)
			return
		}
		target := dialNF1Target(ctx, p, ps, logger)
		if target == nil {
			return
		}
		done := d.handshaking()
		defer done()
		c := pathswitch.Server(pathStream{Conn: ps}, PathRelayed, pathswitch.Config{Detach: d.detach})
		tc := admitNF1(ctx, l, newPSConn(c, s), logger)
		if tc == nil {
			c.Abort()
			dropTarget(target)
			return
		}
		key, err := sessionKey(tc.ConnectionState())
		if err != nil {
			_ = tc.Close()
			dropTarget(target)
			return
		}
		setDirect(target, d.registerSession(&directSession{c: c, key: key, nf1: l, sni: nf1SNI(key)}))
		done()
		join(tc, target)
	}
}

// framed: first is a path frame's first byte (neither a TLS record nor a
// mark).
func framed(first byte) bool {
	return first != tlsRecordHandshake && first != nf1MarkControl && first != nf1MarkAttach
}

// serveNF1Anon serves a framed session of an address served with no
// account (nfltr docs/decisions/nf1-anon-2026-11-16.md section 2): the
// service's target is dialled only once the session is on a direct path,
// so no byte of the service crosses the relay; none within
// nf1AnonDirectBound ends the session with ERROR_REASON_ACCOUNT_REQUIRED.
// The direct path's loss ends it too (the client never re-attaches it
// relayed): the target reads the same reason.
func serveNF1Anon(ctx context.Context, s, ps net.Conn, p sessionPlan, logger *slog.Logger) {
	l, d := p.nf1, p.direct
	done := d.handshaking()
	defer done()
	c := pathswitch.Server(pathStream{Conn: ps}, PathRelayed, pathswitch.Config{Detach: d.detach})
	tap := &detachTap{Conn: newPSConn(c, s)}
	tc := admitNF1(ctx, l, tap, logger)
	if tc == nil {
		c.Abort()
		return
	}
	key, err := sessionKey(tc.ConnectionState())
	if err != nil {
		_ = tc.Close()
		return
	}
	ds := d.registerSession(&directSession{c: c, key: key, nf1: l, sni: nf1SNI(key)})
	done()
	if !onPathWithin(c, PathDirect, nf1AnonDirectBound) {
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
	join(tc, target)
}

// onPathWithin waits until c is on path, false once d passed or c ended.
// ponytail: polls every 50 ms (pathswitch has no move event on the
// server); an event when one exists.
func onPathWithin(c *pathswitch.Conn, path string, d time.Duration) bool {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	end := time.After(d)
	for c.Path() != path {
		select {
		case <-c.Done():
			return false
		case <-end:
			return false
		case <-t.C:
		}
	}
	return true
}

// detachTap is an anonymous session's conn below its TLS: it notes a read
// that ended with no stream within the detach bound (its direct path died
// and no other came: the client does not re-attach it relayed).
type detachTap struct {
	net.Conn
	detached atomic.Bool
}

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
// bound: the admitted TLS, or nil with conn closed.
func admitNF1(ctx context.Context, l *nf1.Listener, conn net.Conn, logger *slog.Logger) *tls.Conn {
	hctx, cancel := context.WithTimeout(ctx, e2eeHeaderTimeout)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	tc, err := l.Admit(hctx, conn)
	if err != nil {
		logger.Debug("nf1: session refused", "error", err)
		_ = conn.Close()
		return nil
	}
	_ = conn.SetDeadline(time.Time{})
	return tc
}

// join bridges an admitted session to its target; tc nil: the target is
// closed unused.
func join(tc *tls.Conn, target net.Conn) {
	if tc == nil {
		dropTarget(target)
		return
	}
	_ = peerlink.Join(tc, target)
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
	s := d.findBy(func(s *directSession) bool { return s.nf1 != nil && s.sni == hello.ServerName })
	if s == nil {
		return nil, errors.New("nf1 direct path: no session asked for this name")
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{s.nf1.Certificate()},
		NextProtos:             []string{quiclink.ALPNChain, quiclink.ALPN},
		SessionTicketsDisabled: true,
	}, nil
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
	if ps, ok := s.c.Current().(pathStream); ok && s.c.Path() == PathRelayed {
		_ = nf1.AbortDirectRequired(ps.Conn)
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
