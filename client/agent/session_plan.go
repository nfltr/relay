// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/nfltr/link/peerlink"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// sessionKind is what serves a session the relay opened.
type sessionKind int

const (
	sessionRaw     sessionKind = iota // a TCP connection to the target
	sessionE2EE                       // TLS ended here, proxied to the backend
	sessionHTTP                       // the HTTP tunnel (dataplane.HTTPSessionTarget)
	sessionE2EETCP                    // TLS ended here, bytes to a tcp service's target
)

// sessionPlan is how one session is served.
type sessionPlan struct {
	kind            sessionKind
	network         string // "" or "tcp": target is host:port; "unix": a service's socket path
	target, backend string
	wrap            func(http.Handler) http.Handler
	client          netip.Addr // an E2EE session's visitor, from the relay (pb.TCPData.ClientAddr); zero: unknown
}

var (
	errNoHTTPSessions = errors.New("this agent serves no HTTP sessions")
	errNoRawTargets   = errors.New("this agent serves no tcp targets")
)

// planSession resolves a session's open (its frame on a stream, its header
// on the agent link) against what the tunnel serves; an error refuses it.
func planSession(open *pb.TCPData, targets sessionTargets, e2ee *e2eeTLSConfig) (sessionPlan, error) {
	if open.GetTargetAddr() == dataplane.HTTPSessionTarget && !open.GetE2Ee() {
		if targets.http == nil {
			return sessionPlan{}, errNoHTTPSessions
		}
		return sessionPlan{kind: sessionHTTP}, nil
	}
	p := sessionPlan{target: open.GetTargetAddr(), backend: targets.defaultBackend}
	if e2ee != nil {
		p.wrap = e2ee.wrapHTTP
	}
	if targets.services != nil {
		// The table is the only set of targets: a session that names
		// anything else is refused, never dialled.
		svc, err := targets.services.resolve(open.GetTargetAddr(), open.GetE2Ee(), e2ee != nil, open.GetAnswer())
		if err != nil {
			return sessionPlan{}, err
		}
		p.network, p.target, p.backend, p.wrap = svc.network, svc.addr, svc.backend, composeWraps(p.wrap, svc.wrap)
	} else if targets.forwardAddr != "" {
		p.target = targets.forwardAddr
	}
	if open.GetE2Ee() && e2ee != nil {
		p.kind = sessionE2EE
		p.client = clientAddr(open.GetClientAddr())
		if targets.services != nil && targets.services.byName[open.GetTargetAddr()].kind == agentservices.TCP {
			p.kind = sessionE2EETCP
		}
		return p, nil
	}
	if targets.noRaw {
		return sessionPlan{}, errNoRawTargets
	}
	return p, nil
}

// clientAddr is the visitor address an open names, the zero Addr when it
// names none or no IP address: it goes into a header only as an address.
func clientAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

func logSessionRefused(logger *slog.Logger, id string, err error, targets sessionTargets) {
	if targets.services != nil {
		logger.Warn("tcp tunnel: service session refused", "session", id, "error", err,
			"refused_total", targets.services.Refused())
		return
	}
	logger.Warn("tcp tunnel: session refused", "session", id, "error", err)
}

// linkSessions serves the sessions a relay opens on the agent link: each a
// peerlink.Session whose header is its open (dataplane.OpenHeader).
type linkSessions struct {
	ctx     context.Context
	targets sessionTargets
	e2ee    *e2eeTLSConfig
	logger  *slog.Logger
	growth  *tcpStreamGrowth // counts sessions in flight (moves wait for them)
}

// newLinkSessions serves the sessions of a primary's agent link. Where the
// link can outlive the primary (park: it waits for the next primary), its
// sessions dial their targets in the agent's context: the primary's end
// (which may cancel its tunnel context, Config.Drain) must not refuse an
// open on a link that goes on, in flight or still to come. Without a park
// the link ends with the primary, and so do its dials.
func newLinkSessions(park *linkPark, primary context.Context, targets sessionTargets, e2ee *e2eeTLSConfig, logger *slog.Logger, growth *tcpStreamGrowth) *linkSessions {
	ctx := primary
	if park != nil {
		ctx = park.ctx
	}
	return &linkSessions{ctx: ctx, targets: targets, e2ee: e2ee, logger: logger, growth: growth}
}

// accept is the agent link's peerlink accept: it owns s. It answers the
// open (sessionAnswer) once the target is reached, then joins the session
// to it (peerlink.Join: bytes, half closes and resets both ways).
func (l *linkSessions) accept(_ string, header []byte, s peerlink.Session) {
	l.growth.add(1)
	defer l.growth.add(-1)
	open, err := dataplane.ParseOpenHeader(header)
	var p sessionPlan
	if err == nil {
		p, err = planSession(open, l.targets, l.e2ee)
	}
	a := sessionAnswer{s: s, inband: open.GetAnswer()}
	if err != nil {
		logSessionRefused(l.logger, "link", err, l.targets)
		a.refuse(refusalReason(err), err)
		return
	}
	switch p.kind {
	case sessionHTTP:
		serveHTTPConn(s, l.targets.http) // its first response answers the open
	case sessionE2EE:
		backend, err := url.Parse(p.backend)
		if err != nil || p.backend == "" {
			l.logger.Warn("e2ee: no valid backend for reverse proxy", "backend", p.backend)
			_ = s.Reset()
			return
		}
		if a.accept() != nil {
			_ = s.Close()
			return
		}
		serveE2EEConn(tls.Server(s, l.e2ee.tlsConfig), backend, l.e2ee.rewriteHost, p.client, p.wrap, l.logger)
	default:
		target, reason, err := dialTarget(l.ctx, p.network, p.target)
		if err != nil {
			l.logger.Warn("tcp tunnel: dial target failed", "target", p.target, "error", err)
			a.refuse(reason, err)
			return
		}
		if a.accept() != nil {
			_ = target.Close()
			_ = s.Close()
			return
		}
		if p.kind == sessionE2EETCP {
			serveE2EETCP(s, target, l.e2ee, l.logger)
			return
		}
		_ = peerlink.Join(s, target)
	}
}

// sessionAnswer answers an agent-link session's open: link's own way
// (Accept, a refusal with dataplane.AbortCode) where its connection
// negotiated link.FeatureChain; in band where it did not (a relay before
// nfltr-relay v0.22.0) and the open asks for an answer; otherwise a
// refusal is a reset and an accept says nothing.
type sessionAnswer struct {
	s      peerlink.Session
	inband bool
}

// native is s where it answers link's own way, else nil.
func (a sessionAnswer) native() peerlink.ChainSession {
	if cs, ok := a.s.(peerlink.ChainSession); ok && cs.Answers() {
		return cs
	}
	return nil
}

func (a sessionAnswer) accept() error {
	if cs := a.native(); cs != nil {
		return cs.Accept()
	}
	if a.inband {
		return dataplane.WriteAnswer(a.s, 0, "")
	}
	return nil
}

func (a sessionAnswer) refuse(reason relayv1.ErrorReason, err error) {
	switch cs := a.native(); {
	case cs != nil:
		_ = cs.AbortWith(dataplane.Refusal(reason, err.Error()))
	case a.inband:
		refuseAnswered(a.s, reason, err)
	default:
		_ = a.s.Reset()
	}
}

// targetDialTimeout bounds the agent's dial of a session's target: a
// target that does not answer within it is TARGET_UNREACHABLE.
var targetDialTimeout = 10 * time.Second

// targetKeepAlive is TCP keepalive on the agent's connection to a target.
// A target on another host (forward:) that goes silent is noticed after
// about Idle + Interval*Count = 25 s; Go's default (15 s + 9 x 15 s) took
// about 150 s. A host whose kernel still answers (a frozen VM) is never
// noticed by TCP keepalive: only the application's own deadlines see it.
var targetKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 10 * time.Second, Interval: 5 * time.Second, Count: 3}

// targetDialer dials a session's target.
func targetDialer() *net.Dialer {
	return &net.Dialer{Timeout: targetDialTimeout, KeepAliveConfig: targetKeepAlive}
}

// dialTarget dials a session's target over network ("" is tcp; unix only
// for a service table's own socket): the connection, or the answer's
// reason for the failure (refused, or unreachable: a timeout, no route, an
// unknown host).
func dialTarget(ctx context.Context, network, addr string) (net.Conn, relayv1.ErrorReason, error) {
	if network == "" {
		network = "tcp"
	}
	c, err := targetDialer().DialContext(ctx, network, addr)
	if err == nil {
		return c, 0, nil
	}
	for _, refused := range errConnRefused {
		if errors.Is(err, refused) {
			return nil, relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, err
		}
	}
	return nil, relayv1.ErrorReason_ERROR_REASON_TARGET_UNREACHABLE, err
}

// refusalReason is the answer's reason for a session planSession refused.
func refusalReason(err error) relayv1.ErrorReason {
	if e, ok := errors.AsType[*ServiceRefusedError](err); ok {
		return e.Answer
	}
	return relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED
}

// refuseAnswered answers a refused session with reason and err, then
// ends it cleanly (its opener reads the answer, then the end).
func refuseAnswered(s net.Conn, reason relayv1.ErrorReason, err error) {
	_ = dataplane.WriteAnswer(s, reason, err.Error())
	_ = s.Close()
}

// serveE2EETCP serves an end-to-end encrypted session of a tcp service:
// TLS with the agent's E2EE certificate on s (the client verifies it
// against the pin it got from the agent), the plaintext bridged to target,
// each side's end passed on as a half close (TLS close_notify on s).
func serveE2EETCP(s, target net.Conn, cfg *e2eeTLSConfig, logger *slog.Logger) {
	tc := tls.Server(s, cfg.tlsConfig)
	_ = tc.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	if err := tc.Handshake(); err != nil {
		logger.Debug("e2ee tcp: handshake failed", "error", err)
		_ = target.Close()
		_ = s.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	_ = peerlink.Join(tc, target)
}
