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
	"github.com/nfltr/relay/client/nf1"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// sessionKind is what serves a session the relay opened.
type sessionKind int

const (
	sessionRaw       sessionKind = iota // a TCP connection to the target
	sessionE2EE                         // TLS ended here, proxied to the backend
	sessionHTTP                         // the HTTP tunnel (dataplane.HTTPSessionTarget)
	sessionE2EETCP                      // organisation TLS ended here, bytes to a tcp service's target
	sessionDirect                       // the reserved DirectServiceName, served in process
	sessionNF1                          // a capability address's listener here, bytes to a tcp service's target
	sessionNF1Direct                    // ... whose listener takes direct paths: the target dialled only for a session, after its first byte (direct_nf1.go)
)

// sessionPlan is how one session is served.
type sessionPlan struct {
	kind            sessionKind
	network         string // "" or "tcp": target is host:port; "unix": a service's socket path
	target, backend string
	wrap            func(http.Handler) http.Handler
	client          netip.Addr     // an E2EE session's visitor, from the relay (pb.TCPData.ClientAddr); zero: unknown
	e2ee            *e2eeTLSConfig // the certificate an E2EE session ends with: its service's, else the tunnel's
	org             Org            // a sessionE2EETCP's organisation
	groups          []string       // ... its allow groups
	bind            serviceBind    // ... the service protocols it accepts (service_alpn.go)
	direct          *directServer  // ... the table's direct paths (nil: none); a sessionDirect's server
	relay           *qadTarget     // ... a sessionDirect's, or a direct service's: the QAD of the relay its tunnel is on (nil: none offered)
	nf1             *nf1.Listener  // a sessionNF1's
	queue           *SessionQueue  // the target in this process (Service.Queue); nil: dial target
	caller          *pb.CallerIdentity
}

// ErrE2EENoFixedTarget: Config.TCPE2EEOnly without Config.TCPForwardAddr.
// An end-to-end encrypted session's plaintext goes only to a target the
// agent fixed; the relay names a session's target, so one it names is
// refused (spec/proverif/e2ee_tcp.pv mutant relay-names-target).
var ErrE2EENoFixedTarget = errors.New("an end-to-end encrypted tunnel needs a fixed target (TCPForwardAddr): the agent never dials a target the relay names")

var (
	errNoHTTPSessions = errors.New("this agent serves no HTTP sessions")
	errNoRawTargets   = errors.New("this agent serves no tcp targets")
)

// planSession resolves a session's open (its frame on a stream, its header
// on the agent link) against what the tunnel serves; an error refuses it.
func planSession(open *pb.TCPData, targets sessionTargets, e2ee *e2eeTLSConfig) (sessionPlan, error) {
	p, err := planOpen(open, targets, e2ee)
	if err == nil && targets.services != nil && targets.services.onSession != nil {
		targets.services.onSession(Session{Service: open.GetTargetAddr(), caller: open.GetCaller()})
	}
	return p, err
}

func planOpen(open *pb.TCPData, targets sessionTargets, e2ee *e2eeTLSConfig) (sessionPlan, error) {
	if open.GetTargetAddr() == dataplane.HTTPSessionTarget && !open.GetE2Ee() {
		if targets.http == nil {
			return sessionPlan{}, errNoHTTPSessions
		}
		return sessionPlan{kind: sessionHTTP}, nil
	}
	p := sessionPlan{target: open.GetTargetAddr(), backend: targets.defaultBackend, e2ee: e2ee, caller: open.GetCaller()}
	var svcWrap func(http.Handler) http.Handler
	if targets.services != nil {
		// The table is the only set of targets: a session that names
		// anything else is refused, never dialled.
		svc, err := targets.services.resolve(open.GetTargetAddr(), open.GetE2Ee(), e2ee != nil, open.GetAnswer())
		if err != nil {
			return sessionPlan{}, err
		}
		p.network, p.target, p.backend, svcWrap, p.queue = svc.network, svc.addr, svc.backend, svc.wrap, svc.queue
		if svc.network == networkDirect {
			p.kind, p.org, p.groups, p.direct = sessionDirect, svc.org, svc.groups, targets.services.direct
			p.relay = targets.relayQAD()
			p.bind = serviceBind{agent: targets.agent, service: DirectServiceName}
			return p, nil
		}
		if svc.nf1 != nil {
			// A capability address: an E2EE session only (resolve refused
			// a plain one); its listener's TLS, never the tunnel's.
			p.kind, p.nf1, p.e2ee = sessionNF1, svc.nf1, nil
			if svc.nf1.TakesDirect() && targets.services.direct != nil {
				p.kind, p.direct, p.relay = sessionNF1Direct, targets.services.direct, targets.relayQAD()
				p.bind = serviceBind{agent: targets.agent, service: open.GetTargetAddr()}
			}
			return p, nil
		}
		if svc.org != nil {
			// Organisation mode: resolve refused a plain session (E2EE
			// On); the session is the organisation's TLS, never the
			// tunnel's certificate (e2ee_tcp.pv).
			p.kind, p.org, p.groups, p.e2ee = sessionE2EETCP, svc.org, svc.groups, nil
			p.bind = serviceBind{agent: targets.agent, service: open.GetTargetAddr(), group: svc.group}
			p.client = clientAddr(open.GetClientAddr())
			if targets.services.direct != nil && targets.services.direct.modes[open.GetTargetAddr()] != DirectOff {
				p.direct, p.relay = targets.services.direct, targets.relayQAD()
			}
			return p, nil
		}
		if svc.cert != nil {
			p.e2ee = svc.cert
		}
	} else if targets.forwardAddr != "" {
		p.target = targets.forwardAddr
		if targets.org != nil {
			// Config.TCPE2EEOrg (nfltr tcp --e2ee): organisation TLS only,
			// its bytes to the agent's fixed target (TCPForwardAddr,
			// required at New), never to the open's, which the relay
			// writes (E2EEPROOF finding 1); a plain session is refused,
			// never dialled. Guards: TestOrgTunnelCarriesBytes,
			// TestOrgTunnelRefusesPlainSessions.
			if !open.GetE2Ee() {
				return sessionPlan{}, errE2EERequired(open)
			}
			p.kind, p.org, p.groups, p.e2ee = sessionE2EETCP, targets.org, targets.groups, nil
			p.bind = serviceBind{agent: targets.agent, service: open.GetTargetAddr()}
			p.client = clientAddr(open.GetClientAddr())
			return p, nil
		}
	}
	if p.e2ee != nil {
		p.wrap = p.e2ee.wrapHTTP
	}
	p.wrap = composeWraps(p.wrap, svcWrap)
	if open.GetE2Ee() && p.e2ee != nil {
		// An E2EE share session: HTTP to the default route or the table's
		// http service (relay-core TestCoreProcessTLSAndE2EE).
		p.kind = sessionE2EE
		p.client = clientAddr(open.GetClientAddr())
		return p, nil
	}
	if targets.noRaw {
		return sessionPlan{}, errNoRawTargets
	}
	return p, nil
}

// errE2EERequired refuses a session to an end-to-end encrypted only tunnel
// that is not end to end encrypted.
func errE2EERequired(open *pb.TCPData) error {
	return &ServiceRefusedError{Target: open.GetTargetAddr(), E2EE: open.GetE2Ee(), Answer: relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED,
		Reason: "the agent takes end-to-end encrypted sessions only: open it from a machine enrolled in its organisation, in one of its allowed groups"}
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
	ts := traceAOpen(l)
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
		serveE2EEConn(tls.Server(s, p.e2ee.tlsConfig), backend, p.e2ee.rewriteHost, p.client, p.wrap, l.logger)
	case sessionDirect:
		if a.accept() != nil {
			_ = s.Close()
			return
		}
		p.direct.serveService(s, p.bind, p.relay, l.logger)
	case sessionNF1Direct:
		if a.accept() != nil {
			_ = s.Close()
			return
		}
		serveNF1Direct(l.ctx, s, p, l.logger)
	default:
		target, reason, err := p.dial(l.ctx)
		if err != nil {
			if traceOn && l.ctx.Err() != nil {
				traceARefused(l, ts) // no context to serve it in (finding 42)
			}
			l.logger.Warn("tcp tunnel: dial target failed", "target", p.target, "error", err)
			a.refuse(reason, err)
			return
		}
		if a.accept() != nil {
			dropTarget(target)
			_ = s.Close()
			return
		}
		if p.kind == sessionE2EETCP {
			serveE2EETCP(s, target, p, l.logger)
			return
		}
		if p.kind == sessionNF1 {
			serveNF1(l.ctx, s, target, p, l.logger)
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

// dial reaches the session's target: its service's queue (Accept takes
// it), else a dial of its address.
func (p sessionPlan) dial(ctx context.Context) (net.Conn, relayv1.ErrorReason, error) {
	if p.queue != nil {
		return p.queue.enter(ctx, p.caller)
	}
	return dialTarget(ctx, p.network, p.target)
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
