// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/relay/client/tlsend"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// Org is an organisation's identity for a tcp service in organisation mode
// (Service.Org; nfltr docs/decisions/org-enrolment-2026-11-09.md), the
// only end-to-end encrypted tcp mode: the agent ends its sessions' TLS
// with this machine's certificate and admits a client only by its
// certificate, checked by CheckClient. The SDK holds no policy of its
// own; client/orgid's Identity is one (spec/proverif/e2ee_tcp.pv, the
// service's half).
type Org interface {
	// Certificate is this machine's certificate chain (its leaf, then its
	// issuer's certificate) and key, read at every handshake: a renewed
	// certificate serves the next session.
	Certificate() (*tls.Certificate, error)
	// CheckClient checks a client's certificates (its leaf, then its
	// issuer's) at now: the chain to the organisation's root, NotAfter,
	// the issuer's current CRL, and a group of groups. until is when the
	// admission lapses: the session ends then.
	CheckClient(certs []*x509.Certificate, groups []string, now time.Time) (until time.Time, err error)
	// Changed is closed at the next change of what CheckClient checks
	// against (a CRL, a root, a certificate); open sessions are checked
	// again then, and a refused one ends.
	Changed() <-chan struct{}
}

// ErrOrgClientRefused: a session's client presented no certificate the
// organisation admits to the service. It sees a TLS alert.
var ErrOrgClientRefused = errors.New("e2ee: the organisation does not admit this client to the service")

// orgAdmission is what a session's handshake admitted: the client's
// certificates and when the admission lapses.
type orgAdmission struct {
	certs []*x509.Certificate
	until time.Time
}

// errNoServiceProtocol: the client offered no service protocol (an old
// client): a hard cut, no session without the binding.
var errNoServiceProtocol = errors.New("e2ee: the client named no service (ALPN): a client of this release dials by service")

// orgServerConfig is TLS 1.3 with o's machine certificate (read once per
// session) and a client certificate required (crypto/tls checks its
// CertificateVerify against the certificate's key) and checked by o for
// groups, into adm; the session's service protocols only (bind.protos: an
// offer of another ends the handshake with no_application_protocol, and
// one without a protocol is refused). No other mode: a client without an
// organisation certificate is refused (e2ee_tcp.pv mutant
// downgrade-any-client). VerifyConnection, not VerifyPeerCertificate,
// runs on a resumed session too; tickets are off.
func orgServerConfig(o Org, groups []string, bind serviceBind, adm *orgAdmission, logger *slog.Logger) (*tls.Config, error) {
	cert, err := o.Certificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{*cert},
		NextProtos:             bind.protos(cert),
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol == "" {
				logger.Warn("e2ee tcp: client refused", "error", errNoServiceProtocol)
				return errNoServiceProtocol
			}
			until, err := o.CheckClient(cs.PeerCertificates, groups, time.Now())
			if err != nil {
				logger.Warn("e2ee tcp: organisation client refused", "error", err)
				return fmt.Errorf("%w: %v", ErrOrgClientRefused, err)
			}
			adm.certs, adm.until = cs.PeerCertificates, until
			return nil
		},
	}, nil
}

// holdAdmission ends a session at its admission's end: cut is called at
// until, or at a change (changed closed) after which check refuses it; a
// change check still passes moves until (Enrol.tla NoExpiredSession and
// RevocationBound: mutants no-expiry-timer, no-cut-on-update). next
// returns the channel of the change after the one just taken; take
// changed before the check that admitted the session, so a change between
// the two is not missed. It returns when done is closed or after cut.
func holdAdmission(until time.Time, changed <-chan struct{}, next func() <-chan struct{}, check func(now time.Time) (time.Time, error), cut func(), done <-chan struct{}) {
	t := time.NewTimer(time.Until(until))
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			cut()
			return
		case <-changed:
			changed = next()
			u, cerr := check(time.Now())
			if cerr != nil {
				cut()
				return
			}
			t.Reset(time.Until(u))
		}
	}
}

// checkOrgTunnel is checkOrgService of Config's tunnel (TCPE2EEOrg needs
// TCPE2EEOnly, which needs TCPForwardAddr).
func checkOrgTunnel(cfg Config) error {
	e2ee := agentservices.E2EEDefault
	if cfg.TCPE2EEOnly {
		e2ee = agentservices.E2EEOn
	}
	return checkOrgService(Service{Name: "tcp tunnel", Kind: agentservices.TCP, E2EE: e2ee, Org: cfg.TCPE2EEOrg, AllowGroups: cfg.TCPE2EEAllowGroups})
}

// checkOrgService: a tcp service with E2EE On is in organisation mode (Org
// and at least one group), the only end-to-end encrypted tcp mode; Org is
// only that, and groups without Org are refused.
func checkOrgService(s Service) error {
	switch {
	case s.Org == nil && len(s.AllowGroups) > 0:
		return fmt.Errorf("service %q: allow groups need the organisation (Org)", s.Name)
	case s.Org == nil && s.NF1 == nil && s.Kind == agentservices.TCP && s.E2EE == agentservices.E2EEOn:
		return fmt.Errorf("service %q: e2ee %q needs organisation mode (Org and at least one allow group) or a capability address (NF1)", s.Name, agentservices.E2EEOn)
	case s.Org == nil:
		return nil
	case s.Kind != agentservices.TCP || s.E2EE != agentservices.E2EEOn:
		return fmt.Errorf("service %q: organisation mode needs a tcp service with e2ee %q", s.Name, agentservices.E2EEOn)
	case len(s.AllowGroups) == 0:
		return fmt.Errorf("service %q: organisation mode needs at least one allow group", s.Name)
	}
	return nil
}

// serveE2EETCP serves an end-to-end encrypted session of a tcp service in
// organisation mode: TLS (orgServerConfig) on s, the plaintext bridged to
// target, each side's end passed on as a half close (TLS close_notify on
// s), and the session ended at its admission's end (holdAdmission): a cut
// is a reset to both ends. A session that ends without the client's
// close_notify (the relay cut it) is a reset to the target, never its half
// close (tlsend; CLAIMS-A Q5, TestOrgSessionCutIsResetAtTarget); a
// target's reset is one to the client, no close_notify (Join calls
// tlsend's Reset; lane TCPRESET, TestOrgSessionTargetResetIsResetAtClient).
// A refused client gets a TLS alert and the target only a connection that
// closes: no byte of it is read or written.
//
// A session whose first byte is no TLS record asked for direct paths: its
// stream is framed (pathswitch) under the TLS, and with Service.Direct on
// it may move (direct_server.go); without it the framed session stays on
// the relay.
//
// On a service with direct paths, a stream whose first byte is
// directControlMark is a control exchange (a group dial's first toward
// this agent), never a session: target is closed unused.
func serveE2EETCP(s, target net.Conn, p sessionPlan, logger *slog.Logger) {
	if p.direct != nil {
		first, peeked, err := peekFirst(s, e2eeHeaderTimeout)
		if err != nil {
			dropTarget(target)
			_ = s.Close()
			return
		}
		if first == directControlMark {
			dropTarget(target)
			p.direct.controlSession(s, p.org, p.groups, p.bind, p.relay, logger) // s: the mark read
			return
		}
		s = peeked
	}
	ps, s, err := startDirect(s, p.direct)
	if err != nil {
		dropTarget(target)
		return
	}
	handshook := func() {}
	if ps != nil && p.direct != nil {
		handshook = p.direct.handshaking()
		defer handshook()
	}
	var adm orgAdmission
	changed := p.org.Changed() // before the check: a change after it is seen
	cfg, err := orgServerConfig(p.org, p.groups, p.bind, &adm, logger)
	if err != nil {
		logger.Warn("e2ee tcp: this machine's certificate", "error", err)
		dropTarget(target)
		_ = s.Close()
		return
	}
	tc := tlsend.Server(s, cfg)
	_ = tc.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	if err := tc.Handshake(); err != nil {
		logger.Debug("e2ee tcp: handshake failed", "error", err)
		dropTarget(target)
		_ = s.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	if ps != nil && p.direct != nil {
		if key, err := sessionKey(tc.ConnectionState()); err == nil {
			p.direct.register(ps, key)
		}
	}
	handshook()
	done := make(chan struct{})
	defer close(done)
	go holdAdmission(adm.until, changed, p.org.Changed,
		func(now time.Time) (time.Time, error) { return p.org.CheckClient(adm.certs, p.groups, now) },
		func() {
			logger.Info("e2ee tcp: organisation admission ended, session cut")
			_ = tc.Reset()
			dropTarget(target)
		}, done)
	_ = peerlink.Join(tc, target)
}

// serveNF1 serves a session of a service under a capability address: the
// listener's rendezvous answer, pinned TLS and proof on s (nf1.Listener),
// then the plaintext bridged to target. A refused client's target gets
// only a connection that closes: no byte of it is read or written.
func serveNF1(ctx context.Context, s, target net.Conn, p sessionPlan, logger *slog.Logger) {
	hctx, cancel := context.WithTimeout(ctx, e2eeHeaderTimeout)
	tc, err := p.nf1.Accept(hctx, s)
	cancel()
	if err != nil {
		logger.Debug("nf1: session refused", "error", err)
		dropTarget(target)
		return
	}
	_ = peerlink.Join(tc, target)
}
