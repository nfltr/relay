// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
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
// (Service.Org; nfltr docs/decisions/org-enrolment-2026-11-09.md): the
// agent ends its pinned sessions' TLS with this machine's certificate and
// admits a client only by its certificate, checked by CheckClient. The SDK
// holds no policy of its own; nfltr's orgpki is behind it
// (spec/proverif/e2ee_tcp_org.pv, the service's half).
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

// orgServerConfig is TLS 1.3 with o's machine certificate and a client
// certificate required (crypto/tls checks its CertificateVerify against
// the certificate's key) and checked by o for groups, into adm. No pin and
// no other mode: a client without an organisation certificate is refused
// (e2ee_tcp_org.pv mutant downgrade-any-client). VerifyConnection, not
// VerifyPeerCertificate, runs on a resumed session too; tickets are off.
func orgServerConfig(o Org, groups []string, adm *orgAdmission, logger *slog.Logger) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return o.Certificate() },
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			until, err := o.CheckClient(cs.PeerCertificates, groups, time.Now())
			if err != nil {
				logger.Warn("e2ee tcp: organisation client refused", "error", err)
				return fmt.Errorf("%w: %v", ErrOrgClientRefused, err)
			}
			adm.certs, adm.until = cs.PeerCertificates, until
			return nil
		},
	}
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
	return checkOrgService(Service{Name: "tcp tunnel", Kind: agentservices.TCP, E2EE: e2ee, E2EEClients: cfg.TCPE2EEClients, Org: cfg.TCPE2EEOrg, AllowGroups: cfg.TCPE2EEAllowGroups})
}

// checkOrgService: a service in organisation mode (Org) is a tcp service
// with E2EE On, at least one group, and no pin of either side (Cert,
// E2EEClients), so it has one mode only; groups without Org are refused.
func checkOrgService(s Service) error {
	switch {
	case s.Org == nil && len(s.AllowGroups) > 0:
		return fmt.Errorf("service %q: allow groups need the organisation (Org)", s.Name)
	case s.Org == nil:
		return nil
	case s.Kind != agentservices.TCP || s.E2EE != agentservices.E2EEOn:
		return fmt.Errorf("service %q: organisation mode needs a tcp service with e2ee %q", s.Name, agentservices.E2EEOn)
	case len(s.AllowGroups) == 0:
		return fmt.Errorf("service %q: organisation mode needs at least one allow group", s.Name)
	case len(s.E2EEClients) > 0 || s.Cert != nil:
		return fmt.Errorf("service %q: organisation mode takes no pins (e2ee clients, its own certificate): one mode per service", s.Name)
	}
	return nil
}

// serveOrgTCP serves a session of a tcp service in organisation mode as
// serveE2EETCP does a pinned one (tlsend, Join), with the organisation's
// TLS (orgServerConfig), and ends it at its admission's end
// (holdAdmission): a cut is a reset to both ends.
func serveOrgTCP(s, target net.Conn, p sessionPlan, logger *slog.Logger) {
	var adm orgAdmission
	changed := p.org.Changed() // before the check: a change after it is seen
	tc := tlsend.Server(s, orgServerConfig(p.org, p.groups, &adm, logger))
	_ = tc.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	if err := tc.Handshake(); err != nil {
		logger.Debug("e2ee tcp: handshake failed", "error", err)
		_ = target.Close()
		_ = s.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	done := make(chan struct{})
	defer close(done)
	go holdAdmission(adm.until, changed, p.org.Changed,
		func(now time.Time) (time.Time, error) { return p.org.CheckClient(adm.certs, p.groups, now) },
		func() {
			logger.Info("e2ee tcp: organisation admission ended, session cut")
			_ = tc.Reset()
			_ = target.Close()
		}, done)
	_ = peerlink.Join(tc, target)
}
