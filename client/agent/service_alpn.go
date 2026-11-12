// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nfltr/relay/proto/wire/agentservices"
)

// The service a session of organisation mode reaches is bound in its TLS,
// as one ALPN protocol (spec/proverif/e2ee_tcp.pv queries 30-35; nfltr
// docs/decisions/service-discovery-2026-11-12.md section 4). The machine
// certificate names the machine, which all its agents and services share:
// without the binding a relay routes web/pg to web's vault. The client
// offers the protocol naming what it dialled (MachineALPN, GroupALPN) and
// requires it negotiated (BindServiceTLS); the agent accepts only the
// protocol of the service the session was routed to, for a group only one
// it publishes that service under (Service.Group) and its certificate's OU
// holds, else the handshake ends (no_application_protocol). ALPN is in the
// ClientHello and the agent's choice in EncryptedExtensions, both under
// the handshake's transcript: a relay that changes either fails it. No
// protocol, no session: a client that offers none is refused.

// ServiceALPNPrefix starts every service protocol.
const ServiceALPNPrefix = "nfltr-svc/"

// MachineALPN is the protocol a client offers for a machine dial of
// service on agent, as the client names it: "<agent>" or
// "<machine>.<agent>" (another account machine's agent); the protocol
// names the agent part, nfltr-svc/<agent>/<service> (BIND:org.service).
func MachineALPN(agent, service string) string {
	return ServiceALPNPrefix + alpnAgent(agent) + "/" + service
}

// GroupALPN is the protocol a client offers for a group dial,
// <service>@<group>: nfltr-svc/<service>@<group> (BIND:org.service).
func GroupALPN(service, group string) string {
	return ServiceALPNPrefix + service + "@" + group
}

// alpnAgent is the agent part of an agent as dialled.
func alpnAgent(agent string) string {
	if _, a, ok := strings.Cut(agent, "."); ok {
		return a
	}
	return agent
}

// ErrServiceNotNegotiated: the session's server did not negotiate the
// service protocol the client offered (another service, or none). The
// session is refused.
var ErrServiceNotNegotiated = errors.New("e2ee: the server did not negotiate the service dialled")

// BindServiceTLS makes cfg, a client's TLS of organisation mode, offer
// proto (MachineALPN, GroupALPN) as its only ALPN protocol and fail the
// handshake unless the server negotiated it, after cfg's own
// VerifyConnection (BIND:org.service; e2ee_tcp.pv mutant
// client-no-alpn-check). The checks of the server's certificate (chain,
// name or, for a group dial, OU, NotAfter, CRL) stay cfg's.
func BindServiceTLS(cfg *tls.Config, proto string) {
	cfg.NextProtos = []string{proto}
	verify := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if verify != nil {
			if err := verify(cs); err != nil {
				return err
			}
		}
		return checkNegotiated(cs, proto)
	}
}

// checkNegotiated is the client's check: the negotiated protocol is the
// offer.
func checkNegotiated(cs tls.ConnectionState, proto string) error {
	if cs.NegotiatedProtocol != proto {
		return fmt.Errorf("%w: offered %q, negotiated %q", ErrServiceNotNegotiated, proto, cs.NegotiatedProtocol)
	}
	return nil
}

// serviceBind is what an agent's session of organisation mode accepts:
// the agent's name, the service the session was routed to (the open's
// target), and the group that service is published under ("": none).
type serviceBind struct {
	agent, service, group string
}

// protos are the protocols the agent accepts for b with cert, its
// machine certificate for the session: the machine dial of itself and the
// service, and the service under a group of cert's OU (BIND:org.group)
// that it is published under (BIND:org.publish; e2ee_tcp.pv mutants
// agent-no-alpn-check, agent-no-publish-check).
func (b serviceBind) protos(cert *tls.Certificate) []string {
	p := []string{MachineALPN(b.agent, b.service)}
	for _, g := range certGroups(cert) {
		if g != "" && g == b.group {
			p = append(p, GroupALPN(b.service, g))
		}
	}
	return p
}

// certGroups is cert's leaf's OU: the organisation groups the issuer
// certified; none when the leaf does not parse.
func certGroups(cert *tls.Certificate) []string {
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf == nil {
		return nil
	}
	return leaf.Subject.OrganizationalUnit
}

// checkPublish: a service published under a group needs organisation
// mode and a certificate whose OU holds the group (the agent refuses to
// start one it lacks; BIND:org.publish).
func checkPublish(s Service) error {
	if s.Group == "" {
		return nil
	}
	if !agentservices.ValidLabel(s.Group) {
		return fmt.Errorf("service %q: invalid group %q (a lowercase DNS label)", s.Name, s.Group)
	}
	if s.Org == nil {
		return fmt.Errorf("service %q: group %q needs organisation mode", s.Name, s.Group)
	}
	cert, err := s.Org.Certificate()
	if err != nil {
		return fmt.Errorf("service %q: group %q: this machine's certificate: %w", s.Name, s.Group, err)
	}
	if !slices.Contains(certGroups(cert), s.Group) {
		return fmt.Errorf("service %q: group %q: this machine's certificate is not in it", s.Name, s.Group)
	}
	return nil
}
