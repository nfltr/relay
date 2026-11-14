// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/client/tlsend"
	"github.com/nfltr/relay/proto/pb"
)

// Organisation mode: TLS with the organisation's machine the target names
// (its certificate's chain, name and CRL), or for a group dial any machine
// of the group, never the relay's word for it (relay
// spec/proverif/e2ee_tcp.pv; mutant downgrade-plain: the relay's answer
// never changes the mode). Direct paths (nfltr
// docs/decisions/direct-paths-2026-11-11.md): a session that asks is
// framed for them from its first byte and moves to a QUIC connection
// straight to the agent's machine when one can be punched, back to the
// relay when it dies.

// orgSession puts c's end-to-end TLS on ls (framed for direct paths when
// direct asks); run, after the handshake, starts its moves. A machine that
// cannot make its direct paths opens the session relayed, and says so (a
// path event).
func (c *Conn) orgSession(d *Dialer, ls net.Conn, t Target, org *orgid.Identity, direct DirectMode) (run func()) {
	type doner interface{ Done() <-chan struct{} }
	raw, done := ls, ls.(doner).Done()
	run = func() {}
	if direct != DirectOff {
		if dc, err := d.orgDirect(org); err != nil {
			c.onPath(agent.PathEvent{Path: agent.PathRelayed, Reason: "no_socket"})
		} else {
			c.ds = dc.Start(ls)
			raw, done = c.ds.Conn(), c.ds.Done()
			run = func() {
				// The machine the session's certificate names: the one
				// checked (a machine dial), or the relay's pick (a group dial).
				cs := c.tc.ConnectionState()
				if err := c.ds.Run(cs, agentID(t), cs.PeerCertificates[0].Subject.CommonName, t.Service, direct, c.onPath); err != nil {
					c.onPath(agent.PathEvent{Path: agent.PathRelayed, Reason: "no_exporter"})
				}
			}
		}
	}
	c.useOrgTLS(raw, t, org, done)
	return run
}

// useOrgTLS makes c the end-to-end TLS client to t on raw (orgTLS), ended
// with done.
func (c *Conn) useOrgTLS(raw net.Conn, t Target, org *orgid.Identity, done <-chan struct{}) {
	c.tc = tlsend.Client(raw, c.orgTLS(raw, t, org, done))
	c.s, c.done = c.tc, done
}

// orgTLS is the session's TLS client to t: the machine t names, or for a
// group dial (<service>@<group>) any machine of the group. Either way the
// session is bound to the service dialled by ALPN (agent.BindServiceTLS:
// BIND:org.service), which the server's certificate alone does not do (it
// names the machine, which serves every service on it). A session ends at
// its admission's end (orgid.Identity.Hold: the server certificate's NotAfter or the
// CRL's NextUpdate, or a change after which the check refuses it): raw is
// reset then (cutRaw), at both ends.
func (c *Conn) orgTLS(raw net.Conn, t Target, org *orgid.Identity, done <-chan struct{}) *tls.Config {
	changed := org.Changed() // before the check: a change after it is seen
	admitted := func(check func([]*x509.Certificate, time.Time) (time.Time, error)) func([]*x509.Certificate, time.Time) {
		return func(certs []*x509.Certificate, until time.Time) {
			go org.Hold(until, changed, func(now time.Time) (time.Time, error) { return check(certs, now) },
				func() { cutRaw(raw) }, done)
		}
	}
	var cfg *tls.Config
	if t.Kind == GroupTarget {
		cfg = org.GroupClientTLS(t.Group, admitted(func(certs []*x509.Certificate, now time.Time) (time.Time, error) {
			return org.CheckServerGroup(certs, t.Group, now)
		}))
		agent.BindServiceTLS(cfg, agent.GroupALPN(t.Service, t.Group))
	} else {
		name := orgServerName(t)
		cfg = org.ClientTLS(name, admitted(func(certs []*x509.Certificate, now time.Time) (time.Time, error) {
			return org.CheckServer(certs, name, now)
		}))
		agent.BindServiceTLS(cfg, agent.MachineALPN(agentID(t), t.Service))
	}
	c.recordRefused(cfg)
	return cfg
}

// orgServerName is the organisation machine a machine dial checks: the
// machine of <machine>.<agent> (another relay machine's agent), else the
// agent itself.
func orgServerName(t Target) string {
	if t.Kind == MachineTarget {
		return t.Machine
	}
	return t.Agent
}

// cutRaw ends raw as a reset: a direct-path session's (its Reset: the
// ABORT on its current path, direct or relayed) or a link session's, else
// its Close. A direct-path session's Close is its clean end, which waits
// for the peer's: a revoked agent's bytes would flow meanwhile
// (TestCutRawResetsADirectSession).
func cutRaw(raw net.Conn) {
	if r, ok := raw.(interface{ Reset() error }); ok {
		_ = r.Reset()
		return
	}
	_ = raw.Close()
}

// orgDirect is the organisation sessions' direct paths, made at the first
// session that asks, with this machine's identity org.
func (d *Dialer) orgDirect(org *orgid.Identity) (*agent.DirectClient, error) {
	return d.directClient("", func() (*agent.DirectClient, error) {
		return agent.NewDirectClient(agent.DirectClientConfig{
			Machine: org,
			Relayed: func(ctx context.Context, agentID string) (net.Conn, error) {
				return d.openAnswered(ctx, &pb.TCPData{AgentId: agentID, TargetAddr: agent.DirectServiceName, E2Ee: true})
			},
			RelayedGroup: func(ctx context.Context, name string, exclude []string) (net.Conn, error) {
				t, err := ParseTarget(name)
				if err != nil {
					return nil, err
				}
				return d.openAnswered(ctx, &pb.TCPData{AgentId: name, TargetAddr: t.Service, E2Ee: true, Exclude: exclude})
			},
			QADTLS: func(string) *tls.Config { return d.relayTLS(d.cfg.Relay) },
			OwnQAD: d.ownQAD(),
		})
	})
}

// ownQAD is this machine's own relay's QAD address, taken when the
// agent's relay (the offer's) does not answer: its agent-link address,
// whose port number its QUIC agent link shares.
func (d *Dialer) ownQAD() string {
	if d.cfg.AgentRelay != "" {
		return d.cfg.AgentRelay
	}
	return d.cfg.Relay
}

// directClient is the Dialer's direct paths for key, made by mk at the
// first session that asks; refused once the Dialer is closed.
func (d *Dialer) directClient(key string, mk func() (*agent.DirectClient, error)) (*agent.DirectClient, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errClosed
	}
	if dc := d.direct[key]; dc != nil {
		return dc, nil
	}
	dc, err := mk()
	if err == nil {
		d.direct[key] = dc
	}
	return dc, err
}

// openAnswered opens a session through the relay, answered: to an agent's
// reserved direct service (a control exchange, a re-attach), or to a group
// dial's service, the machines it excludes left out.
func (d *Dialer) openAnswered(ctx context.Context, open *pb.TCPData) (net.Conn, error) {
	ls, err := d.openData(ctx, open)
	if err != nil {
		return nil, err
	}
	if err := ls.Answered(ctx); err != nil {
		_ = ls.Close()
		return nil, err
	}
	return ls, nil
}
