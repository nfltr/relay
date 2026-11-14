// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
)

// Config is the caller's identity and how it reaches its relay. Zero values
// are omissions: nothing is read from the environment except where a field
// says so.
type Config struct {
	// Relay is the relay's HTTP address (host:port, "nfltr.xyz:443"), whose
	// data connections carry every session but an nf1 address's (the
	// address names its relay).
	Relay string
	// AgentRelay is the relay's agent-link (gRPC) address: Listen's agent
	// connects there, and direct paths ask its QUIC port (the same number)
	// for this machine's public address; "": Relay.
	AgentRelay string
	// Agent is Listen's agent name (a DNS label): its sessions' targets
	// are <agent>/<service>. Required by Listen, unused by Dial.
	Agent string
	// APIKey authenticates to the relay; ClientCert instead presents an
	// account machine certificate, read per handshake (a renewal swaps it).
	// One of them, never both (NewDialer refuses both).
	APIKey     string
	ClientCert func() (*tls.Certificate, error)
	// Org is this machine's organisation identity (orgid.Load): set, every
	// session is end-to-end encrypted in organisation mode
	// (DialOptions.Plain opens a plain one on purpose); nil, plain. The
	// relay's answer never changes it.
	Org *orgid.Identity
	// RelayTLS verifies the relay (roots, a pin: relaytrust.WithPin); its
	// ServerName defaults to the relay's host. nil: the system roots.
	RelayTLS *tls.Config
	// Plaintext: the relay is a loopback dev relay without TLS. Refused
	// with ClientCert.
	Plaintext bool
	// DialRelay connects to a relay's address (host:port) for Dial; nil:
	// TCP, through the proxy HTTPS_PROXY and NO_PROXY name for it. Listen's
	// agent dials its relay itself.
	DialRelay func(ctx context.Context, addr string) (net.Conn, error)
	// Logger gets Listen's agent's logs (connections, refused sessions);
	// nil: none.
	Logger *slog.Logger
	// Events gets each session's events (open, path, close, error), on the
	// goroutine that caused them: it must not block.
	Events func(Event)
}

// DirectMode is a session's direct-path mode: DirectOff (relayed only),
// DirectOn, DirectPublic (no LAN addresses).
type DirectMode = agent.DirectMode

// The direct modes.
const (
	DirectOff    = agent.DirectOff
	DirectOn     = agent.DirectOn
	DirectPublic = agent.DirectPublic
)

// DialOptions are one dial's choices.
type DialOptions struct {
	// Plain opens a plain session though Config.Org is set: to a service
	// that is not in organisation mode, on purpose.
	Plain bool
	// Direct asks for a direct path (organisation mode or an nf1 address;
	// the service must take them too).
	Direct DirectMode
	// Early returns before the open's answer: bytes written meanwhile go
	// with the open; Conn.Answered tells its outcome. An early dial is not
	// held (its bytes may be gone).
	Early bool
}

func (c Config) check() error {
	switch {
	case c.APIKey != "" && c.ClientCert != nil:
		return usage("Config: APIKey and ClientCert both set: the relay takes one credential")
	case c.Plaintext && c.ClientCert != nil:
		return usage("Config: a ClientCert needs TLS to the relay (Plaintext set)")
	}
	return nil
}
