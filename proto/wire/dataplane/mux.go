// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"context"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
)

// Session is one session of a Mux, a net.Conn (link.Session).
type Session = link.Session

// OwnedWriter is a writer that may keep the slices it is given: WriteTo
// hands it the received slices themselves, no copy (the relay's agent
// sessions, which queue them as frames).
type OwnedWriter = link.OwnedWriter

// Mux carries sessions over a Conn, each a net.Conn: tcp-connect's tunnels
// to the relay. A session's open is an OPEN frame whose header is the open
// TCPData without its session id and open flag (Conn.Send's encoding).
type Mux struct {
	m *link.Mux
	c *Conn
}

// NewMux returns a Mux over c.
func NewMux(c *Conn) *Mux {
	return &Mux{m: link.NewMux(c.Conn), c: c}
}

// Open starts a session whose open carries open's fields (the agent and
// target); the Mux picks its session id.
func (m *Mux) Open(open *pb.TCPData) (*Session, error) {
	header, err := OpenHeader(open)
	if err != nil {
		return nil, err
	}
	return m.m.Open(header)
}

// Serve receives frames until the connection ends (link.Mux.Serve).
// accept, nil on the opening side, gets each session the peer opens with
// its open's fields; a session whose header is not a TCPData is refused
// (INVALID_ARGUMENT where the connection negotiated link.FeatureChain).
func (m *Mux) Serve(accept func(open *pb.TCPData, s *Session)) error {
	if accept == nil {
		return m.m.Serve(nil)
	}
	return m.m.Serve(func(header []byte, s *Session) {
		f, err := ParseOpenHeader(header)
		if err != nil {
			_ = s.AbortWith(Refusal(relayv1.ErrorReason_ERROR_REASON_INVALID_ARGUMENT, "the open's header is no TCPData"))
			return
		}
		accept(f, s)
	})
}

// Drain closes the connection gracefully (link.Mux.Drain): GOAWAY tells
// the peer to open its next sessions on another connection (its Open
// fails link.ErrGoAway), the open sessions run to their end or ctx's
// deadline, where each still open is aborted link.CodeDrainDeadline (on a
// link.FeatureChain connection; a peer without it reads the connection's
// end). A relay drains its clients' data connections so when it leaves.
// allow:wrapper
func (m *Mux) Drain(ctx context.Context) error { return m.m.Drain(ctx) }

// Close ends the connection and every session. allow:wrapper
func (m *Mux) Close() error { return m.m.Close() }
