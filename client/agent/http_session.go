// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/nfltr/relay/client/internal/bytequeue"
	"github.com/nfltr/relay/proto/pb"
)

// HTTP on link sessions (client generation 3): the relay opens a session
// to dataplane.HTTPSessionTarget on one of the agent's TCP streams (a link
// data connection first) and writes HTTP/1.1 requests into it; the agent
// serves them with net/http.

// HTTPSessionsOnly is the HTTPSessionsHeader value of a tunnel that serves
// HTTP sessions and no raw TCP targets; "1" serves both.
const HTTPSessionsOnly = "only"

// serveHTTPSession serves one session's HTTP/1.1 connection with h until
// the relay or h closes it.
func (t *tcpTunnel) serveHTTPSession(id string, q *bytequeue.Queue, h http.Handler) {
	serveHTTPConn(newSessionConn(t, id, q), h)
}

// Tunnel is what an agent's TCP streams serve.
type Tunnel struct {
	// HTTP serves sessions to dataplane.HTTPSessionTarget (the agent's
	// HTTP tunnel on link sessions); nil serves none.
	HTTP http.Handler
	// RawTCP lets the relay's sessions dial their target (ForwardAddr when
	// set, else the address the relay names); false refuses them.
	RawTCP      bool
	ForwardAddr string
	// E2EE terminates E2EE sessions and proxies them to DefaultBackend.
	E2EE           *E2EESetup
	DefaultBackend string
	// Services, when set, are the only targets of raw and E2EE sessions
	// (ForwardAddr, RawTCP and DefaultBackend unused), as for
	// RunServiceTunnel.
	Services *ServiceTable
}

// RunTunnel serves an agent's ConnectTCP stream (and the further streams
// its relay asks for, as RunTCPTunnel) with what t says.
func RunTunnel(ctx context.Context, client pb.DispatcherClient, dial RelayDialer, streamCtx context.Context, t Tunnel, logger *slog.Logger) error {
	var e2ee *e2eeTLSConfig
	if t.E2EE != nil {
		e2ee = t.E2EE.cfg
	}
	return runTCPTunnel(ctx, client, dial, streamCtx, sessionTargets{
		forwardAddr: t.ForwardAddr, defaultBackend: t.DefaultBackend, services: t.Services, http: t.HTTP, noRaw: !t.RawTCP && t.Services == nil,
	}, e2ee, logger, nil)
}

// httpSessionsValue is the HTTPSessionsHeader value targets announce; ""
// for none.
func (s sessionTargets) httpSessionsValue() string {
	switch {
	case s.http == nil:
		return ""
	case s.noRaw && s.services == nil:
		return HTTPSessionsOnly
	}
	return "1"
}

