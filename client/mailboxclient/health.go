// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nfltr/relay/client/relaytrust"
)

// A long-poll parks on a connection that carries nothing until its answer.
// A NAT that lost the connection's mapping meanwhile (a router change, a
// conntrack flush) drops that answer until this side sends a packet on
// the connection, and nothing in a parked pull sends one: TCP's keepalive
// comes after 30 s idle, the pull's deadline after its wait plus 30 s. An
// HTTP/2 health check sends one: a ping once the connection was silent for
// pingAfter re-makes a lost mapping (the relay's retransmission then goes
// through), and a connection whose ping goes unanswered for pingTimeout is
// closed (the pull fails, and its caller pulls again on a new one). Lane
// REVOKEWAKE (docs/decisions/direct-paths-2026-11-11.md in nfltr/nfltr):
// a revocation's push sat at a NAT for 25 s; guard
// TestLongPollAnswerCrossesALostNATMapping.
const (
	pingAfter   = 5 * time.Second
	pingTimeout = 10 * time.Second
)

// relayHTTP is the client of a Client without its own: the relay's
// transport for the pin as it is now (relaytrust.Transport), health-checked;
// one per pin, so connections are reused.
func relayHTTP() *http.Client {
	pin := os.Getenv(relaytrust.PinEnv)
	if c, ok := relayHTTPs.Load(pin); ok {
		return c.(*http.Client)
	}
	c, _ := relayHTTPs.LoadOrStore(pin, healthChecked(relaytrust.Transport(pin), pingAfter, pingTimeout))
	return c.(*http.Client)
}

var relayHTTPs sync.Map // pin -> *http.Client

// healthChecked is a client over a copy of base with HTTP/2 health checks;
// base itself when it is not an *http.Transport.
func healthChecked(base http.RoundTripper, after, timeout time.Duration) *http.Client {
	t, ok := base.(*http.Transport)
	if !ok {
		return &http.Client{Transport: base}
	}
	t = t.Clone()
	h2 := http.HTTP2Config{}
	if t.HTTP2 != nil {
		h2 = *t.HTTP2
	}
	h2.SendPingTimeout, h2.PingTimeout = after, timeout
	t.HTTP2 = &h2
	return &http.Client{Transport: t}
}
