// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package relayoutage lets a relay client ride out a relay that refuses
// connections (restart or deploy window), bounded by Budget. It is the one
// outage wait shared by the orch CLI and nfltr mcp.
package relayoutage

import (
	"errors"
	"net"
	"net/http"
	"time"
)

// Budget bounds how long one relay request waits for a relay that
// refuses connections (restart or deploy window) when its context sets no
// earlier deadline.
var Budget = 2 * time.Minute

// Transport wraps base so a request whose connection to the relay
// could not be established is resent, with capped backoff, until the relay
// accepts it, the request's context ends, or Budget elapses. Only
// dial failures are resent: such a request never reached the relay, so
// resending is safe for any method. Errors after the connection was made
// (reset, EOF, status codes) are returned unchanged for the caller's own
// idempotency-aware retry.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return relayOutageTransport{base: base}
}

type relayOutageTransport struct{ base http.RoundTripper }

func (t relayOutageTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deadline := time.Now().Add(Budget)
	backoff := 200 * time.Millisecond
	for {
		resp, err := t.base.RoundTrip(req)
		if err == nil || !isDialError(err) || req.Context().Err() != nil || time.Now().After(deadline) {
			return resp, err
		}
		if req.Body != nil {
			if req.GetBody == nil {
				return resp, err
			}
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return resp, err
			}
			req = req.Clone(req.Context())
			req.Body = body
		}
		timer := time.NewTimer(backoff)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		backoff = min(backoff*2, time.Second)
	}
}

func isDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
