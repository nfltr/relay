// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"net/http"
	"strconv"
	"time"
)

// Throttled wraps base so a request the relay throttles (429 Too Many
// Requests) is resent after the answer's Retry-After (1 s when it names none)
// until it is answered otherwise. A 429 is sent before the request is handled,
// so resending is safe for any method. It is bounded by the request's context
// and Budget: a Retry-After that would pass either returns the 429. A body is
// resent only when the request can replay it (GetBody, as http.NewRequest
// sets for bytes, strings and no body).
func Throttled(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return throttledTransport{base: base}
}

type throttledTransport struct{ base http.RoundTripper }

func (t throttledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deadline := time.Now().Add(Budget)
	if d, ok := req.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for {
		resp, err := t.base.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || (req.Body != nil && req.GetBody == nil) {
			return resp, err
		}
		wait := retryAfter(resp.Header.Get("Retry-After"))
		if time.Now().Add(wait).After(deadline) {
			return resp, nil
		}
		_ = resp.Body.Close()
		if req.Body != nil {
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, bodyErr
			}
			req = req.Clone(req.Context())
			req.Body = body
		}
		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
}

// retryAfter reads Retry-After as seconds or an HTTP date; 1 s otherwise.
func retryAfter(v string) time.Duration {
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(time.Until(at), 0)
	}
	return time.Second
}
