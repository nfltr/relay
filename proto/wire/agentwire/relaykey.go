// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentwire

import "strings"

// RelayKeyAuthorization reports whether an Authorization header value
// (Bearer or ApiKey) holds a credential of the shape a relay mints: an API
// key "rpc_<hex>" or a fleet token "fleet_<hex>". A relay credential is for
// the relay: whichever edge forwards a visitor's request to a service (the
// relay, or the agent ending an E2EE session's TLS) removes such a value,
// whoever sent it.
func RelayKeyAuthorization(v string) bool {
	tok, ok := strings.CutPrefix(v, "Bearer ")
	if !ok {
		tok, ok = strings.CutPrefix(v, "ApiKey ")
	}
	tok = strings.TrimSpace(tok)
	return ok && (strings.HasPrefix(tok, "rpc_") || strings.HasPrefix(tok, "fleet_"))
}
