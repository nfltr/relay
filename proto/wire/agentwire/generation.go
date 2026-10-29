// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentwire

import "strconv"

// The client generation: a protocol marker every client of the relay built
// from this code sends, on every gRPC call (GenerationKey in its request
// metadata: grpcclient.ClientIdentity) and on every HTTP request of
// tcp-connect's tunnels (the same name as a header: dataplane.Upgrade,
// and the HTTP/2 tunnels). It is not the binary's version: a development
// build sends it too. nfltr v2.0.0 is generation 2; clients before it send
// none. Generation 3 (relay proto v0.16.0, nfltr after v2.1.6) answers
// session opens link's own way (link.FeatureChain) instead of in band: a
// relay that requires it no longer needs the in-band answers
// (dataplane.ReadAnswer). A relay refuses a client below its minimum generation with
// ClientGenerationTooOld (nfltr-relay's security.min_client_generation).
const (
	GenerationKey = "x-nfltr-generation"
	Generation    = 3
)

// ClientGenerationTooOld is the relay's refusal of a client below its
// minimum generation.
const ClientGenerationTooOld = "this nfltr is too old for this relay: run `nfltr update`"

// GenerationPairs is this client's generation as request metadata
// key/value pairs.
func GenerationPairs() []string { return []string{GenerationKey, strconv.Itoa(Generation)} }

// ParseGeneration reads a client's generation from its GenerationKey
// values: 0 when there is none or it is not a number (every client before
// generation 2).
func ParseGeneration(vals []string) int {
	if len(vals) == 0 {
		return 0
	}
	n, err := strconv.Atoi(vals[0])
	if err != nil || n < 0 {
		return 0
	}
	return n
}
