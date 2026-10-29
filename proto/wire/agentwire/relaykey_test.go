// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentwire

import (
	"strings"
	"testing"
)

func TestRelayKeyAuthorization(t *testing.T) {
	key := "rpc_" + strings.Repeat("ab", 32)
	for v, want := range map[string]bool{
		"Bearer " + key:  true,
		"ApiKey " + key:  true,
		"Bearer  " + key: true,
		"Bearer fleet_" + strings.Repeat("cd", 48): true,
		"Bearer app-token":                         false,
		"ApiKey app-key":                           false,
		"Basic cnBjX2FiOg==":                       false,
		key:                                        false,
		"":                                         false,
	} {
		if got := RelayKeyAuthorization(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
