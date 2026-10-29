// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"testing"
	"time"
)

// TestParsePeerStatus: one peer's handshake time and both byte counts
// from a UAPI dump, none of another peer's.
func TestParsePeerStatus(t *testing.T) {
	dump := "private_key=aa\npublic_key=other\nrx_bytes=9\ntx_bytes=9\n" +
		"public_key=peer\nlast_handshake_time_sec=100\nlast_handshake_time_nsec=5\nrx_bytes=148\ntx_bytes=92\n"
	st, found := parsePeerStatus(dump, "peer")
	if !found || st.RxBytes != 148 || st.TxBytes != 92 || !st.LastHandshake.Equal(time.Unix(100, 5)) {
		t.Fatalf("got %+v %v", st, found)
	}
	if _, found := parsePeerStatus(dump, "missing"); found {
		t.Fatal("found a peer the dump does not have")
	}
}
