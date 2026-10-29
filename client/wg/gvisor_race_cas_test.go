// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"testing"

	gsync "gvisor.dev/gvisor/pkg/sync"
)

// TestGVisorRaceCASSwaps guards the gVisor the netstack tunnel runs on:
// gVisor's sleepers park through this CAS. On arm64 race builds before
// gvisor 1b2946c4fa59 (2026-08-23) it loaded new into old's register and
// always failed, so every parked netstack goroutine woke at once and spun;
// tunnels under -race then starved WireGuard handshakes past their
// retransmit timer (nfltr-relay's TestWGRelayClientReachesOnlyItsTenantsNamedExit).
func TestGVisorRaceCASSwaps(t *testing.T) {
	x := uintptr(1)
	if !gsync.RaceUncheckedAtomicCompareAndSwapUintptr(&x, 1, 2) || x != 2 {
		t.Fatalf("CAS(1→2) on 1 left %d: gVisor sleepers busy-spin instead of parking", x)
	}
	if gsync.RaceUncheckedAtomicCompareAndSwapUintptr(&x, 1, 3) || x != 2 {
		t.Fatalf("CAS(1→3) on 2 swapped to %d", x)
	}
}
