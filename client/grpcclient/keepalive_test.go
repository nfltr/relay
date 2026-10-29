// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient_test

import (
	"testing"
	"time"

	"github.com/nfltr/relay/client/grpcclient"
)

// TestKeepaliveParams: the values that survive ~10-minute relay flaps:
// a ping every 30 s, abort after a 10 s unanswered ping (Time > Timeout > 0),
// pings even with no active RPC.
func TestKeepaliveParams(t *testing.T) {
	kp := grpcclient.KeepaliveParams()
	if kp.Time != 30*time.Second {
		t.Errorf("Time = %v, want 30s", kp.Time)
	}
	if kp.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", kp.Timeout)
	}
	if !kp.PermitWithoutStream {
		t.Error("PermitWithoutStream = false, want true")
	}
}
