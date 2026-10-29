// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"
)

// TestTargetDialerKeepAlive: the agent's target connections carry an
// explicit TCP keepalive, so a silent forward: host is noticed in about
// 25 s instead of Go's default 150 s (measured in nfltr's
// tests/connect/grpc-liveness, claims 6a/6b).
func TestTargetDialerKeepAlive(t *testing.T) {
	d := targetDialer()
	ka := d.KeepAliveConfig
	if !ka.Enable || d.KeepAlive < 0 {
		t.Fatalf("keepalive off: %+v", d)
	}
	if detect := ka.Idle + ka.Interval*time.Duration(ka.Count); detect <= 0 || detect > 30*time.Second {
		t.Fatalf("a silent target is noticed after %s, want at most 30 s (%+v)", detect, ka)
	}
	if d.Timeout != targetDialTimeout {
		t.Fatalf("dial timeout %s, want %s", d.Timeout, targetDialTimeout)
	}
}
