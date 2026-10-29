// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"testing"
	"time"

	"google.golang.org/grpc/keepalive"
)

// TestDial_RequiresAPIKeyOrClientCert: Dial authenticates only with an API
// key (x-api-key) or a client certificate, the two credentials the relay's
// gRPC port reads; anything else is refused before a stream opens.
func TestDial_RequiresAPIKeyOrClientCert(t *testing.T) {
	_, err := Dial(t.Context(), "127.0.0.1:1", WithAgentID("agent-a"))
	if err == nil {
		t.Fatal("Dial without credentials succeeded")
	}
	want := "rpcclient: no authentication configured — use WithAPIKey() or WithClientCert()"
	if err.Error() != want {
		t.Fatalf("Dial error = %q, want %q", err, want)
	}
}

func TestWithKeepalive_SetsOption(t *testing.T) {
	var do dialOptions
	params := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	WithKeepalive(params)(&do)

	if do.keepalive == nil {
		t.Fatal("expected keepalive to be set")
	}
	if do.keepalive.Time != 30*time.Second {
		t.Fatalf("expected Time=30s, got %v", do.keepalive.Time)
	}
	if do.keepalive.Timeout != 10*time.Second {
		t.Fatalf("expected Timeout=10s, got %v", do.keepalive.Timeout)
	}
	if !do.keepalive.PermitWithoutStream {
		t.Fatal("expected PermitWithoutStream=true")
	}
}

// TestDefaultKeepaliveParams verifies the recommended defaults: 60 s interval
// (stays below GCP NAT's 30-min TCP idle timeout while exceeding the server's
// 5-min enforcement MinTime), 20 s ACK timeout (tolerates transient delays).
func TestDefaultKeepaliveParams(t *testing.T) {
	kp := DefaultKeepaliveParams()
	if kp.Time != 60*time.Second {
		t.Fatalf("Time = %v, want 60s", kp.Time)
	}
	if kp.Timeout != 20*time.Second {
		t.Fatalf("Timeout = %v, want 20s", kp.Timeout)
	}
	if !kp.PermitWithoutStream {
		t.Fatal("PermitWithoutStream = false, want true")
	}
}
