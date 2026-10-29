// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// TestAgentCloseReturnsInEveryState: Close returns promptly whatever the
// agent did before: never connected, a Connect that failed (relay
// unreachable, or WithConnected refusing), connected, closed twice.
func TestAgentCloseReturnsInEveryState(t *testing.T) {
	quiet := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) Agent
	}{
		{"never connected", func(*testing.T) Agent { return New(Config{AgentID: "x", APIKey: "k", Logger: quiet}) }},
		{"connect failed: unreachable", func(t *testing.T) Agent {
			a := New(Config{ServerAddr: "127.0.0.1:1", AgentID: "x", APIKey: "k", Retries: 1, RetryWait: 1, Logger: quiet})
			if a.Connect(context.Background()) == nil {
				t.Fatal("Connect to nothing succeeded")
			}
			return a
		}},
		{"connect failed: refused by WithConnected", func(t *testing.T) Agent {
			f := &fakeRelay{connected: make(chan struct{}, 4)}
			addr, stop := startFakeRelay(t, "127.0.0.1:0", f)
			t.Cleanup(stop)
			a := New(Config{ServerAddr: addr, AgentID: "x", APIKey: "k", Retries: 1, Logger: quiet},
				WithConnected(func(Connection) (*Tunnel, error) { return nil, errors.New("no") }))
			if a.Connect(context.Background()) == nil {
				t.Fatal("Connect succeeded")
			}
			return a
		}},
		{"connected", func(t *testing.T) Agent {
			f := &fakeRelay{connected: make(chan struct{}, 4)}
			addr, stop := startFakeRelay(t, "127.0.0.1:0", f)
			t.Cleanup(stop)
			a := New(Config{ServerAddr: addr, AgentID: "x", APIKey: "k", Retries: 1, Logger: quiet})
			if err := a.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitConnected(t, f, 5*time.Second, "connect")
			return a
		}},
		{"closed twice", func(t *testing.T) Agent {
			f := &fakeRelay{connected: make(chan struct{}, 4)}
			addr, stop := startFakeRelay(t, "127.0.0.1:0", f)
			t.Cleanup(stop)
			a := New(Config{ServerAddr: addr, AgentID: "x", APIKey: "k", Retries: 1, Logger: quiet})
			if err := a.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			a.Close()
			return a
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.setup(t)
			done := make(chan struct{})
			go func() { a.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Close blocked")
			}
		})
	}
}
