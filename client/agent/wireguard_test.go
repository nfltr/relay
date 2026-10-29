// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/metadata"
)

type fakeExit struct {
	enabled bool
	started int
	closed  int
	err     error
	tunnel  WireGuardTunnel
}

func (f *fakeExit) Enabled() bool                  { return f.enabled }
func (f *fakeExit) ConnectMetadata(md metadata.MD) { md.Set("x-wg-pubkey", "k") }
func (f *fakeExit) Close()                         { f.closed++ }
func (f *fakeExit) Start(context.Context, metadata.MD, *slog.Logger) (WireGuardTunnel, error) {
	f.started++
	return f.tunnel, f.err
}

type fakeTunnel struct{}

func (fakeTunnel) Handle(*pb.HTTPRequest) bool                             { return false }
func (fakeTunnel) Pump(context.Context, func(*pb.HTTPProxyResponse) error) {}

// TestWireGuardExitHook: the agent asks an enabled exit for its metadata and
// tunnel, keeps it off the move path, surfaces a refusal and an option error,
// and ignores an exit that is not enabled (a pairing key alone).
func TestWireGuardExitHook(t *testing.T) {
	a := &agent{logger: slog.New(slog.DiscardHandler)}
	if !a.canMove() {
		t.Fatal("an agent without an exit cannot move")
	}
	off := &fakeExit{}
	WithWireGuardExit(func(prev WireGuardExit) (WireGuardExit, error) { return off, nil })(a)
	md := metadata.New(nil)
	a.setWireGuardMetadata(md)
	if md.Len() != 0 || !a.canMove() || a.startWireGuardFromHeader(context.Background(), metadata.Pairs("a", "b")) != nil || off.started != 0 {
		t.Fatal("an exit that is not enabled was used")
	}

	on := &fakeExit{enabled: true, tunnel: fakeTunnel{}}
	WithWireGuardExit(func(prev WireGuardExit) (WireGuardExit, error) {
		if prev != off {
			t.Errorf("prev = %v; want the exit set before", prev)
		}
		return on, nil
	})(a)
	a.setWireGuardMetadata(md)
	if md.Get("x-wg-pubkey") == nil || a.canMove() {
		t.Fatal("an enabled exit sent no metadata or moves")
	}
	if err := a.startWireGuardFromHeader(context.Background(), metadata.MD{}); err != nil || on.started != 0 {
		t.Fatal("a stream the relay refused started a tunnel")
	}
	if err := a.startWireGuardFromHeader(context.Background(), metadata.Pairs("a", "b")); err != nil || a.wgx == nil {
		t.Fatalf("start: %v, tunnel %v", err, a.wgx)
	}
	refuse := errors.New("relay too old")
	on.err, on.tunnel = refuse, nil
	if err := a.startWireGuardFromHeader(context.Background(), metadata.Pairs("a", "b")); !errors.Is(err, refuse) {
		t.Fatalf("refusal: %v", err)
	}
	a.closeWireGuard()
	if on.closed != 1 {
		t.Fatal("Close did not close the exit")
	}

	WithWireGuardExit(func(prev WireGuardExit) (WireGuardExit, error) { return prev, refuse })(a)
	if !errors.Is(a.initErr, refuse) || a.wgExit != on {
		t.Fatalf("option error: initErr %v, exit %v", a.initErr, a.wgExit)
	}
}
