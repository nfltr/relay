// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"testing"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// closingAgent's Close blocks until release: an agent still stopping.
type closingAgent struct {
	agent.Agent
	in, release chan struct{}
}

func (a closingAgent) Close() { close(a.in); <-a.release }

// TestCloseWaitsForTheFirstClose (lane SENDBEST, nfltr-send --once): a
// second Close returns only once the first one finished. It returned at
// once, so a program whose deferred Close ran while another goroutine's
// Close was still resetting sessions and stopping the agent exited before
// its peers heard of the end, and a receiver waited out its 30 s close
// bound for an acknowledgement from a process that was gone.
func TestCloseWaitsForTheFirstClose(t *testing.T) {
	q := agent.NewSessionQueue(1)
	table, err := agent.NewServiceTable([]agent.Service{{Name: "s", Kind: agentservices.TCP, Queue: q}})
	if err != nil {
		t.Fatal(err)
	}
	a := closingAgent{in: make(chan struct{}), release: make(chan struct{})}
	ended := make(chan struct{})
	close(ended)
	l := &Listener{a: a, q: q, table: table, cancel: func() {}, conns: map[*Conn]struct{}{}, ended: ended}
	first, second := make(chan struct{}), make(chan struct{})
	go func() { _ = l.Close(); close(first) }()
	<-a.in
	go func() { _ = l.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("a second Close returned while the first was still stopping the agent")
	case <-time.After(100 * time.Millisecond):
	}
	close(a.release)
	<-first
	<-second
}
