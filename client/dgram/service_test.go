// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// A service's flows are bounded across its associations (lane
// NF1UDPBOUND): many associations, each under its own cap, hold at most
// Service.MaxFlows sockets together; the opens past it are refused full
// and counted, and a flow's place is free again once its association ends.
func TestDatagramServiceBoundsFlowsAcrossAssociations(t *testing.T) {
	to, _ := echo(t, 1)
	svc := &Service{MaxFlows: 16}
	const assocs, perAssoc = 20, 4
	var clients []*Client
	var refused []chan Reason
	for range assocs {
		c, _ := pair(t, Config{}, Config{Service: svc}, dialUDP(to))
		clients = append(clients, c)
		for range perAssoc {
			f, _, cl := recvFlow(c)
			f.Send([]byte("x"))
			refused = append(refused, cl)
		}
	}
	waitFor(t, "every open answered", func() bool {
		st := svc.Stats()
		return st.Flows+st.Refused == assocs*perAssoc
	})
	st := svc.Stats()
	if st.Live != 16 || st.Flows != 16 || st.Refused != assocs*perAssoc-16 || st.FlowsFull != st.Refused {
		t.Fatalf("service %+v, want 16 live and the rest refused full", st)
	}
	// The refusals counted, their R frames may still be on the way.
	full := 0
	for deadline := time.Now().Add(10 * time.Second); full < assocs*perAssoc-16 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, cl := range refused {
			select {
			case r := <-cl:
				if r != ReasonFull {
					t.Fatalf("a flow ended %v, want refused full", r)
				}
				full++
			default:
			}
		}
	}
	if full != assocs*perAssoc-16 {
		t.Fatalf("%d flows told full, want %d", full, assocs*perAssoc-16)
	}
	for _, c := range clients {
		_ = c.Close()
	}
	waitFor(t, "the closed associations' places freed", func() bool { return svc.Stats().Live == 0 })
	c, _ := pair(t, Config{}, Config{Service: svc}, dialUDP(to))
	f, in, _ := recvFlow(c)
	f.Send([]byte("again"))
	if p := recv(t, in); !bytes.Equal(p, []byte("again")) {
		t.Fatalf("got %q", p)
	}
}

// The agent's queue toward a target is bounded in bytes too (lane
// NF1UDPBOUND): a stalled target holds at most QueueBytes of a flow's
// datagrams, the rest counted TargetFull. Before, only QueueLen bounded
// it: 64 datagrams of 64 KiB, 4 MiB a flow, 1 GiB an association.
func TestDatagramTargetQueueBytesBounded(t *testing.T) {
	dial := func() (net.Conn, error) { return stuck{done: make(chan struct{})}, nil }
	c, s := pair(t, Config{}, Config{QueueBytes: 4 << 10}, dial)
	f, _, _ := recvFlow(c)
	const n = 60
	sent := 0
	for range n {
		if f.Send(make([]byte, 1<<10)) {
			sent++
		}
	}
	waitFor(t, "every datagram taken or dropped", func() bool {
		st := s.Stats()
		return st.Datagrams[0]+st.TargetFull == uint64(sent)
	})
	if st := s.Stats(); st.Datagrams[0] > 4 {
		t.Fatalf("%d datagrams of 1 KiB queued for a stalled target, want at most 4 (QueueBytes 4 KiB)", st.Datagrams[0])
	}
}
