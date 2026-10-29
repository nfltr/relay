// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build conformance

package p2p

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestSTUNProbe is the STUN/TURN conformance suite's view of nfltr's own STUN
// client (tests/conformance/protocols/stun/run.sh): for each server in
// STUN_PROBE_SERVERS (comma-separated host:port) it prints the
// server-reflexive address DiscoverExternalAddr finds, as
// "mapped <server> <addr>" or "error <server> <err>". Every probe binds
// local UDP port STUN_PROBE_PORT (as GatherCandidates binds its TCP
// listener's port), so mappings toward two servers compare like for like.
func TestSTUNProbe(t *testing.T) {
	servers := os.Getenv("STUN_PROBE_SERVERS")
	if servers == "" {
		t.Skip("STUN_PROBE_SERVERS not set (conformance harness only)")
	}
	port, err := strconv.Atoi(os.Getenv("STUN_PROBE_PORT"))
	if err != nil {
		t.Fatalf("STUN_PROBE_PORT: %v", err)
	}
	orig := STUNServer
	defer func() { STUNServer = orig }()
	for s := range strings.SplitSeq(servers, ",") {
		STUNServer = s
		if addr, err := DiscoverExternalAddr(port); err != nil {
			fmt.Printf("error %s %v\n", s, err)
		} else {
			fmt.Printf("mapped %s %s\n", s, addr)
		}
	}
}
