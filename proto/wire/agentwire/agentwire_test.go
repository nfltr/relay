// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentwire

import (
	"maps"
	"strings"
	"testing"
	"time"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"google.golang.org/protobuf/proto"
)

func TestLabelsRoundTrip(t *testing.T) {
	labels := map[string]string{"zone": "b1", "nfltr.machine.resources": "cpu:16,mem:64GB"}
	if got := ParseLabels(EncodeLabels(labels)); !maps.Equal(got, labels) {
		t.Fatalf("round trip = %v, want %v", got, labels)
	}
	if EncodeLabels(nil) != "" {
		t.Fatal("no labels must encode to no value")
	}
	// One encoding: k=v pairs (the pre-v1 fallback) and other non-objects read as none.
	for _, raw := range []string{"", "  ", "zone=b1,fleet=hvac", "[]", `{"a":1}`, "{}"} {
		if got := ParseLabels(raw); got != nil {
			t.Errorf("ParseLabels(%q) = %v, want nil", raw, got)
		}
	}
}

func TestHelloRoundTrip(t *testing.T) {
	c := Client{Name: "nfltr", Version: "v1.0.700", Build: "abc123def456-dirty"}
	md := map[string][]string{}
	kv := c.HelloPairs()
	md[kv[0]] = []string{kv[1]}
	if got, err := ParseHello(md); err != nil || got != c {
		t.Fatalf("round trip = %+v, %v; want %+v", got, err, c)
	}
	bad := Client{Name: "evil\nname", Version: strings.Repeat("9", MaxClientField+1), Build: "a b"}.HelloPairs()
	if got, err := ParseHello(map[string][]string{bad[0]: {bad[1]}}); err != nil || got != (Client{"invalid", "invalid", "invalid"}) {
		t.Fatalf("unsafe values = %+v, %v; want all invalid", got, err)
	}
}

// A call without a v1 Hello (every pre-v1 client) is refused, never read
// as an anonymous client; a reply without a Welcome is a pre-v1 relay.
func TestHelloRequiredAndWelcome(t *testing.T) {
	for name, md := range map[string]map[string][]string{
		"no metadata":   nil,
		"pre-v1 client": {"x-nfltr-client": {"nfltr"}, "x-nfltr-client-version": {"v1.0.685"}},
		"garbage":       {HelloKey: {"\xff\xff"}},
	} {
		if _, err := ParseHello(md); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	two, _ := proto.Marshal(&relayv1.Hello{ProtocolVersion: 2})
	if _, err := ParseHello(map[string][]string{HelloKey: {string(two)}}); err == nil {
		t.Error("protocol version 2 accepted")
	}
	w := WelcomePairs("v1.0.700")
	if !HasWelcome(map[string][]string{w[0]: {w[1]}}) || HasWelcome(nil) {
		t.Error("HasWelcome")
	}
}

func TestSetClientKeepsBuild(t *testing.T) {
	prev := Self()
	t.Cleanup(func() { named.Store(nil) })
	SetClient("nfltr", "v9")
	if got := Self(); got.Name != "nfltr" || got.Version != "v9" || got.Build != prev.Build {
		t.Fatalf("Self() = %+v after SetClient (build was %q)", got, prev.Build)
	}
}

func TestHeartbeatRoundTrip(t *testing.T) {
	kv := HeartbeatPairs(HeartbeatKey, 5*time.Second)
	if got := Heartbeat(map[string][]string{kv[0]: {kv[1]}}, HeartbeatKey); got != 5*time.Second {
		t.Fatalf("Heartbeat = %s, want 5s", got)
	}
	if HeartbeatPairs(HeartbeatKey, 0) != nil {
		t.Fatal("no heartbeats must state none")
	}
	// A relay that states nothing (older, or heartbeats off) or nonsense
	// states no interval.
	for _, md := range []map[string][]string{nil, {HeartbeatKey: {""}}, {HeartbeatKey: {"-5"}}, {HeartbeatKey: {"5s"}}, {HeartbeatKey: {"99999999999"}}} {
		if got := Heartbeat(md, HeartbeatKey); got != 0 {
			t.Errorf("Heartbeat(%v) = %s, want 0", md, got)
		}
	}
}

// The Welcome names the relay id; an absent, oversized or unsafe one reads
// as none.
func TestWelcomeRelayID(t *testing.T) {
	for id, want := range map[string]string{"": "", "R1": "R1", strings.Repeat("a", MaxClientField+1): "", "a,b": ""} {
		w := WelcomeOf("v1", id)
		md := map[string][]string{w[0]: {w[1]}}
		if got := WelcomeRelayID(md); got != want || !HasWelcome(md) {
			t.Errorf("WelcomeRelayID(%q) = %q, want %q", id, got, want)
		}
	}
	if got := WelcomeRelayID(nil); got != "" {
		t.Errorf("no Welcome: %q", got)
	}
	w := WelcomePairs("v1")
	if got := WelcomeRelayID(map[string][]string{w[0]: {w[1]}}); got != "" {
		t.Errorf("WelcomePairs names %q", got)
	}
}

// A connect names the relays the agent holds; a relay is named only by
// its exact id, and a relay without one never.
func TestAgentRelaysNamesRelay(t *testing.T) {
	if AgentRelaysPairs() != nil {
		t.Fatal("no ids: want no pair")
	}
	kv := AgentRelaysPairs("A", "B2")
	if kv[0] != AgentRelaysKey {
		t.Fatalf("key %q", kv[0])
	}
	vals := []string{kv[1]}
	for id, want := range map[string]bool{"A": true, "B2": true, "B": false, "": false, "A,B2": false} {
		if got := NamesRelay(vals, id); got != want {
			t.Errorf("NamesRelay(%q, %q) = %v, want %v", vals, id, got, want)
		}
	}
	if !NamesRelay([]string{"x", " A , C"}, "C") {
		t.Error("second value, spaces")
	}
	if NamesRelay(nil, "A") || NamesRelay([]string{""}, "") {
		t.Error("nothing named")
	}
}
