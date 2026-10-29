// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package pb

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestRoutingInfoRoundTrip is a focused contract test: it pins the wire
// behavior of a representative generated message (marshal/unmarshal via the
// real protobuf codec) so an accidental hand-edit to the generated files, or
// a regeneration against a mismatched .proto, is caught before publish.
func TestRoutingInfoRoundTrip(t *testing.T) {
	original := &RoutingInfo{
		AgentId:       "agent-1",
		TargetAgentId: "agent-2",
		DeadlineMs:    12345,
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &RoutingInfo{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.GetAgentId() != original.AgentId ||
		decoded.GetTargetAgentId() != original.TargetAgentId ||
		decoded.GetDeadlineMs() != original.DeadlineMs {
		t.Fatalf("round trip mismatch: got %+v, want %+v", decoded, original)
	}
}

// TestDispatcherServiceRegistered pins the gRPC service name so a proto
// rename shows up as a test failure, not just a runtime surprise for
// consumers dialing the well-known service name.
func TestDispatcherServiceRegistered(t *testing.T) {
	const want = "rpcserver.Dispatcher"
	desc := File_service_proto.Services().ByName("Dispatcher")
	if desc == nil {
		t.Fatalf("service Dispatcher not found in descriptor")
	}
	if got := string(desc.FullName()); got != want {
		t.Fatalf("service full name = %q, want %q", got, want)
	}
}

// TestDispatcherMethods pins the client-callable RPCs: agents connect
// (ConnectHTTP, AgentTunnel, ConnectTCP); relay tunnels are the replica
// link's and FleetInvoke is gone, so neither is a method a client can call.
func TestDispatcherMethods(t *testing.T) {
	methods := File_service_proto.Services().ByName("Dispatcher").Methods()
	var got []string
	for i := range methods.Len() {
		got = append(got, string(methods.Get(i).Name()))
	}
	want := []string{"ConnectHTTP", "AgentTunnel", "ConnectTCP"}
	if len(got) != len(want) {
		t.Fatalf("Dispatcher methods = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Dispatcher methods = %v, want %v", got, want)
		}
	}
}
