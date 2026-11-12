// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package pb

import (
	"encoding/hex"
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

// TestTCPDataCallerWireVector pins the open's caller (field 12, a
// CallerIdentity) and RoutingInfo.caller_group (field 6) on the wire, and
// that a frame from a relay that sends neither decodes as no caller.
func TestTCPDataCallerWireVector(t *testing.T) {
	open := &TCPData{SessionId: "s", Open: true, Caller: &CallerIdentity{
		MachineId: "m-aaaaaaaaaaaaaaaaaaaaaaaaaa", GroupId: "g1", Account: "acct", MachineName: "box"}}
	// field 12 (0x62), 45 bytes: machine_id (0x0a), group_id (0x12), account (0x1a), machine_name (0x22)
	const want = "0a01732801622d0a1c6d2d6161616161616161616161616161616161616161616161616161120267311a04616363742203626f78"
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != want {
		t.Fatalf("wire = %s, want %s", got, want)
	}
	back := &TCPData{}
	if err := proto.Unmarshal(b, back); err != nil || !proto.Equal(back, open) {
		t.Fatalf("round trip = %v (%v), want %v", back, err, open)
	}
	old, _ := hex.DecodeString("0a01732801") // session_id "s", open: no caller
	back = &TCPData{}
	if err := proto.Unmarshal(old, back); err != nil || back.GetCaller() != nil || back.GetCaller().GetMachineId() != "" {
		t.Fatalf("old frame caller = %v (%v), want none", back.GetCaller(), err)
	}
	ri := &RoutingInfo{AgentId: "a", CallerGroup: "g1"}
	if b, _ = proto.Marshal(ri); hex.EncodeToString(b) != "0a016132026731" {
		t.Fatalf("routing info wire = %x", b)
	}
}

// TestTCPDataExcludeWireVector pins the open's exclude list (field 13,
// repeated string) on the wire.
func TestTCPDataExcludeWireVector(t *testing.T) {
	open := &TCPData{Open: true, Exclude: []string{"a-pg", "b-pg"}}
	// open (0x28 01), then field 13 (0x6a) twice: 4 bytes each
	const want = "28016a04612d70676a04622d7067"
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != want {
		t.Fatalf("wire = %s, want %s", got, want)
	}
}
