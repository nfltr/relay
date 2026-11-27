// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

func TestLinkHello(t *testing.T) {
	for _, bound := range []bool{true, false} {
		a, b := net.Pipe()
		got := make(chan string, 1)
		go func() {
			tok, err := ReadLinkHello(b)
			if err != nil {
				t.Error(err)
			}
			got <- tok
			_ = AnswerLinkHello(b, bound)
		}()
		err := WriteLinkHello(a, "tok-123")
		if tok := <-got; tok != "tok-123" {
			t.Fatalf("token %q", tok)
		}
		if bound && err != nil || !bound && !errors.Is(err, ErrLinkHelloRefused) {
			t.Fatalf("bound=%v: %v", bound, err)
		}
		_ = a.Close()
		_ = b.Close()
	}
}

func TestReadLinkHelloRefusesMalformed(t *testing.T) {
	for name, in := range map[string][]byte{
		"magic":     []byte("NFDP\x00\x01x"),
		"too long":  append([]byte(AgentLinkMagic), 0xff, 0xff),
		"truncated": append([]byte(AgentLinkMagic), 0, 5, 'a'),
	} {
		if _, err := ReadLinkHello(bytes.NewReader(in)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := ReadLinkHello(bytes.NewReader([]byte("NFDP\x00\x01x"))); !errors.Is(err, link.ErrFrame) {
		t.Errorf("magic: %v", err)
	}
}

func TestParseAgentLinkOffer(t *testing.T) {
	for _, tc := range []struct {
		link, port []string
		want       AgentLinkOffer
	}{
		{nil, nil, AgentLinkOffer{}},
		{[]string{"tcp"}, nil, AgentLinkOffer{TCP: true}},
		{[]string{"tcp, quic"}, []string{"443"}, AgentLinkOffer{TCP: true, QUIC: true, QUICPort: 443}},
		{[]string{"tcp", "quic"}, nil, AgentLinkOffer{TCP: true}}, // QUIC without a port is no offer
		{[]string{"quic"}, []string{"x"}, AgentLinkOffer{}},
		{[]string{"grpc"}, []string{"443"}, AgentLinkOffer{QUICPort: 443}},
	} {
		if got := ParseAgentLinkOffer(tc.link, tc.port); got != tc.want {
			t.Errorf("%v %v: %+v, want %+v", tc.link, tc.port, got, tc.want)
		}
	}
}

func TestOpenHeaderRoundTrip(t *testing.T) {
	h, err := OpenHeader(&pb.TCPData{SessionId: "7", Open: true, AgentId: "a", TargetAddr: HTTPSessionTarget, E2Ee: true, Exclude: refs(MaxExclude)})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseOpenHeader(h)
	if err != nil || f.GetSessionId() != "" || f.GetOpen() || f.GetAgentId() != "a" || f.GetTargetAddr() != HTTPSessionTarget || !f.GetE2Ee() || !slices.Equal(f.GetExclude(), refs(MaxExclude)) {
		t.Fatalf("%v %v", f, err)
	}
}

// refs is n distinct agent refs.
func refs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("m-%026d-pg", i)
	}
	return out
}

func TestOpenHeaderRefusesABadExclude(t *testing.T) {
	for name, ex := range map[string][]string{
		"over MaxExclude": refs(MaxExclude + 1),
		"empty ref":       {""},
		"not a label":     {"m-1/pg"},
		"upper case":      {"M-1-PG"},
		"over 63 bytes":   {strings.Repeat("a", 64)},
		"repeated":        {"m-1-pg", "m-2-pg", "m-1-pg"},
	} {
		if _, err := OpenHeader(&pb.TCPData{AgentId: "a", Exclude: ex}); err == nil {
			t.Errorf("%s: OpenHeader wrote %q", name, ex)
		}
		raw, err := proto.Marshal(&pb.TCPData{AgentId: "a", Exclude: ex})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseOpenHeader(raw); err == nil {
			t.Errorf("%s: ParseOpenHeader read %q", name, ex)
		}
	}
}
