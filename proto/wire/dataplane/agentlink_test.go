// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
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
	h, err := OpenHeader(&pb.TCPData{SessionId: "7", Open: true, AgentId: "a", TargetAddr: HTTPSessionTarget, E2Ee: true})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseOpenHeader(h)
	if err != nil || f.GetSessionId() != "" || f.GetOpen() || f.GetAgentId() != "a" || f.GetTargetAddr() != HTTPSessionTarget || !f.GetE2Ee() {
		t.Fatalf("%v %v", f, err)
	}
}
