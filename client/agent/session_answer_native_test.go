// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// On an agent link that negotiated link.FeatureChain (TCP, and QUIC with
// quiclink.ALPNChain) the agent answers link's own way: a refusal is an
// *link.Abort whose code carries the reason, an open is accepted once the
// target is reached, and no answer bytes precede the session's own.
func TestAgentLinkNativeAnswers(t *testing.T) {
	if got := dataplane.AgentLinkALPNs()[0]; got != quiclink.ALPNChain {
		t.Fatalf("AgentLinkALPNs()[0] = %q, want quiclink.ALPNChain %q", got, quiclink.ALPNChain)
	}
	old := targetDialTimeout
	targetDialTimeout = 300 * time.Millisecond
	t.Cleanup(func() { targetDialTimeout = old })
	echo := echoTarget(t)
	tab, err := NewServiceTable([]Service{
		{Name: "db", Kind: agentservices.TCP, Target: echo},
		{Name: "down", Kind: agentservices.TCP, Target: closedAddr(t)},
		{Name: "vault", Kind: agentservices.TCP, Target: echo, E2EE: agentservices.E2EEOn},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{TransportTCP, TransportQUIC} {
		t.Run(transport, func(t *testing.T) {
			r := newFakeLinkRelay(t)
			offer := dataplane.AgentLinkOffer{TCP: true, QUIC: true, QUICPort: r.udpAddr.Port}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ls := &linkSessions{ctx: ctx, targets: sessionTargets{services: tab}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
			go runAgentLink(ctx, r.dialer(transport), testLinkToken, offer, ls, slog.New(slog.DiscardHandler))
			var node peerlink.Link = r.tcp
			if transport == TransportQUIC {
				node = r.quic
			}
			answered := func(target string, answer bool) (peerlink.ChainSession, error) {
				s, ok := r.open(t, node, &pb.TCPData{TargetAddr: target, Answer: answer}).(peerlink.ChainSession)
				if !ok || !s.Answers() {
					t.Fatalf("%s: the session does not answer link's own way", target)
				}
				actx, acancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer acancel()
				return s, s.Answered(actx)
			}
			for target, want := range map[string]relayv1.ErrorReason{
				"down":  relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED,
				"nope":  relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE,
				"vault": relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED,
			} {
				for _, answer := range []bool{true, false} {
					_, err := answered(target, answer)
					var a *link.Abort
					if !errors.As(err, &a) || !a.Refused || a.Msg == "" {
						t.Fatalf("%s (answer %v): %v, want a refusal with a message", target, answer, err)
					}
					if r, ok := dataplane.AbortReason(a); !ok || r != want {
						t.Fatalf("%s (answer %v): reason %v, want %v", target, answer, r, want)
					}
				}
			}
			s, err := answered("db", true)
			if err != nil {
				t.Fatalf("db: %v, want accepted", err)
			}
			_, _ = s.Write([]byte("ping"))
			_ = s.CloseWrite()
			if got, err := io.ReadAll(s); err != nil || string(got) != "ping" {
				t.Fatalf("db: echo %q, %v; want exactly the bytes, then the target's half close", got, err)
			}
			_ = s.Close()
		})
	}
}
