// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// An nf1 session whose target resets reads as a reset at the client,
// never as the service's clean end: the agent ends its end-to-end TLS
// without close_notify (lane NFCAT: peerlink.Join closed the plain
// *tls.Conn, its close_notify a clean end, so an nfltr-pipe listener's
// failure read as the end of the other side's stdout). A clean end
// still reads as one.
func TestNF1TargetResetIsResetAtClient(t *testing.T) {
	for _, reset := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*net.TCPConn)
			_, _ = io.ReadFull(tc, make([]byte, len("hello")))
			_, _ = io.WriteString(tc, "hi")
			if reset {
				_ = tc.SetLinger(0) // the target's reset
				_ = tc.Close()
				return
			}
			_ = tc.CloseWrite()
			_, _ = io.Copy(io.Discard, tc)
			_ = tc.Close()
		}()
		l, _, err := nf1.Mint("relay.example")
		if err != nil {
			t.Fatal(err)
		}
		table, err := NewServiceTable([]Service{{Name: "clip", Kind: agentservices.TCP, E2EE: agentservices.E2EEOn, Target: ln.Addr().String(), NF1: l}})
		if err != nil {
			t.Fatal(err)
		}
		p, err := planOpen(&pb.TCPData{TargetAddr: "clip", E2Ee: true, Answer: true}, sessionTargets{services: table}, nil)
		if err != nil {
			t.Fatal(err)
		}
		target, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c, s := net.Pipe()
		go serveNF1(t.Context(), s, target, p, slog.New(slog.DiscardHandler))
		w, bind := tlsend.Wrap(c)
		hc, err := nf1.Handshake(t.Context(), w, l.Address())
		if err != nil {
			t.Fatal(err)
		}
		conn := bind(hc.(*tls.Conn))
		if _, err := io.WriteString(conn, "hello"); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(conn)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("reset %v: the client's read did not end", reset)
		}
		if reset && err == nil {
			t.Errorf("reset: the client read %q and a clean end, want a reset", got)
		}
		if !reset && (err != nil || string(got) != "hi") {
			t.Errorf("clean end: the client read %q, %v; want hi and a clean end", got, err)
		}
		_ = conn.CloseWrite()
		_ = c.Close()
	}
}
