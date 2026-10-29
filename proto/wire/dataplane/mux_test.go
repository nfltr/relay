// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
)

// muxPair returns an opener Mux and the accepting Mux's peer, serving
// sessions with accept.
func muxPair(t *testing.T, accept func(*pb.TCPData, *Session)) *Mux {
	t.Helper()
	a, b := v2pair(t)
	client, server := NewMux(a), NewMux(b)
	go func() { _ = client.Serve(nil) }()
	go func() { _ = server.Serve(accept) }()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client
}

// echoAccept echoes every session except those whose agent is "nope",
// which it refuses.
func echoAccept(open *pb.TCPData, s *Session) {
	defer s.Close() //nolint:errcheck
	if open.GetAgentId() == "nope" {
		return
	}
	_, _ = io.Copy(s, s)
}

func TestMuxSessions(t *testing.T) {
	client := muxPair(t, echoAccept)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 3*testWindow/16) // past a window: credit must return
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			s, err := client.Open(&pb.TCPData{AgentId: "echo", TargetAddr: "22"})
			if err != nil {
				t.Error(err)
				return
			}
			msg := append([]byte(fmt.Sprintf("session %d:", i)), payload...)
			go func() { _, _ = s.Write(msg) }()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, msg) {
				t.Errorf("session %d: echo %d bytes, %v", i, len(got), err)
			}
			_ = s.Close()
		})
	}
	wg.Wait()

	// A refused open is a close: the opener reads io.EOF, its writes fail.
	s, err := client.Open(&pb.TCPData{AgentId: "nope", TargetAddr: "22"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // refused: link debug mode reports a session never closed
	if n, err := s.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("refused session read %d, %v; want io.EOF", n, err)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("write on a refused session succeeded")
	}
}

func TestMuxMaxSessions(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	var accepted atomic.Int64
	client := muxPair(t, func(_ *pb.TCPData, s *Session) {
		accepted.Add(1)
		<-hold
		_ = s.Close()
	})
	var first *Session
	for i := range MaxSessions {
		s, err := client.Open(&pb.TCPData{AgentId: "a"})
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if first == nil {
			first = s
		}
	}
	if _, err := client.Open(&pb.TCPData{AgentId: "a"}); !errors.Is(err, ErrFull) {
		t.Fatalf("session past MaxSessions: %v, want ErrFull", err)
	}
	_ = first.Close()
	s, err := client.Open(&pb.TCPData{AgentId: "a"})
	if err != nil {
		t.Fatalf("after one closed: %v", err)
	}
	_ = s.Close()
	// An open past the accepting side's limit ends the connection (link).
}

func TestUpgrade(t *testing.T) {
	serve := func(answer string) (net.Conn, chan *http.Request) {
		a, b := net.Pipe()
		reqs := make(chan *http.Request, 1)
		go func() {
			req, err := http.ReadRequest(bufio.NewReader(b))
			if err != nil {
				return
			}
			reqs <- req
			if answer == "" {
				m, err := Accept(context.Background(), b, 2*testWindow, "require")
				if err == nil {
					_ = m.Serve(echoAccept)
				}
				return
			}
			_, _ = io.WriteString(b, answer)
		}()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		return a, reqs
	}

	nc, reqs := serve("")
	m, hdr, err := Upgrade(context.Background(), nc, "relay:443", "key", testWindow)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Get(AnswerHeader) != "1" || hdr.Get(E2EEPolicyHeader) != "require" {
		t.Fatalf("101 header %v: want the answer and policy headers", hdr)
	}
	req := <-reqs
	if !IsUpgrade(req) || IsOldUpgrade(req) || req.URL.Path != UpgradePath || req.Header.Get("X-API-Key") != "key" ||
		agentwire.ParseGeneration(req.Header.Values(agentwire.GenerationKey)) != agentwire.Generation {
		t.Fatalf("upgrade request %s %s %v", req.Method, req.URL, req.Header)
	}
	if m.c.Credit().PeerWindow() != 2*testWindow || m.c.Credit().Window() != testWindow {
		t.Fatalf("windows %d/%d", m.c.Credit().Window(), m.c.Credit().PeerWindow())
	}
	go func() { _ = m.Serve(nil) }()
	s, err := m.Open(&pb.TCPData{AgentId: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	go func() { _, _ = s.Write([]byte("ping")) }()
	if got := make([]byte, 4); func() error { _, err := io.ReadFull(s, got); return err }() != nil || string(got) != "ping" {
		t.Fatalf("echo over the upgraded connection: %q", got)
	}
	// The data connection negotiates link.FeatureChain: opens are
	// answered link's own way, a refusal carries its reason.
	if !s.Answers() || s.Answered(context.Background()) != nil {
		t.Fatalf("session answers %v, answered %v: want an accepted FeatureChain session", s.Answers(), s.Answered(context.Background()))
	}
	bad, err := m.m.Open([]byte{0xff})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close() //nolint:errcheck
	var a *link.Abort
	if err := bad.Answered(context.Background()); !errors.As(err, &a) || !a.Refused {
		t.Fatalf("an open whose header is no TCPData: %v, want a refusal", err)
	} else if r, ok := AbortReason(a); !ok || r != relayv1.ErrorReason_ERROR_REASON_INVALID_ARGUMENT {
		t.Fatalf("refusal %v: reason %v, want INVALID_ARGUMENT", a, r)
	}

	nc, _ = serve("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	var nu *NoUpgradeError
	if _, _, err := Upgrade(context.Background(), nc, "relay:443", "key", testWindow); !errors.As(err, &nu) || nu.Status != 400 {
		t.Fatalf("a relay that answers 400: %v, want NoUpgradeError", err)
	}
	for _, w := range []string{"", "x", "1", "99999999999"} {
		if _, err := ParseWindow(w); err == nil {
			t.Fatalf("window %q accepted", w)
		}
	}
}

// TestMuxDrain: a drained data connection tells the opener to open
// elsewhere (link.ErrGoAway), runs an open session on until the drain's
// deadline, then aborts it link.CodeDrainDeadline; Drain returns
// context.DeadlineExceeded for the cut.
func TestMuxDrain(t *testing.T) {
	a, b := v2pair(t)
	client, server := NewMux(a), NewMux(b)
	go func() { _ = client.Serve(nil) }()
	go func() { _ = server.Serve(echoAccept) }()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	s, err := client.Open(&pb.TCPData{AgentId: "echo", TargetAddr: "22"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	echo := func(msg string) error {
		if _, err := s.Write([]byte(msg)); err != nil {
			return err
		}
		got := make([]byte, len(msg))
		_, err := io.ReadFull(s, got)
		return err
	}
	if err := echo("before"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- server.Drain(ctx) }()
	for start := time.Now(); ; time.Sleep(5 * time.Millisecond) {
		more, err := client.Open(&pb.TCPData{AgentId: "echo", TargetAddr: "22"})
		if err == nil {
			_ = more.Close()
		}
		if errors.Is(err, link.ErrGoAway) {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("open on a drained connection: %v, want link.ErrGoAway", err)
		}
	}
	if err := echo("while draining"); err != nil {
		t.Fatalf("an open session during the drain: %v", err)
	}
	if err := <-drained; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain: %v, want the deadline", err)
	}
	_, err = s.Read(make([]byte, 1))
	var ab *link.Abort
	if !errors.As(err, &ab) || ab.Code != link.CodeDrainDeadline {
		t.Fatalf("an open session at the drain's deadline: %v, want aborted drain deadline", err)
	}
}
