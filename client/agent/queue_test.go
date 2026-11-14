// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"golang.org/x/net/nettest"
)

// A QueueConn pair is a correct net.Conn both ways: deadlines (write
// deadlines included: a writer past queuePipeWindow unread bytes waits),
// concurrent Close, Read after Close.
func TestQueueConnIsANetConn(t *testing.T) {
	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		user, agentEnd := newQueuePipe()
		return user, agentEnd, func() { _ = user.Close(); _ = agentEnd.Close() }, nil
	})
}

// queueSessions serves a table with one queued tcp service, svc, on the
// agent link.
func queueSessions(t *testing.T, q *SessionQueue, s Service) *linkSessions {
	t.Helper()
	s.Name, s.Kind, s.Queue = "svc", agentservices.TCP, q
	tab, err := NewServiceTable([]Service{s})
	if err != nil {
		t.Fatal(err)
	}
	return &linkSessions{ctx: t.Context(), targets: sessionTargets{services: tab, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
}

// openQueued opens a plain session to svc on l (in-band answers), as
// caller machine m.
func openQueued(t *testing.T, l *linkSessions, m string) *net.TCPConn {
	t.Helper()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "svc", Answer: true, Caller: &pb.CallerIdentity{MachineId: m, MachineName: m}})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	return c
}

// unanswered fails unless c has no byte (no answer) for a while.
func unanswered(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%s: read %d, %v before Accept; want no answer", what, n, err)
	}
	_ = c.SetReadDeadline(time.Time{})
}

func wantRefused(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	a, err := dataplane.ReadAnswer(c)
	if err != nil || a.GetReason() != relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED {
		t.Fatalf("%s: answer %v, %v; want TARGET_REFUSED", what, a, err)
	}
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("%s: after the refusal read %d, %v; want its end", what, n, err)
	}
}

// Accept answers the open: a queued session's client reads no answer
// until Accept took it, then OK, then the bytes of the conn Accept
// returned (with the caller the relay named); a session never accepted is
// refused at Close, never opened and then reset. Mutant answer-at-enqueue
// (testdata/queue_mutants.txt).
func TestQueueAnswersAtAccept(t *testing.T) {
	q := NewSessionQueue(4)
	l := queueSessions(t, q, Service{})
	c := openQueued(t, l, "m1")
	unanswered(t, c, "queued")
	got, err := q.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close() //nolint:errcheck
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("accepted: answer %v, %v; want OK", a, err)
	}
	if cl, ok := got.(*QueueConn).Caller(); !ok || cl.Machine != "m1" {
		t.Fatalf("caller %+v, %v", cl, ok)
	}
	_, _ = c.Write([]byte("ping"))
	_ = c.CloseWrite()
	if b, err := io.ReadAll(got); err != nil || string(b) != "ping" {
		t.Fatalf("accepted read %q, %v", b, err)
	}
	_, _ = got.Write([]byte("pong"))
	_ = got.(*QueueConn).CloseWrite()
	if b, err := io.ReadAll(c); err != nil || string(b) != "pong" {
		t.Fatalf("client read %q, %v", b, err)
	}

	never := openQueued(t, l, "m2")
	unanswered(t, never, "never accepted")
	_ = q.Close()
	wantRefused(t, never, "never accepted, at Close")
	wantRefused(t, openQueued(t, l, "m3"), "after Close")
	if _, err := q.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
}

// A session beyond the backlog is refused at once (client exit 4); the
// ones within it wait, unanswered, and are served in order.
func TestQueueBacklogRefuses(t *testing.T) {
	q := NewSessionQueue(2)
	l := queueSessions(t, q, Service{})
	var waiting []*net.TCPConn
	for i := range 2 {
		waiting = append(waiting, openQueued(t, l, "m"))
		waitUntilQueued(t, q, i+1)
	}
	wantRefused(t, openQueued(t, l, "m"), "beyond the backlog")
	for i, c := range waiting {
		unanswered(t, c, "within the backlog")
		got, err := q.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("%d: answer %v, %v", i, a, err)
		}
		_ = got.Close()
	}
}

func waitUntilQueued(t *testing.T, q *SessionQueue, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		q.mu.Lock()
		k := len(q.pending)
		q.mu.Unlock()
		if k == n {
			return
		}
	}
	t.Fatalf("queue never held %d sessions", n)
}

// The frame streams (ConnectTCP, data connections) queue the same way:
// no answer frame until Accept; a client's reset is the accepted conn's
// link.ErrReset, never io.EOF.
func TestQueueFrameSessions(t *testing.T) {
	q := NewSessionQueue(0)
	tab, err := NewServiceTable([]Service{{Name: "svc", Kind: agentservices.TCP, Queue: q}})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 8, 8)
	go func() {
		_ = serveTCPStream(t.Context(), st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), &tcpStreamGrowth{}, nil)
	}()
	st.in <- &pb.TCPData{SessionId: "s1", Open: true, TargetAddr: "svc", Answer: true}
	select {
	case f := <-st.out:
		t.Fatalf("before Accept: frame %+v", f)
	case <-time.After(200 * time.Millisecond):
	}
	got, err := q.Accept()
	if err != nil {
		t.Fatal(err)
	}
	f := <-st.out
	if a, err := dataplane.ReadAnswer(bytes.NewReader(f.Data)); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer frame %+v: %v, %v", f, a, err)
	}
	st.in <- &pb.TCPData{SessionId: "s1", Data: []byte("hi")}
	b := make([]byte, 2)
	if _, err := io.ReadFull(got, b); err != nil || string(b) != "hi" {
		t.Fatalf("read %q, %v", b, err)
	}
	st.in <- &pb.TCPData{SessionId: "s1", Close: true, Abort: true}
	if _, err := got.Read(b); !errors.Is(err, link.ErrReset) {
		t.Fatalf("after the client's reset: %v; want link.ErrReset", err)
	}
}

// Organisation mode on a queue: the accepted conn carries the TLS's
// plaintext; a revocation of the client cuts it (link.ErrReset, never
// io.EOF), as it cuts a target's connection.
func TestQueueOrgRevocationCutsAccepted(t *testing.T) {
	o := newTestOrg(t)
	cli := o.machine(t, "cli", []string{"db"}, time.Hour, false)
	org := o.agentOrg(o.machine(t, "web", nil, time.Hour, false))
	q := NewSessionQueue(0)
	l := queueSessions(t, q, Service{E2EE: agentservices.E2EEOn, Org: org, AllowGroups: []string{"db"}})
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := q.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		b := make([]byte, 5) // the first echo (orgSessionTo's ping)
		if _, err := io.ReadFull(c, b); err == nil {
			_, _ = c.Write(b)
		}
		accepted <- c
	}()
	if _, err := orgSessionTo(t, l, "svc", o.pool, &cli); err != nil {
		t.Fatal(err)
	}
	got := <-accepted
	org.change(cli.Leaf)
	_ = got.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := got.Read(make([]byte, 1)); !errors.Is(err, link.ErrReset) {
		t.Fatalf("after the revocation: %v; want link.ErrReset", err)
	}
}

// A client that closes its session whole (no half close first) ends the
// accepted conn's reads cleanly after the client's last bytes, as a TCP
// target's FIN would: never a reset that drops them. A failure before the
// session was used resets it (dropTarget). Mutant close-is-reset
// (testdata/queue_mutants.txt).
func TestQueueClientCloseKeepsTheTail(t *testing.T) {
	q := NewSessionQueue(0)
	tab, err := NewServiceTable([]Service{{Name: "svc", Kind: agentservices.TCP, Queue: q}})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 8, 8)
	go func() {
		_ = serveTCPStream(t.Context(), st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), &tcpStreamGrowth{}, nil)
	}()
	st.in <- &pb.TCPData{SessionId: "s1", Open: true, TargetAddr: "svc", Answer: true}
	got, err := q.Accept()
	if err != nil {
		t.Fatal(err)
	}
	<-st.out // the answer
	st.in <- &pb.TCPData{SessionId: "s1", Data: []byte("tail")}
	st.in <- &pb.TCPData{SessionId: "s1", Close: true}
	if b, err := io.ReadAll(got); err != nil || string(b) != "tail" {
		t.Fatalf("after the client's close: read %q, %v; want the tail, then io.EOF", b, err)
	}

	user, agentEnd := newQueuePipe()
	dropTarget(agentEnd)
	if _, err := user.Read(make([]byte, 1)); !errors.Is(err, link.ErrReset) {
		t.Fatalf("dropped: %v; want link.ErrReset", err)
	}
}

// enter gives up with its tunnel: a pending session leaves the queue.
func TestQueueEnterEndsWithItsTunnel(t *testing.T) {
	q := NewSessionQueue(1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, _, err := q.enter(ctx, nil); done <- err }()
	waitUntilQueued(t, q, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("enter: %v", err)
	}
	waitUntilQueued(t, q, 0)
}

// A tcp service has a target or a queue, never both or neither; an http
// service takes no queue.
func TestQueueServiceValidation(t *testing.T) {
	q := NewSessionQueue(0)
	for name, s := range map[string]Service{
		"both":    {Name: "a", Kind: agentservices.TCP, Target: "127.0.0.1:1", Queue: q},
		"neither": {Name: "a", Kind: agentservices.TCP},
		"http":    {Name: "a", Kind: agentservices.HTTP, Target: "http://127.0.0.1:1", Queue: q},
	} {
		if _, err := NewServiceTable([]Service{s}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
