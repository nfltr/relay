// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// tcpSession is a loopback TCP connection as a peerlink.Session.
type tcpSession struct{ *net.TCPConn }

func (s tcpSession) Reset() error { _ = s.SetLinger(0); return s.Close() }

// sessionPair is the agent's and the opener's end of one session.
func sessionPair(t *testing.T) (tcpSession, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = a.Close() })
	return tcpSession{a.(*net.TCPConn)}, c.(*net.TCPConn)
}

// echoTarget is a TCP echo server that passes each end on as a half close.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().String()
}

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// An open that asks for an answer gets one before any byte: OK once the
// agent reached its target, else the typed reason (refused, unreachable,
// unknown service, E2EE required or unavailable), then the session's end.
// An E2EE tcp service is TLS with the agent's E2EE certificate, whose
// SHA-256 the client pins, and passes half closes through.
func TestLinkSessionAnswers(t *testing.T) {

	echo := echoTarget(t)
	tab, err := NewServiceTable([]Service{
		{Name: "db", Kind: agentservices.TCP, Target: echo},
		{Name: "down", Kind: agentservices.TCP, Target: closedAddr(t)},
		{Name: "void", Kind: agentservices.TCP, Target: "void.invalid:9"}, // RFC 2606: never resolves (a TEST-NET address is refused by some networks)
		{Name: "vault", Kind: agentservices.TCP, Target: echo, E2EE: agentservices.E2EEOn},
		{Name: "plain", Kind: agentservices.TCP, Target: echo, E2EE: agentservices.E2EEOff},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := generateSelfSignedCert("agent")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "agent")
	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{services: tab}, e2ee: e2ee, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	open := func(target string, e2eeOpen bool) *net.TCPConn {
		s, c := sessionPair(t)
		h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: e2eeOpen, Answer: true})
		if err != nil {
			t.Fatal(err)
		}
		go l.accept("", h, s)
		return c
	}
	refused := map[string]struct {
		e2ee bool
		want relayv1.ErrorReason
	}{
		"down":  {false, relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED},
		"void":  {false, relayv1.ErrorReason_ERROR_REASON_TARGET_UNREACHABLE},
		"nope":  {false, relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE},
		"vault": {false, relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED},
		"plain": {true, relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE},
	}
	for target, tc := range refused {
		c := open(target, tc.e2ee)
		a, err := dataplane.ReadAnswer(c)
		if err != nil || a.GetReason() != tc.want || a.GetMessage() == "" {
			t.Fatalf("%s: answer %v, %v; want %v", target, a, err, tc.want)
		}
		if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("%s: after a refusal read %d, %v; want a clean end", target, n, err)
		}
	}

	// Open, then half closes both ways: the target's answer still comes
	// after ours ended.
	c := open("db", false)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("db: answer %v, %v", a, err)
	}
	_, _ = c.Write([]byte("ping"))
	_ = c.CloseWrite()
	if got, err := io.ReadAll(c); err != nil || string(got) != "ping" {
		t.Fatalf("db: echo %q, %v", got, err)
	}

	// E2EE: the answer, then TLS whose certificate matches the pin.
	pin := sha256.Sum256(cert.Certificate[0])
	for _, target := range []string{"vault", "db"} { // On, and Default (either)
		c := open(target, true)
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("%s e2ee: answer %v, %v", target, a, err)
		}
		tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, //nolint:gosec // pinned below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if got := sha256.Sum256(raw[0]); !bytes.Equal(got[:], pin[:]) {
					return errors.New("pin mismatch")
				}
				return nil
			}})
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("%s e2ee: handshake: %v", target, err)
		}
		_, _ = tc.Write([]byte("secret"))
		_ = tc.CloseWrite()
		if got, err := io.ReadAll(tc); err != nil || string(got) != "secret" {
			t.Fatalf("%s e2ee: echo %q, %v", target, got, err)
		}
	}
}

// The frame streams answer as the agent link does: the answer is the
// session's first data frame; a refusal is followed by its close.
func TestFrameSessionAnswers(t *testing.T) {
	tab, err := NewServiceTable([]Service{
		{Name: "db", Kind: agentservices.TCP, Target: echoTarget(t)},
		{Name: "down", Kind: agentservices.TCP, Target: closedAddr(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 8, 8)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = serveTCPStream(ctx, st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), &tcpStreamGrowth{}, nil)
	}()
	next := func() *pb.TCPData {
		select {
		case f := <-st.out:
			return f
		case <-time.After(5 * time.Second):
			t.Fatal("no frame")
		}
		return nil
	}
	for id, want := range map[string]relayv1.ErrorReason{"down": relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, "nope": relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE} {
		st.in <- &pb.TCPData{SessionId: id, Open: true, TargetAddr: id, Answer: true}
		f := next()
		a, err := dataplane.ReadAnswer(bytes.NewReader(f.Data))
		if f.SessionId != id || err != nil || a.GetReason() != want {
			t.Fatalf("%s: first frame %+v (%v, %v), want answer %v", id, f, a, err, want)
		}
		if f := next(); f.SessionId != id || !f.Close {
			t.Fatalf("%s: then %+v, want the close", id, f)
		}
	}
	st.in <- &pb.TCPData{SessionId: "ok", Open: true, TargetAddr: "db", Answer: true}
	if a, err := dataplane.ReadAnswer(bytes.NewReader(next().Data)); err != nil || a.GetReason() != 0 {
		t.Fatalf("db: answer %v, %v", a, err)
	}
	st.in <- &pb.TCPData{SessionId: "ok", Data: []byte("ping")}
	if f := next(); string(f.Data) != "ping" {
		t.Fatalf("db: echo %+v", f)
	}
	// Without answer, the session starts with its bytes, as before.
	st.in <- &pb.TCPData{SessionId: "raw", Open: true, TargetAddr: "db"}
	st.in <- &pb.TCPData{SessionId: "raw", Data: []byte("pong")}
	if f := next(); string(f.Data) != "pong" {
		t.Fatalf("raw: first frame %+v, want the echo", f)
	}
}
