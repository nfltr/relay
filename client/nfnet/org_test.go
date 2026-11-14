// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
)

// orgServer serves an echo over the agent's TLS of organisation mode (allow
// group db, negotiating protos) on a pipe; the client end is returned with
// a done channel closed at the test's end.
func orgServer(t *testing.T, srv *orgid.Identity, protos ...string) (net.Conn, chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	ended := make(chan struct{})
	t.Cleanup(func() { _ = a.Close(); _ = b.Close(); close(done); <-ended })
	s := tls.Server(a, serverTLS(srv, protos...))
	go func() { defer close(ended); _ = s.Handshake(); _, _ = io.Copy(s, s) }()
	return b, done
}

// orgClient is a Conn of org's TLS client to target on raw.
func orgClient(raw net.Conn, target string, org *orgid.Identity, done <-chan struct{}) *Conn {
	t, err := ParseTarget(target)
	if err != nil {
		panic(err)
	}
	c := &Conn{target: t}
	c.useOrgTLS(raw, t, org, done)
	return c
}

func echo(c *Conn) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, 1))
	return err
}

// The client of organisation mode reaches only the machine it names, and
// its session ends when a newer CRL revokes that machine (relay
// spec/proverif/e2ee_tcp.pv query 1; Enrol.tla RevocationBound, mutant
// client-no-cut-on-update).
func TestOrgClientNamesMachineAndCutsOnRevoke(t *testing.T) {
	o := newTestOrg(t)
	web, eve, cli := o.machine(t, "web", "web"), o.machine(t, "eve", "web"), o.machine(t, "cli", "db")
	raw, done := orgServer(t, eve, agent.MachineALPN("web", "pg"))
	if err := echo(orgClient(raw, "web/pg", cli, done)); err == nil {
		t.Error("the client took eve for web")
	}
	raw, done = orgServer(t, web, agent.MachineALPN("web", "pg"))
	c := orgClient(raw, "web/pg", cli, done)
	if err := echo(c); err != nil {
		t.Fatalf("cli to web: %v", err)
	}
	// Another relay machine's agent (<machine>.<agent>): the machine part
	// is checked.
	raw, done = orgServer(t, eve, agent.MachineALPN("access", "pg"))
	if err := echo(orgClient(raw, "web.access/pg", cli, done)); err == nil {
		t.Error("the client took eve for web.access")
	}
	raw, done = orgServer(t, web, agent.MachineALPN("access", "pg"))
	if err := echo(orgClient(raw, "web.access/pg", cli, done)); err != nil {
		t.Errorf("cli to web.access: %v", err)
	}
	o.revoke("web")
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the session to a revoked web went on: %v", err)
	}
}

// orgPair is a client Conn of machine cli to machine web's pg over TCP and
// web's server end (allow group db), with the raw server connection.
func orgPair(t *testing.T) (*Conn, *tls.Conn, net.Conn) {
	t.Helper()
	o := newTestOrg(t)
	web, cli := o.machine(t, "web", "web"), o.machine(t, "cli", "db")
	c, s := tcpPair(t)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	return orgClient(c, "web/pg", cli, done), tls.Server(s, serverTLS(web, agent.MachineALPN("web", "pg"))), s
}

// A session the relay cuts between two TLS records (the session ends, no
// close_notify from the agent) reads as a reset, never as the agent's
// clean end; the agent's close_notify is a clean end (relay
// spec/proverif/e2ee_tcp.pv query 11, mutant clear-end).
func TestOrgSessionCutIsReset(t *testing.T) {
	for _, cut := range []bool{false, true} {
		c, srv, raw := orgPair(t)
		go func() {
			if srv.Handshake() == nil {
				_, _ = srv.Write([]byte("hello"))
				if cut {
					_ = raw.Close() // the relay's cut: no close_notify
				} else {
					_ = srv.CloseWrite()
				}
			}
		}()
		if err := c.handshake(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(c)
		if string(got) != "hello" || (err != nil) != cut || (cut && CodeOf(err) != CodeReset) {
			t.Errorf("cut %v: read %q, %v; want hello and a reset %v", cut, got, err, cut)
		}
		_ = c.Close()
	}
}

// Reset resets the session: the agent reads a reset, never the client's
// close_notify; Close is the agent's clean end (relay
// spec/proverif/e2ee_tcp.pv query 14, mutant client-abort-as-close).
func TestOrgSessionLocalResetIsResetAtAgent(t *testing.T) {
	for _, reset := range []bool{false, true} {
		c, srv, raw := orgPair(t)
		ended := make(chan error, 1)
		go func() {
			_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := io.ReadAll(srv)
			ended <- err
		}()
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if reset {
			_ = c.Reset()
		} else {
			_ = c.Close()
		}
		if err := <-ended; errors.Is(err, os.ErrDeadlineExceeded) || (err != nil) != reset {
			t.Errorf("reset %v: the agent's read ended with %v, want a reset %v", reset, err, reset)
		}
	}
}

// tcpPair is both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
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
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s
}

func TestOrgServerName(t *testing.T) {
	for target, want := range map[string]string{
		"web-1/pg":         "web-1",
		"ops-vm.access/pg": "ops-vm",
		"m-abc-access/pg":  "m-abc-access",
	} {
		tg, err := ParseTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		if got := orgServerName(tg); got != want {
			t.Errorf("orgServerName(%q) = %q, want %q", target, got, want)
		}
	}
}

type resetConn struct {
	net.Conn
	reset, closed bool
}

func (c *resetConn) Reset() error { c.reset = true; return nil }
func (c *resetConn) Close() error { c.closed = true; return nil }

// TestCutRawResetsADirectSession: an admission's end resets a session
// whose conn has a Reset (a direct-path session: its Close is a clean end
// that waits for a revoked peer), and closes any other.
func TestCutRawResetsADirectSession(t *testing.T) {
	c := &resetConn{}
	cutRaw(c)
	if !c.reset || c.closed {
		t.Fatalf("reset %v, closed %v: want the reset only", c.reset, c.closed)
	}
	a, b := net.Pipe()
	defer b.Close() //nolint:errcheck
	cutRaw(a)
	if _, err := a.Write([]byte{1}); err == nil {
		t.Fatal("a conn without Reset is not closed")
	}
}

// A group dial opens again on a refusal of the end-to-end check (7),
// excluding each refused certificate's machine; any other answer (10 among
// them) ends it at once; ctx's end answers the instances tried (nfltr
// docs/decisions/service-discovery-2026-11-12.md sections 3, 6).
func TestRetryGroup(t *testing.T) {
	group := Target{Kind: GroupTarget, Service: "pg", Group: "db"}
	refused := func(peer string) error {
		return &Error{Code: CodeE2EEPinMismatch, Message: "end-to-end TLS with the agent failed", peer: peer}
	}
	t.Run("excludes refused machines", func(t *testing.T) {
		var seen [][]string
		answers := []error{refused("mal"), refused("eve"), nil}
		err := retryGroup(t.Context(), group, func(ex []string) error {
			seen = append(seen, slices.Clone(ex))
			return answers[len(seen)-1]
		})
		if err != nil || len(seen) != 3 || len(seen[0]) != 0 || !slices.Equal(seen[1], []string{"mal"}) || !slices.Equal(seen[2], []string{"mal", "eve"}) {
			t.Fatalf("err %v, excludes %q; want nil after [] [mal] [mal eve]", err, seen)
		}
	})
	t.Run("client refused is not retried", func(t *testing.T) {
		n := 0
		err := retryGroup(t.Context(), group, func([]string) error {
			n++
			if n == 1 {
				return refused("mal")
			}
			return &Error{Code: CodeE2EEClientRefused, Message: "refused this machine"}
		})
		e, _ := errors.AsType[*Error](err)
		if n != 2 || e == nil || e.Code != CodeE2EEClientRefused || !strings.Contains(e.Message, "1 refused before it: mal") {
			t.Fatalf("%d opens, %v", n, err)
		}
	})
	t.Run("none left but the refused", func(t *testing.T) {
		n := 0
		err := retryGroup(t.Context(), group, func([]string) error {
			n++
			if n == 1 {
				return refused("mal")
			}
			return &Error{Code: CodeNotFound, Reason: "ERROR_REASON_AGENT_OFFLINE", Message: "offline"}
		})
		e, _ := errors.AsType[*Error](err)
		if n != 2 || e == nil || e.Code != CodeE2EEPinMismatch || !strings.Contains(e.Message, "1 instance(s) tried: mal (") {
			t.Fatalf("%d opens, %v", n, err)
		}
	})
	t.Run("machine dial is one open", func(t *testing.T) {
		n := 0
		_ = retryGroup(t.Context(), Target{Kind: MachineTarget, Machine: "web", Agent: "db", Service: "pg"}, func([]string) error { n++; return refused("eve") })
		if n != 1 {
			t.Fatalf("%d opens of a machine dial", n)
		}
	})
	t.Run("timeout names the instances tried", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
		defer cancel()
		var excludes []int
		err := retryGroup(ctx, group, func(ex []string) error {
			excludes = append(excludes, len(ex))
			return refused("") // no certificate seen: nothing to exclude, so spaced
		})
		e, _ := errors.AsType[*Error](err)
		if e == nil || e.Code != CodeE2EEPinMismatch || !strings.Contains(e.Message, "not a machine of group db serving pg") ||
			len(excludes) > 4 || slices.Max(excludes) != 0 {
			t.Fatalf("%d opens (excludes %v): %v", len(excludes), excludes, err)
		}
	})
}

// TestGroupDialThroughTheRelay: a group dial's open names <service>@<group>
// and the service; the session reaches a machine of the group.
func TestGroupDialThroughTheRelay(t *testing.T) {
	r := newDataRelay(t, true)
	cfg := r.config(true)
	cfg.Org = r.org.cli
	_, err := dial(t, dialer(t, cfg), Target{Kind: GroupTarget, Service: "pg", Group: "db"}, DialOptions{})
	// The stand-in serves machine web (group web), not of db: refused, with
	// web named and excluded.
	e := wantCode(t, "pg@db served by web", err, CodeE2EEPinMismatch, "")
	if !strings.Contains(e.Message, "web") {
		t.Fatalf("%q, want web named", e.Message)
	}
	first := <-r.opens
	if first.GetAgentId() != "pg@db" || first.GetTargetAddr() != "pg" || !first.GetE2Ee() {
		t.Fatalf("open %v", first)
	}
	if second := <-r.opens; !slices.Equal(second.GetExclude(), []string{"web"}) {
		t.Fatalf("second open %v, want web excluded", second)
	}
}
