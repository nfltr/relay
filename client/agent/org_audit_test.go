// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// auditOrg is a fakeOrg that keeps an audit record (OrgAuditor).
type auditOrg struct {
	*fakeOrg
	opened chan string
	ended  chan orgaudit.End
}

func (a *auditOrg) Audit(certs []*x509.Certificate, service string, _ []string, _ time.Time) func(orgaudit.End) {
	a.opened <- certs[0].Subject.CommonName + "/" + service
	return func(e orgaudit.End) { a.ended <- e }
}

// TestOrgSessionAudited: a session the agent admits is audited at its
// open (the client certificate and the service), and at its end with the
// plaintext bytes each way and why it ended: either side's end, or a
// change that revokes the client.
func TestOrgSessionAudited(t *testing.T) {
	for _, revoke := range []bool{false, true} {
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
			defer c.Close() //nolint:errcheck
			_, _ = io.ReadFull(c, make([]byte, len("hello")))
			_, _ = io.WriteString(c, "world!")
			_, _ = io.Copy(io.Discard, c) // until the client's end, or the revoke's cut
		}()
		l, o, cli := orgTunnel(t, ln.Addr().String())
		a := &auditOrg{fakeOrg: l.targets.org.(*fakeOrg), opened: make(chan string, 1), ended: make(chan orgaudit.End, 1)}
		l.targets.org = a
		s, c := sessionPair(t)
		h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "localhost:1", E2Ee: true, Answer: true})
		if err != nil {
			t.Fatal(err)
		}
		go l.accept("", h, s)
		if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
			t.Fatalf("answer %v, %v", a, err)
		}
		tc := orgClient(c, o, cli, "localhost:1")
		if _, err := io.WriteString(tc, "hello"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(tc, make([]byte, len("world!"))); err != nil {
			t.Fatal(err)
		}
		if got := <-a.opened; got != "cli/localhost:1" {
			t.Fatalf("opened %q", got)
		}
		want := orgaudit.ReasonClosed
		if revoke {
			want = orgaudit.ReasonRevoked
			a.change(cli.Leaf)
		} else {
			_ = tc.CloseWrite()
		}
		select {
		case e := <-a.ended:
			if e.In != 5 || e.Out != 6 || e.Reason != want || e.Path != PathRelayed || e.Closed.IsZero() {
				t.Fatalf("revoke %v: the end %+v, want in 5 out 6 reason %s", revoke, e, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("revoke %v: no audit end", revoke)
		}
		_ = tc.Close()
	}
}
