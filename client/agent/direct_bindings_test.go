// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The bindings spec/proverif/e2ee_tcp.pv's direct path relies on (queries
// 21-29), against the real code: each BIND:direct.* the model lists has
// one row here that changes just what a relay can change of an honest
// attach (an address it answers, a token it replays or forges) and
// requires a refusal. `make spec-bindings`.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/quic-go"
)

const directBindModel = "../../spec/proverif/e2ee_tcp.pv"

// lyingQAD is a relay whose QAD answers addr, whoever asks.
func lyingQAD(t *testing.T, addr string) string {
	t.Helper()
	o := newTestOrg(t)
	cert := o.machine(t, "relay", nil, time.Hour, false)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{QADALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			q, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				if s, err := q.OpenUniStream(); err == nil {
					_, _ = io.WriteString(s, addr)
					_ = s.Close()
				}
				<-q.Context().Done()
			}()
		}
	}()
	return ln.Addr().String()
}

// rogueAnswer: the relay points the agent's candidate at another holder
// (cert its certificate), which answers the punch; the client must refuse
// it and stay relayed.
func rogueAnswer(t *testing.T, cert func(o *testOrg) tls.Certificate) {
	r := newDirectRig(t, DirectOn)
	o := r.client.o
	rogue, err := newDirectServer(o.agentOrg(cert(o)), []string{"db"}, map[string]DirectMode{"blob": DirectOn})
	if err != nil {
		t.Fatal(err)
	}
	rogue.ep.loopback = true
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = rogue.node.Drain(ctx)
		_ = rogue.ep.Close()
	})
	r.l.targets.services.direct.setRelay(lyingQAD(t, fmt.Sprintf("127.0.0.1:%d", rogue.ep.pc.LocalAddr().(*net.UDPAddr).Port)), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- a test's relay
	_, tc, events := r.session(t)
	if e := waitPath(t, events, PathRelayed); e.Reason != ReasonRefusedCert {
		t.Fatalf("reason %q, want %s", e.Reason, ReasonRefusedCert)
	}
	echo(t, tc, 64<<10, func() {})
}

// boundSession is a session registered at a direct server with key, and
// the honest OPEN of its epoch 2 on a direct connection whose exporter is
// qk.
func boundSession(t *testing.T) (*directServer, pathswitch.Open, []byte, []byte) {
	d := &directServer{sessions: map[*directSession]struct{}{}}
	key, qk := []byte("session exporter, 32 bytes long."), []byte("quic exporter, 32 bytes long....")
	c := pathswitch.Server(pathStream{Conn: nopConn{}}, PathRelayed, pathswitch.Config{Detach: 10 * time.Millisecond}) // its Abort ends it at once
	t.Cleanup(c.Abort)
	d.sessions[&directSession{c: c, key: key}] = struct{}{}
	o := pathswitch.Open{Epoch: 2, Token: pathToken(key, roleClient, 2, qk)}
	if d.find(o, qk) == nil {
		t.Fatal("the honest OPEN found no session")
	}
	return d, o, key, qk
}

func refusedOpen(t *testing.T, what string, d *directServer, o pathswitch.Open, qk []byte) {
	t.Helper()
	if d.find(o, qk) != nil {
		t.Fatalf("%s: the agent attached it", what)
	}
}

var directBindings = map[string]func(t *testing.T){
	// The answer's certificate is checked as the organisation's: a
	// self-signed look-alike named web is refused.
	"direct.cert": func(t *testing.T) {
		rogueAnswer(t, func(o *testOrg) tls.Certificate { return o.machine(t, "web", nil, time.Hour, true) })
	},
	// ... and names the machine the session asked for: eve, enrolled, is
	// refused at web's address.
	"direct.name": func(t *testing.T) {
		rogueAnswer(t, func(o *testOrg) tls.Certificate { return o.machine(t, "eve", nil, time.Hour, false) })
	},
	// The token is keyed by the session's exporter: another session's
	// (the relay's own) attaches nothing.
	"direct.token": func(t *testing.T) {
		d, o, _, qk := boundSession(t)
		o.Token = pathToken([]byte("another session's exporter......"), roleClient, o.Epoch, qk)
		refusedOpen(t, "a token of another session", d, o, qk)
	},
	// ... bound to the direct connection: the token of another one (a
	// relay in the middle with two QUIC sessions) attaches nothing.
	"direct.quic": func(t *testing.T) {
		d, o, key, qk := boundSession(t)
		o.Token = pathToken(key, roleClient, o.Epoch, []byte("the relay's own quic exporter..."))
		refusedOpen(t, "a token of another direct connection", d, o, qk)
		o.Token = pathToken(key, roleClient, o.Epoch, nil)
		refusedOpen(t, "a relayed stream's token on a direct connection", d, o, qk)
	},
	// ... and to the sender's role: the agent's token reflected as the
	// client's attaches nothing, and the client takes no reflected token
	// of its own as the agent's.
	"direct.role": func(t *testing.T) {
		d, o, key, qk := boundSession(t)
		o.Token = pathToken(key, roleServer, o.Epoch, qk)
		refusedOpen(t, "the agent's token as the client's", d, o, qk)
		a, b := tcpPair(t)
		var took bool
		tc := &tokenCheck{pathStream: pathStream{Conn: a}, ready: make(chan struct{}), want: pathToken(key, roleServer, 2, qk), ok: func() { took = true }, bad: func() {}}
		close(tc.ready)
		go func() { _, _ = b.Write(pathToken(key, roleClient, 2, qk)); _ = b.Close() }()
		if _, err := tc.Read(make([]byte, 1)); took || !errors.Is(err, errDirectRefused) {
			t.Fatalf("the client took its own token reflected as the agent's (%v)", err)
		}
	},
	// ... and to the attach's epoch: a replayed OPEN under a newer epoch
	// attaches nothing (e2ee_tcp.pv 27).
	"direct.epoch": func(t *testing.T) {
		d, o, _, qk := boundSession(t)
		o.Epoch = 3
		refusedOpen(t, "epoch 2's token under epoch 3", d, o, qk)
	},
}

// TestDirectModelBindings runs every row, and fails when the model's
// BIND:direct ids and the rows differ.
func TestDirectModelBindings(t *testing.T) {
	src, err := os.ReadFile(directBindModel)
	if err != nil {
		t.Fatal(err)
	}
	var model []string
	for _, m := range regexp.MustCompile(`BIND:(direct\.[a-z0-9.]+)`).FindAllSubmatch(src, -1) {
		if id := string(m[1]); !slices.Contains(model, id) {
			model = append(model, id)
		}
	}
	var rows []string
	for id := range directBindings {
		rows = append(rows, id)
	}
	slices.Sort(model)
	slices.Sort(rows)
	if !slices.Equal(model, rows) {
		t.Fatalf("%s BIND ids %v, rows %v: each binding of the model needs one row", directBindModel, model, rows)
	}
	for _, id := range rows {
		t.Run(id, directBindings[id])
	}
}

// nopConn is a stream that carries nothing (a registered session's first
// stream, for the token rows).
type nopConn struct{ net.Conn }

func (nopConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error) { return len(p), nil }
func (nopConn) Close() error                { return nil }
