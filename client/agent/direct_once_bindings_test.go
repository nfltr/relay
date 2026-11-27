// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The bindings spec/proverif/direct_once.pv adds (BIND:once.*: an nf1
// session's path layer over per-epoch channels, each byte sealed once on a
// direct path; nfltr docs/decisions/direct-once-2026-11-22.md), against
// the real code on direct_nf1_test.go's rig: each row changes one field
// of an honest message, as a relay that owns the path can, and requires a
// refusal. `make spec-bindings`.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
)

const directOnceModel = "../../spec/proverif/direct_once.pv"

// openMark is a relayed session to the rig's address with mark as its
// first byte after the answer (checked): the relay's own stream.
func (r *nf1Rig) openMark(t *testing.T, mark byte) net.Conn {
	t.Helper()
	raw, err := r.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nf1.ReadAnswer(raw, r.lis.Address()); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write([]byte{mark}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

// relayReattach is a re-attach the relay runs itself (it holds no
// session key but every public value): its own TLS to the address's
// listener, then an OPEN of epoch 2 carrying tok(x) (x: its handshake's
// exporter). It returns the stream after the OPEN.
func (r *nf1Rig) relayReattach(t *testing.T, tok func(x []byte) []byte) *tlsend.Conn {
	t.Helper()
	tc := tlsend.Client(r.openMark(t, nf1MarkAttach), nf1ReattachClientTLS(r.lis.Address()))
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	x, err := reattachKey(tc.ConnectionState())
	if err != nil {
		t.Fatal(err)
	}
	writeOpen(t, tc, tok(x))
	return tc
}

// writeOpen writes an OPEN of epoch 2 carrying token on s (link
// pathswitch WIRE.md: O epoch rcvd flags toklen token).
func writeOpen(t *testing.T, s io.Writer, token []byte) {
	t.Helper()
	b := binary.AppendUvarint(binary.AppendUvarint([]byte{'O'}, 2), 0)
	b = append(binary.AppendUvarint(append(b, 0), uint64(len(token))), token...)
	if _, err := s.Write(b); err != nil {
		t.Fatal(err)
	}
}

// refusedAttach requires s to be refused within 5 s: ended (an ABORT, a
// reset, an end) with fewer bytes than the agent's token, never attached.
func refusedAttach(t *testing.T, what string, s net.Conn) {
	t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(io.LimitReader(s, 64))
	if errors.Is(err, os.ErrDeadlineExceeded) || len(b) >= directKeyLen {
		t.Fatalf("%s: the agent answered %d bytes (%v) and kept the stream, want a refusal", what, len(b), err)
	}
}

// agentToken requires s to start with the agent's token for epoch 2 over
// x: the row's honest case, so that its refusal is the field's.
func agentToken(t *testing.T, s io.Reader, key, x []byte) {
	t.Helper()
	got := make([]byte, directKeyLen)
	if _, err := io.ReadFull(s, got); err != nil || string(got) != string(pathToken(key, roleServer, 2, x)) {
		t.Fatalf("the honest re-attach got %x, %v: want the agent's token", got, err)
	}
}

// onceRig is a framed nf1 session that stays relayed (the agent's direct
// socket closed: no punch answers), its token key and events.
func onceRig(t *testing.T) (*nf1Rig, *DirectSession, *nf1Conn, []byte, chan PathEvent) {
	t.Helper()
	r := relayedNF1Rig(t)
	ds, tc := r.handshake(t)
	key, err := sessionKey(tc.ConnectionState())
	if err != nil {
		t.Fatal(err)
	}
	events := r.run(t, ds, tc)
	waitPath(t, events, PathRelayed) // the punch's failure: no punch outlives the row
	return r, ds, tc, key, events
}

// relayedNF1Rig is newNF1Rig whose punches find no answer within 200 ms.
func relayedNF1Rig(t *testing.T) *nf1Rig {
	t.Helper()
	r := newNF1Rig(t, DirectOn)
	_ = r.l.targets.services.direct.ep.Close()
	r.d.punchBound = 200 * time.Millisecond
	return r
}

var directOnceBindings = map[string]func(t *testing.T){
	// The OPEN of a re-attach is taken only with the token over the
	// channel it came on: the honest client's token for another channel
	// (the relay replays it on its own re-attach) attaches nothing; the
	// token over the relay's own channel would (the session key is the
	// secret the relay lacks; here the test holds it).
	"once.channel": func(t *testing.T) {
		r, ds, tc, key, _ := onceRig(t)
		other := r.relayReattach(t, func([]byte) []byte { return pathToken(key, roleClient, 2, []byte("another channel's exporter......")) })
		refusedAttach(t, "a token over another channel", other)
		echo(t, tc, 64<<10, func() {})
		var x []byte
		own := r.relayReattach(t, func(e []byte) []byte { x = e; return pathToken(key, roleClient, 2, e) })
		agentToken(t, own, key, x)
		ds.c.Abort()
	},
	// Every frame of a relayed epoch is inside its channel's AEAD: a relay
	// that changes one byte of the session's stream (a frame's offset or
	// bytes) cuts that epoch (a TLS error), which the session resumes on a
	// re-attach; no changed byte is taken.
	"once.offset": func(t *testing.T) {
		r := relayedNF1Rig(t)
		raw, err := r.open(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nf1.ReadAnswer(raw, r.lis.Address()); err != nil {
			t.Fatal(err)
		}
		flip := &flipConn{Conn: raw, at: 40 << 10}
		w, bind := tlsend.Wrap(flip)
		ttc, err := nf1.ClientTLSFramed(t.Context(), w, r.lis.Address())
		if err != nil {
			t.Fatal(err)
		}
		ds := r.d.StartNF1(raw, bind(ttc))
		tc := &nf1Conn{psConn: ds.nc, tls: ds.first.Conn.(*tlsend.Conn)}
		t.Cleanup(func() { _ = tc.Close() })
		events := r.run(t, ds, tc)
		waitPath(t, events, PathRelayed) // the punch's failure, before the flip
		echo(t, tc, 256<<10, func() {})
		if !flip.flipped.Load() {
			t.Fatal("no byte changed")
		}
		for e := waitPath(t, events, PathRelayed); e.Reason != ReasonRelayLost; e = waitPath(t, events, PathRelayed) {
		}
	},
	// A relayed re-attach is a fresh TLS handshake to the pinned key: one
	// answered under another key (the relay routes it to another holder,
	// the honest answer replayed) is refused by the client; and the agent
	// takes no token over the session's own TLS (its key continued).
	"once.reattach": func(t *testing.T) {
		r, ds, tc, key, _ := onceRig(t)
		other, _, err := nf1.Mint("relay.example")
		if err != nil {
			t.Fatal(err)
		}
		a, b := tcpPair(t)
		go func() {
			_ = honestAnswer(t, r).WriteAnswer(b)
			_, _ = io.ReadFull(b, make([]byte, 1))
			_ = tls.Server(b, nf1ReattachTLS(other)).Handshake()
			_ = b.Close()
		}()
		p := &directPair{nf1: &NF1Route{Addr: r.lis.Address(), Open: func(context.Context) (net.Conn, error) { return a, nil }}}
		if _, _, err := r.d.nf1Reattach(t.Context(), p, key, new(atomic.Bool)); !errors.Is(err, capaddr.ErrPin) {
			t.Fatalf("a re-attach under another key: %v, want %v", err, capaddr.ErrPin)
		}
		x0, err := reattachKey(tc.ConnectionState())
		if err != nil {
			t.Fatal(err)
		}
		cont := r.relayReattach(t, func([]byte) []byte { return pathToken(key, roleClient, 2, x0) })
		refusedAttach(t, "a token over the session's own TLS", cont)
		echo(t, tc, 64<<10, func() {})
		ds.c.Abort()
	},
	// No channel is dropped on a word from the path: the agent refuses a
	// session framed outside its TLS (a path frame after the answer) and
	// a re-attach without its TLS (a plain OPEN after the mark, the
	// honest relayed token), and the client's re-attach starts its TLS
	// whatever the stream answers.
	"once.plain": func(t *testing.T) {
		r, _, tc, key, _ := onceRig(t)
		framed := r.openMark(t, 'D') // a DATA frame's first byte (WIRE.md)
		refusedAttach(t, "a session framed outside its TLS", framed)
		plain := r.openMark(t, nf1MarkAttach)
		writeOpen(t, plain, pathToken(key, roleClient, 2, nil))
		refusedAttach(t, "a re-attach without its TLS", plain)
		echo(t, tc, 64<<10, func() {})
		a, b := tcpPair(t)
		sent := make(chan []byte, 1)
		go func() {
			_ = honestAnswer(t, r).WriteAnswer(b)
			buf := make([]byte, 2)
			_, _ = io.ReadFull(b, buf)
			sent <- buf
			_, _ = b.Write([]byte{'R', 0, 0, 0}) // a RESUME's look, no TLS
			_ = b.Close()
		}()
		p := &directPair{nf1: &NF1Route{Addr: r.lis.Address(), Open: func(context.Context) (net.Conn, error) { return a, nil }}}
		if _, _, err := r.d.nf1Reattach(t.Context(), p, key, new(atomic.Bool)); err == nil {
			t.Fatal("the client re-attached on a stream that ran no TLS")
		}
		if b := <-sent; b[0] != nf1MarkAttach || b[1] != tlsRecordHandshake {
			t.Fatalf("the client's re-attach began %x, want the mark and a ClientHello", b)
		}
	},
}

// honestAnswer is the rig's listener as its agent answers (WithDirect):
// a relay replays that answer.
func honestAnswer(t *testing.T, r *nf1Rig) *nf1.Listener {
	l, err := r.lis.WithDirect()
	if err != nil {
		t.Error(err)
	}
	return l
}

// flipConn changes one byte of what is written at offset at: a relay's
// edit of the session's stream.
type flipConn struct {
	net.Conn
	n, at   int
	flipped atomic.Bool
}

func (c *flipConn) Write(p []byte) (int, error) {
	if c.n <= c.at && c.at < c.n+len(p) && !c.flipped.Load() {
		q := slices.Clone(p)
		q[c.at-c.n] ^= 0x40
		c.flipped.Store(true)
		p = q
	}
	c.n += len(p)
	return c.Conn.Write(p)
}

// TestDirectOnceModelBindings runs every row, and fails when the model's
// BIND:once ids and the rows differ.
func TestDirectOnceModelBindings(t *testing.T) {
	src, err := os.ReadFile(directOnceModel)
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(directOnceBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(once\.[a-z0-9.]+)`), rows); err != nil {
		t.Fatalf("%s: %v", directOnceModel, err)
	}
	for _, id := range rows {
		t.Run(id, directOnceBindings[id])
	}
}
