// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// idConn is an authenticated connection with ConnID id whose Close is seen.
func idConn(t *testing.T, id string) (*encryptedConn, net.Conn) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() }) //nolint:errcheck
	return &encryptedConn{Conn: a, id: id}, b
}

func closed(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Second)) // open: times out
	_, err := c.Read(make([]byte, 1))
	return errors.Is(err, io.EOF)
}

// Two peers whose own picks differ (this side saw "b" > "a") end up on the
// connection the dialing side announced.
func TestPickKeepsAnnouncedConnOverOwnPick(t *testing.T) {
	a, aPeer := idConn(t, "a")
	b, bPeer := idConn(t, "b")
	results := make(chan net.Conn)
	announced := make(chan string)
	got := make(chan net.Conn, 1)
	go func() {
		c, err := pick(results, func() (string, error) { return <-announced, nil })
		if err != nil {
			t.Error(err)
		}
		got <- c
	}()
	results <- a // both authenticated here before the announcement
	results <- b
	announced <- "a"
	if c := <-got; ConnID(c) != "a" {
		t.Fatalf("kept %q, want the announced %q", ConnID(c), "a")
	}
	if !closed(bPeer) {
		t.Fatal("the other connection is still open")
	}
	if closed(aPeer) {
		t.Fatal("the kept connection is closed")
	}
}

// The announced connection may authenticate here after others.
func TestPickWaitsForAnnouncedConn(t *testing.T) {
	a, _ := idConn(t, "a")
	z, _ := idConn(t, "z")
	results := make(chan net.Conn)
	go func() { results <- z; results <- a }()
	c, err := pick(results, func() (string, error) { return "a", nil })
	if err != nil || ConnID(c) != "a" {
		t.Fatalf("got %v %v, want a", c, err)
	}
}

// A peer that announces nothing (it predates SignalSelect: the stream ends)
// leaves today's pick: the highest ConnID.
func TestPickWithoutAnnouncementKeepsHighest(t *testing.T) {
	for name, await := range map[string]func() (string, error){
		"none":        nil,
		"stream ends": func() (string, error) { return "", io.EOF },
	} {
		a, _ := idConn(t, "a")
		b, _ := idConn(t, "b")
		results := make(chan net.Conn, 2)
		results <- a
		results <- b
		c, err := pick(results, await)
		if err != nil || ConnID(c) != "b" {
			t.Fatalf("%s: got %v %v, want b", name, c, err)
		}
	}
}

// SignalRelay instead of a selection: no direct connection is kept.
func TestPickPeerRelay(t *testing.T) {
	a, aPeer := idConn(t, "a")
	results := make(chan net.Conn)
	relay := make(chan struct{})
	go func() { results <- a; close(relay) }()
	c, err := pick(results, func() (string, error) { <-relay; return "", ErrPeerRelay })
	if !errors.Is(err, ErrPeerRelay) || c != nil {
		t.Fatalf("got %v %v, want ErrPeerRelay", c, err)
	}
	if !closed(aPeer) {
		t.Fatal("connection still open")
	}
}

// AnnounceConn and AwaitConn carry the choice over the signaling stream.
func TestAnnounceAwaitConnWire(t *testing.T) {
	cs, ss := streamPair()
	var ann, aw connectConfig
	AnnounceConn(cs, "s1")(&ann)
	AwaitConn(ss)(&aw)
	if err := ann.announce("id1"); err != nil {
		t.Fatal(err)
	}
	if id, err := aw.await(); err != nil || id != "id1" {
		t.Fatalf("got %q %v", id, err)
	}
	_ = SendRelay(cs, "s1")
	if _, err := aw.await(); !errors.Is(err, ErrPeerRelay) {
		t.Fatalf("relay: %v", err)
	}
}
