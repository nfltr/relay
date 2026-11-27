// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package tcprig holds TCP test rigs.
package tcprig

import (
	"net"
	"testing"
)

// RefusedAddr is a loopback address every TCP dial to is refused while tb
// runs: the local port of a connection the test holds (no listener on it,
// and no other socket binds it while the connection lasts). A port probed
// free and closed is not that: any process may take it at once, and then a
// dial "to a refusing target" reaches a stranger (a parallel package's
// listener answered one with EOF on a CI runner). A bound socket that never
// listens would do on Linux, but macOS drops a SYN to it (the dial times
// out). Guard: TestRefusedAddrHoldsItsPort.
func RefusedAddr(tb testing.TB) *net.TCPAddr {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = ln.Close() }() // the connection holds the port, not the listener
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	peer, err := ln.Accept()
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = peer.Close() })
	return c.LocalAddr().(*net.TCPAddr)
}
