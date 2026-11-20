// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// TestCloseTwice: what a second Close returns, as each Close's doc says
// (lane RELAYAPI): nil for a Client, Server, Flow and Forwarder;
// net.ErrClosed for a Conn, as net.Conn's. Closes race from two
// goroutines (go test -race).
func TestCloseTwice(t *testing.T) {
	to, _ := echo(t, 1)
	c, s := pair(t, Config{}, Config{}, dialUDP(to))
	f, _, _ := recvFlow(c)
	conn, err := c.Dial(addr("l"), to)
	if err != nil {
		t.Fatal(err)
	}
	fw := NewForwarder(ForwarderConfig{}, func(context.Context) (*Client, error) { return c, nil }, func([]byte, netip.AddrPort) {})
	twice := func(name string, close func() error, second error) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Go(func() { errs[i] = close() })
		}
		wg.Wait()
		if errs[0] != nil && errs[1] != nil {
			t.Errorf("%s: both Closes failed: %v, %v", name, errs[0], errs[1])
		}
		if err := close(); !errors.Is(err, second) || (second == nil && err != nil) {
			t.Errorf("%s: a further Close = %v, want %v", name, err, second)
		}
	}
	twice("Conn", conn.Close, net.ErrClosed)
	twice("Flow", f.Close, nil)
	twice("Forwarder", fw.Close, nil)
	twice("Client", c.Close, nil)
	twice("Server", s.Close, nil)
}
