// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"net"
	"testing"
	"time"
)

// synDropPath stands in for a network that drops packets silently (a NAT
// or uplink gone, no RST) until upAt: a TCP dial made while the path is
// down has its SYN lost and the kernel sends it again only at its
// retransmission times (Linux: 1, 3 and 7 s after the dial), so the dial
// connects at the first of those after the path is back, or never.
type synDropPath struct{ upAt time.Time }

func (p *synDropPath) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	start := time.Now()
	for _, retransmit := range []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second} {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Until(start.Add(retransmit))):
		}
		if !time.Now().Before(p.upAt) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestDialNoticesAPathBackFromSilentDropsWithinASecond: a relay dial made
// while the path drops every packet connects within about a second of the
// path's return, not at the kernel's next SYN retransmission (here 3.5 s
// later: one dial, as before relayDial) or the next connect attempt (up to
// the 10 s connect timeout later): the dx-compare home sidecar came back up
// to 3 s after its uplink.
func TestDialNoticesAPathBackFromSilentDropsWithinASecond(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	// Back 3.5 s into the dial: between the kernel's retransmissions at 3
	// and 7 s.
	back := time.Now().Add(3500 * time.Millisecond)
	path := &synDropPath{upAt: back}
	ctx, cancel := context.WithTimeout(context.Background(), relayReconnectParams.MinConnectTimeout)
	defer cancel()
	c, err := staggeredDial(ctx, ln.Addr().String(), path.dial)
	if err != nil {
		t.Fatalf("not connected %s after the path came back: %v", time.Since(back).Truncate(time.Millisecond), err)
	}
	_ = c.Close()
	if took := time.Since(back); took > 1500*time.Millisecond {
		t.Fatalf("connected %s after the path came back; want within about a second", took.Truncate(time.Millisecond))
	}
	t.Logf("connected %s after the path came back", time.Since(back).Truncate(time.Millisecond))
}
