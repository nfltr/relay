// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"google.golang.org/grpc"
)

// relayDialer is the dial option of a connection to the relay at host:port:
// relayDial, unless an HTTPS proxy from the environment carries it (gRPC
// dials a proxy only without a dialer of its own).
func relayDialer(host string, port int) []grpc.DialOption {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if p, _ := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}}); p != nil {
		return nil
	}
	return []grpc.DialOption{grpc.WithContextDialer(relayDial)}
}

// redialEvery is how often a connect attempt still unanswered starts
// another TCP dial. A SYN lost on a path that drops packets silently is sent
// again only at the kernel's retransmission times (Linux: 1, 3, 7 s), so a
// dial noticed a path that came back up to 4 s late, and a connect attempt
// (relayReconnectParams.MinConnectTimeout, 10 s) never noticed one that came
// back after its last SYN. Guard: TestDialNoticesAPathBackFromSilentDropsWithinASecond.
const redialEvery = time.Second

// relayDial dials addr, starting another dial every redialEvery while none
// has answered (an RST or an error answers), and returns the first answer;
// the dials still waiting are aborted, a late connection closed. At most
// MinConnectTimeout/redialEvery dials wait at once, and only on a path that
// drops their SYNs.
func relayDial(ctx context.Context, addr string) (net.Conn, error) {
	return staggeredDial(ctx, addr, (&net.Dialer{}).DialContext)
}

func staggeredDial(ctx context.Context, addr string, dialTCP func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		c   net.Conn
		err error
	}
	answers := make(chan answer)
	dial := func() {
		c, err := dialTCP(ctx, "tcp", addr)
		select {
		case answers <- answer{c, err}:
		case <-ctx.Done():
			if c != nil {
				_ = c.Close()
			}
		}
	}
	go dial()
	tick := time.NewTicker(redialEvery)
	defer tick.Stop()
	for {
		select {
		case a := <-answers:
			return a.c, a.err
		case <-tick.C:
			go dial()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
