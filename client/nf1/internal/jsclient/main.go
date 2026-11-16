// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Command jsclient is the nf1 handshake as a browser runs it (nfltr
// docs/decisions/browser-peer-2026-11-16.md, lane BP1): the address, the
// rendezvous answer, pinned TLS 1.3 and the proof (nf1.Handshake), built
// for GOOS=js GOARCH=wasm by `make wasm-nf1`, whose size budget keeps the
// relay dial (gRPC, the data plane, QUIC) out of it. It runs one session
// against a listener in the same process, over an in-memory pipe (the
// browser's transports are lane BP4's), and prints "ok" once the service's
// byte came back: the target runs it under node, so the handshake is
// proven to work on js/wasm, not only to link.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "jsclient:", err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

func run() error {
	l, _, err := nf1.Mint("relay.example")
	if err != nil {
		return err
	}
	// The client knows only the address's text, as a browser does.
	addr, err := capaddr.Parse(l.Address().String())
	if err != nil {
		return err
	}
	ctx := context.Background()
	c, s := net.Pipe()
	served := make(chan error, 1)
	go func() {
		tc, err := l.Accept(ctx, s)
		if err == nil {
			_, err = tc.Write([]byte{'!'})
		}
		served <- err
	}()
	tc, err := nf1.Handshake(ctx, c, addr)
	if err != nil {
		return err
	}
	var b [1]byte
	_, err = io.ReadFull(tc, b[:])
	_ = c.Close() // no close_notify: net.Pipe is synchronous, and nobody reads it
	if err != nil || b[0] != '!' {
		return fmt.Errorf("the service's byte: %q, %v", b[:], err)
	}
	return <-served
}
