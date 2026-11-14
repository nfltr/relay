// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/nfnet"
	"github.com/nfltr/relay/client/orgid"
)

// A two-machine chat: `chat serve` on one machine, `chat <target>` on the
// other; lines from stdin go to the peer, the peer's to stdout. On a
// machine enrolled in an organisation (nfltr org join) the session is end
// to end encrypted by its certificates and only machines of group friends
// may connect; otherwise it is a plain session of the account's key.
//
//	chat serve                 # prints: dial me as chat/chat
//	chat laptop.chat/chat      # from another machine of the account
//	chat chat@friends          # any machine of group friends serving chat
func Example_chat() {
	cfg := nfnet.Config{
		Relay: "nfltr.xyz:443", AgentRelay: "grpc.nfltr.xyz:443",
		Agent: "chat", APIKey: os.Getenv("NFLTR_API_KEY"),
	}
	if org, err := orgid.Load(orgid.DefaultDir()); err == nil {
		cfg.Org = org // enrolled: end to end, by organisation certificate
	}
	if len(os.Args) < 2 {
		return
	}
	ctx := context.Background()
	var c net.Conn
	if os.Args[1] == "serve" {
		o := nfnet.ListenOptions{}
		if cfg.Org != nil {
			o.AllowGroups = []string{"friends"}
		}
		ln, err := nfnet.Listen(ctx, cfg, "chat", o)
		check(err)
		defer ln.Close() //nolint:errcheck
		fmt.Fprintln(os.Stderr, "dial me as", ln.Addr())
		c, err = ln.Accept()
		check(err)
	} else {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		conn, err := nfnet.Dial(ctx, cfg, os.Args[1]) // laptop.chat/chat, chat@friends, nf1...
		check(err)
		c = conn
	}
	chat(c)
}

// The same chat under a capability address: the server mints an address
// and prints it; whoever holds it dials with an empty Config (the address
// names its relay, its pin and its secret), no account, no enrolment.
//
//	chat serve-address         # prints: dial me as nf1...
//	chat nf1...                # from anywhere
func Example_chatAddress() {
	if len(os.Args) < 2 {
		return
	}
	ctx := context.Background()
	var c net.Conn
	if os.Args[1] == "serve-address" {
		l, _, err := nf1.Mint("nfltr.xyz") // keep the key to serve the same address again (nf1.NewListener)
		check(err)
		cfg := nfnet.Config{Relay: "nfltr.xyz:443", AgentRelay: "grpc.nfltr.xyz:443", Agent: "chat", APIKey: os.Getenv("NFLTR_API_KEY")}
		ln, err := nfnet.Listen(ctx, cfg, "chat", nfnet.ListenOptions{Address: l})
		check(err)
		defer ln.Close() //nolint:errcheck
		fmt.Fprintln(os.Stderr, "dial me as", ln.Address())
		c, err = ln.Accept()
		check(err)
	} else {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		conn, err := nfnet.Dial(ctx, nfnet.Config{}, os.Args[1])
		check(err)
		c = conn
	}
	chat(c)
}

// chat copies stdin to c (its end a half close) and c to stdout, then
// exits with the session's code (0 for a clean end).
func chat(c net.Conn) {
	go func() {
		_, _ = io.Copy(c, os.Stdin)
		_ = c.(interface{ CloseWrite() error }).CloseWrite()
	}()
	_, err := io.Copy(os.Stdout, c)
	_ = c.Close()
	os.Exit(int(nfnet.CodeOf(err)))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(int(nfnet.CodeOf(err)))
	}
}
