// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/nfltr/relay/client/nfnet"
)

// An echo service and its client, the smallest program of both halves:
//
//	echo serve               # prints the target to dial, e.g. echo/echo
//	echo laptop.echo/echo    # from another machine of the account
func Example_echo() {
	cfg := nfnet.Config{
		Relay: "nfltr.xyz:443", AgentRelay: "grpc.nfltr.xyz:443",
		Agent: "echo", ClientCert: machineCert,
	}
	if len(os.Args) < 2 {
		return
	}
	if os.Args[1] == "serve" {
		ln, err := nfnet.Listen(context.Background(), cfg, "echo", nfnet.ListenOptions{})
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close() //nolint:errcheck
		fmt.Println("dial me as", ln.Addr())
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()      //nolint:errcheck
				_, _ = io.Copy(c, c) // until the client's half close
			}()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := nfnet.Dial(ctx, cfg, os.Args[1])
	if err != nil {
		log.Print(err)
		os.Exit(int(nfnet.CodeOf(err))) // the exit table: 3 not found, 5 unreachable, ...
	}
	defer c.Close() //nolint:errcheck
	_, _ = io.WriteString(c, "hello\n")
	_ = c.CloseWrite() // our half close: the server's copy ends, its bytes still arrive
	_, _ = io.Copy(os.Stdout, c)
}

// ParseTarget reads the target forms offline; anything else is a usage
// error.
func ExampleParseTarget() {
	for _, s := range []string{"web/http", "laptop.chat/chat", "db@backend", "web"} {
		t, err := nfnet.ParseTarget(s)
		if err != nil {
			fmt.Printf("%-16s %v\n", s, nfnet.CodeOf(err))
			continue
		}
		fmt.Printf("%-16s kind %d: %s\n", s, t.Kind, t)
	}
	// Output:
	// web/http         kind 1: web/http
	// laptop.chat/chat kind 2: laptop.chat/chat
	// db@backend       kind 3: db@backend
	// web              usage
}

// CodeOf turns any error of the package into the exit table's code: a
// program exits with it, or branches on it.
func ExampleCodeOf() {
	_, err := nfnet.ParseTarget("not a target")
	code := nfnet.CodeOf(err)
	fmt.Println(int(code), code)
	fmt.Println(nfnet.CodeOf(nil) == 0)
	// Output:
	// 1 usage
	// true
}

// machineCert is this machine's certificate (nfltr config login, or
// machinecert): here a PEM pair beside the program.
func machineCert() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair("machine.crt", "machine.key")
	return &c, err
}
