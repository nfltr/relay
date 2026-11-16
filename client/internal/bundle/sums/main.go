// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Command sums writes a browser extension directory's SHA256SUMS (bundle.Sums)
// or, with -check FILE, verifies the directory against a release's listing
// (bundle.Verify): scripts/browser-bundle.sh.
//
//	go run ./internal/bundle/sums [-check SHA256SUMS] DIR
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nfltr/relay/client/internal/bundle"
)

func main() {
	check := flag.String("check", "", "the release's SHA256SUMS to verify DIR against")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sums [-check SHA256SUMS] DIR")
		os.Exit(2)
	}
	dir := os.DirFS(flag.Arg(0))
	if *check != "" {
		want, err := os.ReadFile(*check)
		if err == nil {
			err = bundle.Verify(dir, want)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	b, err := bundle.Sums(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(b)
}
