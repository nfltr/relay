// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDir(t *testing.T) {
	d := t.TempDir()
	w := func(name, src string) { _ = os.WriteFile(filepath.Join(d, name), []byte(src), 0o600) }
	w("a.go", "package a\nvar knob = 1\nvar Exp = 2\nvar other = 3\n")
	w("a_test.go", "package a\nvar mine = 1\nfunc f() { knob = 2; mine = 3; other++; var knob int; knob = 4; _ = knob }\n")
	w("x_test.go", "package a_test\nfunc g() { a.Exp = 5; a.Other = 1 }\n")
	got, err := scanDir(d)
	if err != nil {
		t.Fatal(err)
	}
	// knob (line 3), other (++) and a.Exp; the shadowed knob and the test's own var are fine.
	var names []string
	for _, g := range got {
		names = append(names, g[strings.LastIndex(g, ":")+1:])
	}
	if strings.Join(names, ",") != "knob,other,Exp" {
		t.Fatalf("got %v", got)
	}
}
