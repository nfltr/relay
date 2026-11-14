// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pendingBindings are BIND ids of spec/proverif models whose rows are not
// in this module yet: id -> where the row is (or why it waits). A model's
// id with no row and no entry here fails TestEveryModelBindingHasARow.
var pendingBindings = map[string]string{
	"dgram.tag": "cap_address.pv datagrams: design (nfltr docs/decisions/nf1-udp-2026-11-14.md, lane UDP3 adds the row with the direct datagram code)",
}

// TestEveryModelBindingHasARow: each BIND:<id> a model in spec/proverif
// declares is a quoted row key in a *_bindings_test.go of this module
// (nfltr.* ids included: the relay's row file lists them), whose package
// `make spec-bindings` runs, or is in pendingBindings. Without it a model
// whose bindings test is missing, or not run, is checked by nothing.
func TestEveryModelBindingHasARow(t *testing.T) {
	models, err := filepath.Glob("../spec/proverif/*.pv")
	if err != nil || len(models) == 0 {
		t.Fatalf("no models: %v", err)
	}
	mk, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	var run string // the spec-bindings recipe line
	for _, l := range strings.Split(string(mk), "\n") {
		if strings.Contains(l, "-run 'ModelBindings'") {
			run = l
		}
	}
	var rows strings.Builder
	err = filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_bindings_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !regexp.MustCompile(`func Test\w*ModelBindings\w*\(`).Match(b) {
			t.Errorf("%s has no Test...ModelBindings: make spec-bindings does not run it", path)
		}
		if dir := "./" + filepath.ToSlash(filepath.Dir(path)) + "/"; !strings.Contains(run, " "+dir) {
			t.Errorf("%s: make spec-bindings does not test %s", path, dir)
		}
		rows.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	id := regexp.MustCompile(`BIND:([a-z0-9][a-z0-9.]*[a-z0-9])`)
	for _, m := range models {
		src, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range id.FindAllSubmatch(src, -1) {
			b := string(s[1])
			if declared[b] {
				continue
			}
			declared[b] = true
			covered := strings.Contains(rows.String(), `"`+b+`"`)
			if _, pending := pendingBindings[b]; !covered && !pending {
				t.Errorf("%s declares BIND:%s and no bindings test has its row (add one, or list it in pendingBindings)", filepath.Base(m), b)
			} else if covered && pending {
				t.Errorf("BIND:%s has a row: drop it from pendingBindings", b)
			}
		}
	}
	for b := range pendingBindings {
		if !declared[b] {
			t.Errorf("pendingBindings lists %s, which no model declares", b)
		}
	}
}
