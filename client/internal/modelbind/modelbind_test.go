// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package modelbind

import (
	"regexp"
	"testing"
)

func TestCheck(t *testing.T) {
	id := regexp.MustCompile(`BIND:(x\.[a-z]+)`)
	pending := map[string]string{"x.later": "test"}
	model := []byte("BIND:x.a BIND:x.b BIND:x.a BIND:x.later BIND:y.c")
	for _, c := range []struct {
		name string
		rows []string
		ok   bool
	}{
		{"every id a row, the pending one exempt", []string{"x.b", "x.a"}, true},
		{"a row missing", []string{"x.a"}, false},
		{"a row the model lacks", []string{"x.a", "x.b", "x.z"}, false},
		{"a pending id with a row", []string{"x.a", "x.b", "x.later"}, false},
	} {
		if err := check(model, id, c.rows, pending); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
