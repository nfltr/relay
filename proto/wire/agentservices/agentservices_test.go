// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentservices

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	good := []Decl{{"web", HTTP, E2EEDefault}, {"db", TCP, E2EEDefault}, {"a1-b", TCP, E2EEOn}, {"p", TCP, E2EEOff}}
	got, err := Parse(Format(good))
	if err != nil || !slices.Equal(got, good) || Format(good) != "web=http,db=tcp,a1-b=tcp+e2ee,p=tcp+plain" {
		t.Fatalf("Parse(%q) = %v, %v", Format(good), got, err)
	}
	if d, ok := Find(got, "a1-b"); !ok || d.E2EE != E2EEOn {
		t.Fatal("Find")
	}
	if Lookup(got, "db") != TCP || Lookup(got, "x") != "" {
		t.Fatal("Lookup")
	}
	bad := []string{
		"", "web", "web=", "=http", "web=udp", "Web=http", "1db=tcp", "db-=tcp",
		"web=http,web=tcp", "web=http,", ",web=http", "a b=http", "web=http=x",
		"localhost:5432=tcp", "../db=tcp", strings.Repeat("a", 64) + "=tcp",
		strings.Repeat("a=tcp,", MaxServices) + "b=tcp",
		"web=http+e2ee", "db=tcp+", "db=tcp+tls", "db=tcp+e2ee+plain", "db=+e2ee",
	}
	for _, v := range bad {
		if d, err := Parse(v); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", v, d)
		}
	}
	var max []Decl
	for i := range MaxServices {
		max = append(max, Decl{Name: fmt.Sprintf("s%d", i), Kind: TCP})
	}
	if _, err := Parse(Format(max)); err != nil {
		t.Fatalf("%d services: %v", MaxServices, err)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"web", "db", "a", "my-api2"} {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range []string{"", "5432", "1web", "-a", "a-", "A", "a.b", "a/b", "a:1", "__e2ee__"} {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"web=http,db=tcp", "a=tcp", "", "x=y", "web=http,web=http", "v=tcp+e2ee,p=tcp+plain", "w=http+e2ee", "x=tcp+"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		decls, err := Parse(s)
		if err != nil {
			return
		}
		if len(decls) == 0 || len(decls) > MaxServices {
			t.Fatalf("Parse(%q) = %d services", s, len(decls))
		}
		for _, d := range decls {
			if !ValidName(d.Name) || (d.Kind != HTTP && d.Kind != TCP) || (d.E2EE != E2EEDefault && (d.Kind != TCP || (d.E2EE != E2EEOn && d.E2EE != E2EEOff))) {
				t.Fatalf("Parse(%q) accepted %+v", s, d)
			}
		}
		if again, err := Parse(Format(decls)); err != nil || !slices.Equal(again, decls) {
			t.Fatalf("round trip of %q: %v %v", s, again, err)
		}
	})
}
