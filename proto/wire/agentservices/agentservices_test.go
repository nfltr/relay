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
	good := []Decl{{Name: "web", Kind: HTTP}, {Name: "db", Kind: TCP}, {Name: "a1-b", Kind: TCP, E2EE: E2EEOn}, {Name: "p", Kind: TCP, E2EE: E2EEOff},
		{Name: "pg", Kind: TCP, E2EE: E2EEOn, Group: "db"}, {Name: "q", Kind: TCP, E2EE: E2EEOn, Group: "0-a", Direct: DirectOn},
		{Name: "r", Kind: TCP, E2EE: E2EEOn, Direct: DirectPublic}}
	got, err := Parse(Format(good))
	if err != nil || !slices.Equal(got, good) || Format(good) != "web=http,db=tcp,a1-b=tcp+e2ee,p=tcp+plain,pg=tcp+e2ee;group=db,q=tcp+e2ee;group=0-a;direct=on,r=tcp+e2ee;direct=public" {
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
		// group and direct: tcp+e2ee only, a valid group, canonical order, once each
		"web=http;group=db", "db=tcp;group=db", "db=tcp+plain;direct=on", "db=tcp+e2ee;",
		"db=tcp+e2ee;group=", "db=tcp+e2ee;group=DB", "db=tcp+e2ee;group=-db", "db=tcp+e2ee;group=db-",
		"db=tcp+e2ee;group=d.b", "db=tcp+e2ee;group=d_b", "db=tcp+e2ee;group=" + strings.Repeat("g", 64),
		"db=tcp+e2ee;group=db;", "db=tcp+e2ee;group=a;group=b", "db=tcp+e2ee;direct=on;group=db",
		"db=tcp+e2ee;direct=", "db=tcp+e2ee;direct=off", "db=tcp+e2ee;direct=true", "db=tcp+e2ee;direct=on;direct=on",
		"db=tcp+e2ee;direct=on;", "db=tcp+e2ee;tags=x", "db=tcp+e2ee;group=db=x",
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

func TestValidLabelAndHealth(t *testing.T) {
	for _, s := range []string{"db", "0", "a-b", "m-abc-db", strings.Repeat("g", 63)} {
		if !ValidLabel(s) {
			t.Errorf("ValidLabel(%q) = false", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", "A", "a.b", "a_b", "a b", strings.Repeat("g", 64)} {
		if ValidLabel(s) {
			t.Errorf("ValidLabel(%q) = true", s)
		}
	}
	if HealthLabel("pg") != "nfltr.health.pg" {
		t.Fatal(HealthLabel("pg"))
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"web=http,db=tcp", "a=tcp", "", "x=y", "web=http,web=http", "v=tcp+e2ee,p=tcp+plain", "w=http+e2ee", "x=tcp+", "pg=tcp+e2ee;group=db;direct=on", "q=tcp+e2ee;direct=public"} {
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
			if !ValidName(d.Name) || (d.Kind != HTTP && d.Kind != TCP) || (d.E2EE != E2EEDefault && (d.Kind != TCP || (d.E2EE != E2EEOn && d.E2EE != E2EEOff))) ||
				((d.Group != "" || d.Direct != DirectOff) && (d.Kind != TCP || d.E2EE != E2EEOn)) || (d.Group != "" && !ValidLabel(d.Group)) ||
				(d.Direct != DirectOff && d.Direct != DirectOn && d.Direct != DirectPublic) {
				t.Fatalf("Parse(%q) accepted %+v", s, d)
			}
		}
		if again, err := Parse(Format(decls)); err != nil || !slices.Equal(again, decls) {
			t.Fatalf("round trip of %q: %v %v", s, again, err)
		}
	})
}
