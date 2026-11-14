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

// TestParseNF1 is the capability address's registration
// (nfltr docs/decisions/nf1-rendezvous-2026-11-13.md section 1): ";nf1=<rid
// hex>" on a tcp+e2ee service alone, a non-zero rid, once per declaration.
func TestParseNF1(t *testing.T) {
	rid := [16]byte{1, 2, 3}
	good := []Decl{{Name: "clip", Kind: TCP, E2EE: E2EEOn, NF1: rid}, {Name: "pg", Kind: TCP, E2EE: E2EEOn, Group: "db"}}
	v := Format(good)
	if v != "clip=tcp+e2ee;nf1=01020300000000000000000000000000,pg=tcp+e2ee;group=db" {
		t.Fatalf("Format = %q", v)
	}
	got, err := Parse(v)
	if err != nil || !slices.Equal(got, good) {
		t.Fatalf("Parse(%q) = %v, %v", v, got, err)
	}
	if d, ok := FindNF1(got, rid); !ok || d.Name != "clip" {
		t.Fatalf("FindNF1 = %v, %v", d, ok)
	}
	if _, ok := FindNF1(got, [16]byte{9}); ok {
		t.Fatal("FindNF1 found another rid")
	}
	h := "01020300000000000000000000000000"
	for _, v := range []string{
		"a=tcp;nf1=" + h, "a=tcp+plain;nf1=" + h, "a=http;nf1=" + h,
		"a=tcp+e2ee;nf1=", "a=tcp+e2ee;nf1=00000000000000000000000000000000", "a=tcp+e2ee;nf1=0102",
		"a=tcp+e2ee;nf1=0102030000000000000000000000000G", "a=tcp+e2ee;nf1=0102030000000000000000000000000A",
		"a=tcp+e2ee;nf1=" + h + "00", "a=tcp+e2ee;nf1=" + h + ";", "a=tcp+e2ee;group=db;nf1=" + h,
		"a=tcp+e2ee;nf1=" + h + ";group=db", "a=tcp+e2ee;nf1=" + h + ";direct=on",
		"a=tcp+e2ee;nf1=" + h + ",b=tcp+e2ee;nf1=" + h,
	} {
		if d, err := Parse(v); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", v, d)
		}
	}
}

func TestParsePublic(t *testing.T) {
	good := []Decl{{Name: "mc", Kind: TCP, E2EE: E2EEOff, Public: true}, {Name: "db", Kind: TCP}}
	v := Format(good)
	if v != "mc=tcp+plain;public,db=tcp" {
		t.Fatalf("Format = %q", v)
	}
	got, err := Parse(v)
	if err != nil || !slices.Equal(got, good) {
		t.Fatalf("Parse(%q) = %v, %v", v, got, err)
	}
	if d, ok := Find(got, "mc"); !ok || !d.Public {
		t.Fatalf("Find = %v, %v", d, ok)
	}
	// A public service is plain tcp by declaration: never e2ee, http, a
	// group, direct or an nf1 address, and the attribute stands alone.
	for _, v := range []string{
		"a=tcp;public", "a=tcp+e2ee;public", "a=http;public", "a=tcp+plain;public;public",
		"a=tcp+plain;public=1", "a=tcp+plain;pub", "a=tcp+plain;group=db", "a=tcp+plain;public;direct=on",
		"a=tcp+e2ee;group=db;public", "a=tcp+e2ee;on", "a=tcp+e2ee;group=db;on",
	} {
		if d, err := Parse(v); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", v, d)
		}
	}
}

// A registration proof round-trips; malformed, duplicate, empty and
// oversized values are refused (nfltr docs/decisions/nf1-risks-2026-11-14.md).
func TestParseReg(t *testing.T) {
	rid := [RIDSize]byte{0xab, 2, 3}
	proof := []byte("proof bytes")
	got, err := ParseReg([]string{FormatReg(rid, proof)})
	if err != nil || string(got[rid]) != string(proof) || len(got) != 1 {
		t.Fatalf("round trip: %v, %v", got, err)
	}
	if got, err := ParseReg(nil); err != nil || len(got) != 0 {
		t.Fatalf("no values: %v, %v", got, err)
	}
	ok := FormatReg(rid, proof)
	many := make([]string, MaxServices+1)
	for i := range many {
		many[i] = FormatReg([RIDSize]byte{byte(i + 1)}, proof)
	}
	for what, vals := range map[string][]string{
		"no colon":    {strings.Replace(ok, ":", "", 1)},
		"short rid":   {ok[2:]},
		"upper hex":   {strings.ToUpper(ok[:2*RIDSize]) + ok[2*RIDSize:]},
		"zero rid":    {FormatReg([RIDSize]byte{}, proof)},
		"rid twice":   {ok, ok},
		"empty proof": {FormatReg(rid, nil)},
		"bad base64":  {ok + "!"},
		"oversized":   {FormatReg(rid, make([]byte, MaxRegProof+1))},
		"too many":    many,
	} {
		if _, err := ParseReg(vals); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}
