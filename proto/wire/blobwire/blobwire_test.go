// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package blobwire

import (
	"errors"
	"strings"
	"testing"
)

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestContentRange(t *testing.T) {
	for _, c := range []struct {
		in                    string
		offset, length, total int64
		bad                   bool
	}{
		{in: "bytes 0-99/100", length: 100, total: 100},
		{in: "bytes 64-127/200", offset: 64, length: 64, total: 200},
		{in: "bytes */100", total: 100},
		{in: "bytes */0"},
		{in: "bytes 0-100/100", bad: true},
		{in: "bytes 5-4/100", bad: true},
		{in: "bytes -1-4/100", bad: true},
		{in: "bytes 0-4/", bad: true},
		{in: "items 0-4/10", bad: true},
		{in: "bytes +1-4/10", bad: true},
	} {
		offset, length, total, err := ParseContentRange(c.in)
		if c.bad {
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("%q: err = %v, want ErrMalformed", c.in, err)
			}
			continue
		}
		if err != nil || offset != c.offset || length != c.length || total != c.total {
			t.Errorf("%q = %d,%d,%d,%v", c.in, offset, length, total, err)
		}
		if got := FormatContentRange(offset, length, total); got != c.in {
			t.Errorf("Format(%q parsed) = %q", c.in, got)
		}
	}
}

func TestDigest(t *testing.T) {
	v := FormatDigest(sha)
	if got, ok, err := ParseDigest("sha-512=:abc:, " + v); err != nil || !ok || got != sha {
		t.Fatalf("ParseDigest = %q, %v, %v", got, ok, err)
	}
	if _, ok, err := ParseDigest("sha-512=:abc:"); ok || err != nil {
		t.Fatalf("no sha-256: ok=%v err=%v", ok, err)
	}
	if _, _, err := ParseDigest("sha-256=:short:"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad sha-256 err = %v", err)
	}
}

func FuzzParseContentRange(f *testing.F) {
	for _, s := range []string{"bytes 0-99/100", "bytes */5", "bytes 9223372036854775806-9223372036854775806/9223372036854775807", "bytes 1-/2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		offset, length, total, err := ParseContentRange(v)
		if err != nil {
			return
		}
		if offset < 0 || length < 0 || total < 0 || offset+length > total || (length == 0 && offset != 0) {
			t.Fatalf("%q accepted as %d,%d,%d", v, offset, length, total)
		}
		if o2, l2, t2, err := ParseContentRange(FormatContentRange(offset, length, total)); err != nil || o2 != offset || l2 != length || t2 != total {
			t.Fatalf("%q does not round-trip", v)
		}
	})
}

func FuzzParseDigest(f *testing.F) {
	f.Add(FormatDigest(sha))
	f.Add("sha-256=:" + strings.Repeat("A", 44) + ":, md5=:x:")
	f.Fuzz(func(t *testing.T, v string) {
		got, ok, err := ParseDigest(v)
		if ok && (err != nil || len(got) != 64) {
			t.Fatalf("%q = %q, %v", v, got, err)
		}
		if ok && FormatDigest(got) == "" {
			t.Fatal("unreachable")
		}
	})
}
