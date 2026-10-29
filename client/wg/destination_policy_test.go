// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"errors"
	"net/netip"
	"testing"
)

func TestDestinationPolicy(t *testing.T) {
	t.Parallel()
	lookup := func(host string) ([]netip.Addr, error) {
		switch host {
		case "db.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.1.20")}, nil
		case "localhost":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, nil
		}
		return nil, errors.New("no such host")
	}
	ip := netip.MustParseAddr
	cases := []struct {
		name    string
		entries []string
		addr    string
		port    uint16
		want    bool
	}{
		{"cidr allows any port inside", []string{"192.168.1.0/24"}, "192.168.1.9", 5432, true},
		{"cidr refuses outside", []string{"192.168.1.0/24"}, "10.0.0.1", 80, false},
		{"host:port allows that port", []string{"10.0.0.5:8080"}, "10.0.0.5", 8080, true},
		{"host:port refuses another port", []string{"10.0.0.5:8080"}, "10.0.0.5", 22, false},
		{"hostname:port resolves once", []string{"db.lan:5432"}, "192.168.1.20", 5432, true},
		{"cidr:port", []string{"10.0.0.0/8:443"}, "10.9.9.9", 443, true},
		{"ipv6 with port", []string{"[fd00::1]:80"}, "fd00::1", 80, true},
		{"bare ipv6", []string{"fd00::1"}, "fd00::1", 22, true},
		{"all allows everything else", []string{"all"}, "203.0.113.7", 25, true},
		{"all refuses the exit's ipv4 loopback", []string{"all"}, "127.0.0.1", 8080, false},
		{"all refuses the rest of 127/8", []string{"all"}, "127.1.2.3", 22, false},
		{"all refuses the exit's ipv6 loopback", []string{"all"}, "::1", 8080, false},
		{"all refuses mapped loopback", []string{"all"}, "::ffff:127.0.0.1", 8080, false},
		{"all refuses unspecified ipv4", []string{"all"}, "0.0.0.0", 8080, false},
		{"all refuses unspecified ipv6", []string{"all"}, "::", 8080, false},
		{"a wide cidr does not reach loopback", []string{"0.0.0.0/0"}, "127.0.0.1", 8080, false},
		{"a wide cidr does not reach unspecified", []string{"0.0.0.0/0"}, "0.0.0.0", 8080, false},
		{"a wide ipv6 cidr does not reach loopback", []string{"::/0"}, "::1", 8080, false},
		{"explicit loopback port", []string{"all", "127.0.0.1:5432"}, "127.0.0.1", 5432, true},
		{"explicit loopback port only", []string{"127.0.0.1:5432"}, "127.0.0.1", 22, false},
		{"localhost:port resolves to loopback", []string{"localhost:5432"}, "::1", 5432, true},
		{"explicit ipv6 loopback", []string{"[::1]:80"}, "::1", 80, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseDestinationPolicy(tc.entries, lookup)
			if err != nil {
				t.Fatalf("parse %v: %v", tc.entries, err)
			}
			if got := p.Allows(ip(tc.addr), tc.port); got != tc.want {
				t.Fatalf("%v Allows(%s:%d) = %v, want %v", tc.entries, tc.addr, tc.port, got, tc.want)
			}
		})
	}
}

func TestDestinationPolicyDefaultRefusesEverything(t *testing.T) {
	t.Parallel()
	if _, err := ParseDestinationPolicy(nil, nil); !errors.Is(err, ErrEmptyDestinationPolicy) {
		t.Fatalf("empty allow-list: err = %v, want ErrEmptyDestinationPolicy", err)
	}
	var zero DestinationPolicy
	if zero.Allows(netip.MustParseAddr("192.168.1.1"), 80) {
		t.Fatal("zero DestinationPolicy allowed a destination")
	}
}

func TestDestinationPolicyRejectsBadEntries(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"10.0.0.1:0", "10.0.0.1:99999", "nope.invalid", "10.0.0.0/33"} {
		if _, err := ParseDestinationPolicy([]string{entry}, func(string) ([]netip.Addr, error) {
			return nil, errors.New("no such host")
		}); err == nil {
			t.Errorf("entry %q parsed; want an error", entry)
		}
	}
}
