// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"bytes"
	"testing"
)

func TestPresharedKeyRejectsShortKeys(t *testing.T) {
	if _, err := PresharedKey([]byte("too-short"), "home", ""); err == nil {
		t.Fatal("a short key was accepted")
	}
}

// Finding 5 (spec/proverif wg_exit.pv query 4, mutant name-unbound): the
// key binds the exit's name and the key id; a ref and its service name
// are one exit.
func TestPresharedKeyBindsExitAndKeyID(t *testing.T) {
	k := bytes.Repeat([]byte{7}, 32)
	psk := func(exit, kid string) string {
		t.Helper()
		p, err := PresharedKey(k, exit, kid)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if psk("home", "") == psk("office", "") {
		t.Fatal("two exits on one key share a preshared key")
	}
	if psk("home", "") == psk("home", "m1.1") {
		t.Fatal("the key id is not bound")
	}
	if psk("home", "m1.1") != psk("m-abcdefghijklmnopqrstuvwxyz-home", "m1.1") {
		t.Fatal("an agent ref and its service name differ")
	}
	if psk("home", "m1.1") != psk("laptop.home", "m1.1") {
		t.Fatal("a machine name's exit and its service name differ")
	}
}
