// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"net"
	"strings"
	"testing"

	"github.com/pion/stun/v4"
)

// fakeSTUNServer answers each Binding Request it gets with reply(req) (pion
// decodes the request: an independent check that it is valid STUN) and
// records every request's transaction ID.
func fakeSTUNServer(t *testing.T, reply func(srv *net.UDPConn, from *net.UDPAddr, req *stun.Message)) (*[][stun.TransactionIDSize]byte, func()) {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var txids [][stun.TransactionIDSize]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if err := req.Decode(); err != nil || req.Type != stun.BindingRequest {
				t.Errorf("request is not a STUN Binding Request (pion: %v, type %v)", err, req.Type)
				continue
			}
			txids = append(txids, req.TransactionID)
			reply(srv, from, req)
		}
	}()
	orig := STUNServer
	STUNServer = srv.LocalAddr().String()
	return &txids, func() {
		STUNServer = orig
		_ = srv.Close()
		<-done
	}
}

func bindingSuccess(t *testing.T, txid [stun.TransactionIDSize]byte, ip string, port int) []byte {
	t.Helper()
	m, err := stun.Build(stun.NewTransactionIDSetter(txid), stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.ParseIP(ip), Port: port}, stun.NewSoftware("conformance"), stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return m.Raw
}

// RFC 8489 §6: a fresh, random 96-bit transaction ID per request.
func TestDiscoverExternalAddrUsesRandomTransactionIDs(t *testing.T) {
	txids, stop := fakeSTUNServer(t, func(srv *net.UDPConn, from *net.UDPAddr, req *stun.Message) {
		_, _ = srv.WriteToUDP(bindingSuccess(t, req.TransactionID, "203.0.113.7", 4242), from)
	})
	for range 2 {
		got, err := DiscoverExternalAddr(0)
		if err != nil || got != "203.0.113.7:4242" {
			t.Fatalf("DiscoverExternalAddr = %q, %v; want 203.0.113.7:4242", got, err)
		}
	}
	stop()
	if len(*txids) != 2 || (*txids)[0] == (*txids)[1] {
		t.Fatalf("transaction IDs %x: want two distinct ones", *txids)
	}
	for _, id := range *txids {
		if strings.HasPrefix(string(id[:]), "nfltr-p2p") {
			t.Fatalf("transaction ID %q is the old fixed one", id)
		}
	}
}

// RFC 8489 §6.3.1: a response whose transaction ID does not match, or that
// does not come from the server, is not the answer (an off-path spoofer or a
// stale reply must not set the server-reflexive candidate).
func TestDiscoverExternalAddrIgnoresForeignResponses(t *testing.T) {
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck
	_, stop := fakeSTUNServer(t, func(srv *net.UDPConn, from *net.UDPAddr, req *stun.Message) {
		var wrong [stun.TransactionIDSize]byte
		copy(wrong[:], "nfltr-p2p-01")
		_, _ = srv.WriteToUDP(bindingSuccess(t, wrong, "6.6.6.6", 6), from)                  // other transaction
		_, _ = other.WriteToUDP(bindingSuccess(t, req.TransactionID, "7.7.7.7", 7), from)    // not the server
		_, _ = srv.WriteToUDP(bindingSuccess(t, req.TransactionID, "198.51.100.9", 9), from) // the answer
	})
	defer stop()
	got, err := DiscoverExternalAddr(0)
	if err != nil || got != "198.51.100.9:9" {
		t.Fatalf("DiscoverExternalAddr = %q, %v; want 198.51.100.9:9", got, err)
	}
}

// parseSTUNMappedAddr against messages pion encodes (SOFTWARE, FINGERPRINT,
// an IPv6 XOR-MAPPED-ADDRESS, an error response).
func TestParseSTUNMappedAddrPionMessages(t *testing.T) {
	var txid [stun.TransactionIDSize]byte
	copy(txid[:], "conformance1")
	if got, err := parseSTUNMappedAddr(bindingSuccess(t, txid, "192.0.2.1", 3478), txid); err != nil || got != "192.0.2.1:3478" {
		t.Fatalf("pion response: %q, %v", got, err)
	}
	// An IPv6 mapping was misread as the first four bytes of an IPv4 one.
	if got, err := parseSTUNMappedAddr(bindingSuccess(t, txid, "2001:db8::1", 3478), txid); err == nil {
		t.Fatalf("IPv6 XOR-MAPPED-ADDRESS parsed as %q; want an error (the probe is IPv4)", got)
	}
	bad := bindingSuccess(t, txid, "192.0.2.1", 3478)
	bad[len(bad)-1] ^= 0xff // FINGERPRINT no longer matches
	if got, err := parseSTUNMappedAddr(bad, txid); err == nil {
		t.Fatalf("bad FINGERPRINT parsed as %q; want an error", got)
	}
	e, err := stun.Build(stun.NewTransactionIDSetter(txid), stun.NewType(stun.MethodBinding, stun.ClassErrorResponse), stun.CodeBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := parseSTUNMappedAddr(e.Raw, txid); err == nil {
		t.Fatalf("error response parsed as %q; want an error", got)
	}
}
