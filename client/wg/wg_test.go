// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestDecodeBase64Key_Valid(t *testing.T) {
	t.Helper()
	b64 := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
	raw, err := decodeBase64Key(b64)
	if err != nil {
		t.Fatalf("decodeBase64Key: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("key length = %d, want 32", len(raw))
	}
}

func TestDecodeBase64Key_Invalid(t *testing.T) {
	t.Helper()
	cases := []struct {
		name string
		key  string
	}{
		{"not_base64", "!!invalid!!"},
		{"wrong_length", "dGVzdA=="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeBase64Key(tc.key)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestHexKey_Valid(t *testing.T) {
	t.Helper()
	b64 := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
	hex, err := hexKey(b64)
	if err != nil {
		t.Errorf("hexKey returned error for valid key: %v", err)
	}
	if hex == "" {
		t.Error("hexKey returned empty string for valid key")
	}
	if len(hex) != 64 {
		t.Errorf("hexKey length = %d, want 64", len(hex))
	}
}

func TestHexKey_Invalid(t *testing.T) {
	t.Helper()
	_, err := hexKey("not-valid-base64")
	if err == nil {
		t.Error("hexKey expected error for invalid input, got nil")
	}
}

func TestBuildIPC(t *testing.T) {
	t.Helper()
	privKey := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
	pubKey := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

	cfg := TunnelConfig{
		PrivateKey:    privKey,
		PeerPublicKey: pubKey,
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}

	ipc, err := buildIPC(cfg)
	if err != nil {
		t.Fatalf("buildIPC error: %v", err)
	}
	if ipc == "" {
		t.Fatal("buildIPC returned empty string")
	}

	for _, want := range []string{"private_key=", "public_key=", "endpoint=" + pubKey, "allowed_ip=0.0.0.0/0"} {
		found := false
		for _, line := range splitLines(ipc) {
			if len(line) >= len(want) && line[:len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IPC config missing %q", want)
		}
	}
}

// TestBuildIPCPresharedKeyAndExitWithoutPeer: a preshared key goes on the
// peer; an exit starts with no peer at all.
func TestBuildIPCPresharedKeyAndExitWithoutPeer(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	psk, _, _ := GenerateKeyPair()
	ipc, err := buildIPC(TunnelConfig{PrivateKey: priv, PeerPublicKey: pub, PresharedKey: psk})
	if err != nil {
		t.Fatal(err)
	}
	pskHex, _ := hexKey(psk)
	if !strings.Contains(ipc, "preshared_key="+pskHex+"\n") {
		t.Errorf("IPC has no preshared_key: %q", ipc)
	}
	ipc, err = buildIPC(TunnelConfig{PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ipc, "public_key=") {
		t.Errorf("exit IPC names a peer: %q", ipc)
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func TestRelayBind_DeliverAndReceive(t *testing.T) {
	t.Helper()
	bind := NewRelayBind()
	defer func() { _ = bind.Close() }()

	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port != 51820 {
		t.Errorf("port = %d, want 51820", port)
	}
	if len(fns) != 1 {
		t.Fatalf("ReceiveFuncs = %d, want 1", len(fns))
	}

	payload := []byte("wg-encrypted-packet")
	if err := bind.Deliver("peer-a", payload); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 2048)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("ReceiveFunc: %v", err)
	}
	if n != 1 {
		t.Fatalf("received %d packets, want 1", n)
	}
	if sizes[0] != len(payload) {
		t.Errorf("size = %d, want %d", sizes[0], len(payload))
	}
	got := string(packets[0][:sizes[0]])
	if got != string(payload) {
		t.Errorf("packet = %q, want %q", got, string(payload))
	}
	if eps[0].DstToString() != "peer-a" {
		t.Errorf("endpoint = %q, want the delivering peer's tag", eps[0].DstToString())
	}
}

func TestRelayBind_SendAndOutbound(t *testing.T) {
	t.Helper()
	bind := NewRelayBind()
	defer func() { _ = bind.Close() }()

	ep := &relayEndpoint{peer: "peer-b"}
	payload := []byte("outbound-wg-packet")
	if err := bind.Send([][]byte{payload}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	pkt := <-bind.Outbound()
	if string(pkt.Data) != string(payload) || pkt.Peer != "peer-b" {
		t.Errorf("outbound = %q to %q, want %q to peer-b", pkt.Data, pkt.Peer, payload)
	}
}

func TestRelayBind_CloseStopsReceive(t *testing.T) {
	t.Helper()
	bind := NewRelayBind()

	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := bind.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 2048)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	_, err = fns[0](packets, sizes, eps)
	if err == nil {
		t.Error("ReceiveFunc should return error after Close")
	}
}

func TestRelayBind_BatchSize(t *testing.T) {
	t.Helper()
	bind := NewRelayBind()
	defer func() { _ = bind.Close() }()
	if bind.BatchSize() != 1 {
		t.Errorf("BatchSize = %d, want 1", bind.BatchSize())
	}
}

func TestRelayBind_ParseEndpoint(t *testing.T) {
	bind := NewRelayBind()
	defer func() { _ = bind.Close() }()

	ep, err := bind.ParseEndpoint("peer-key")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if ep.DstToString() != "peer-key" || string(ep.DstToBytes()) != "peer-key" {
		t.Errorf("endpoint = %q / %q, want the peer tag", ep.DstToString(), ep.DstToBytes())
	}
}

func TestRelayBind_SetMark(t *testing.T) {
	t.Helper()
	bind := NewRelayBind()
	defer func() { _ = bind.Close() }()
	if err := bind.SetMark(42); err != nil {
		t.Errorf("SetMark: %v", err)
	}
}

// TestRelayBind_ReopenAfterClose verifies that a RelayBind can be
// Close()'d and then Open()'d again, which is required by wireguard-go's
// BindUpdate flow (called during device.Up()).
func TestRelayBind_ReopenAfterClose(t *testing.T) {
	t.Helper()
	bind := NewRelayBind()

	// First open.
	fns1, port1, err := bind.Open(0)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if len(fns1) == 0 || port1 == 0 {
		t.Fatal("first Open returned empty fns or zero port")
	}

	// Close.
	if err := bind.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen — must succeed (not return net.ErrClosed).
	fns2, port2, err := bind.Open(0)
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	if len(fns2) == 0 || port2 == 0 {
		t.Fatal("reopen returned empty fns or zero port")
	}

	// Deliver + recv on the reopened bind.
	if err := bind.Deliver("", []byte("hello")); err != nil {
		t.Fatalf("Deliver after reopen: %v", err)
	}

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 128)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns2[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("recv after reopen: %v", err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "hello" {
		t.Fatalf("recv got %d packets, data=%q, want 1/hello", n, packets[0][:sizes[0]])
	}

	if err := bind.Close(); err != nil {
		t.Fatalf("final Close: %v", err)
	}
}

func TestRelayEndpoint_ClearSrc(t *testing.T) {
	ep := &relayEndpoint{peer: "p"}
	ep.ClearSrc()
	if ep.SrcToString() != "" {
		t.Errorf("SrcToString = %q, want empty", ep.SrcToString())
	}
}

func TestNewTunnel(t *testing.T) {
	t.Helper()
	tun := NewTunnel(slogDiscard())
	if tun == nil {
		t.Fatal("NewTunnel returned nil")
	}
}

func TestTunnel_NetBeforeStart(t *testing.T) {
	t.Helper()
	tun := NewTunnel(slogDiscard())
	if tun.Net() != nil {
		t.Error("Net() should be nil before Start")
	}
}

func TestTunnel_CloseBeforeStart(t *testing.T) {
	t.Helper()
	tun := NewTunnel(slogDiscard())
	if err := tun.Close(); err != nil {
		t.Errorf("Close before Start: %v", err)
	}
}

func TestTunnel_CloseIdempotent(t *testing.T) {
	t.Helper()
	tun := NewTunnel(slogDiscard())
	if err := tun.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestTunnel_StartAfterClose(t *testing.T) {
	t.Helper()
	tun := NewTunnel(slogDiscard())
	if err := tun.Close(); err != nil {
		t.Fatalf("Close before StartAfterClose: %v", err)
	}

	bind := NewRelayBind()
	defer func() { _ = bind.Close() }()

	err := tun.Start(context.TODO(), TunnelConfig{
		PrivateKey:    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		PeerPublicKey: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		LocalAddress:  netip.MustParseAddr("100.64.0.1"),
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}, bind)
	if err != ErrTunnelClosed {
		t.Errorf("Start after Close = %v, want ErrTunnelClosed", err)
	}
}

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
