// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wgexit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/wg"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/wgwire"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"google.golang.org/grpc/metadata"
)

// TestWireGuardExitSpeaksOnlyEndToEnd: an exit sends the end-to-end protocol
// (and its pairing flag), and refuses a relay that answers without it rather
// than starting a tunnel the relay would terminate.
func TestWireGuardExitSpeaksOnlyEndToEnd(t *testing.T) {
	pairing := t.TempDir() + "/pairing"
	if err := os.WriteFile(pairing, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The options compose in either order: the pairing key first here.
	var ax agent.WireGuardExit
	for _, set := range []func(*exit) error{pairingKeyFile(pairing), generateKeys([]string{"all"})} {
		var err error
		if ax, err = update(ax, set); err != nil {
			t.Fatal(err)
		}
	}
	x := ax.(*exit)
	if !x.Enabled() {
		t.Fatal("an exit with a key is not enabled")
	}
	md := metadata.New(nil)
	x.ConnectMetadata(md)
	for k, want := range map[string]string{wgwire.ProtocolHeader: wgwire.Protocol, "x-wg-exit-node": "true", wgwire.PairedHeader: "true", "x-wg-pubkey": x.publicKey} {
		if got := md.Get(k); len(got) != 1 || got[0] != want {
			t.Errorf("metadata %s = %q; want %q", k, got, want)
		}
	}

	_, serverKey, _ := wg.GenerateKeyPair()
	old := metadata.Pairs("x-resolved-agent-id", "exit", "x-wg-assigned-ip", "100.64.0.2", "x-wg-server-pubkey", serverKey)
	if tun, err := x.Start(context.Background(), old, slog.New(slog.DiscardHandler)); !errors.Is(err, errRelayTooOld) || tun != nil {
		t.Fatalf("relay-terminated relay: %v, %v; want errRelayTooOld", tun, err)
	}
	if x.running != nil {
		t.Fatal("a tunnel was started for a relay that would terminate it")
	}
}

// TestWireGuardPairingKeyAloneIsNoExit: a pairing key without a key pair
// leaves the agent an ordinary one (it still moves between replicas).
func TestWireGuardPairingKeyAloneIsNoExit(t *testing.T) {
	pairing := t.TempDir() + "/pairing"
	if err := os.WriteFile(pairing, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	x, err := update(nil, pairingKeyFile(pairing))
	if err != nil {
		t.Fatal(err)
	}
	if x.Enabled() {
		t.Fatal("a pairing key alone made the agent an exit")
	}
	if _, err := update(x, useKeys("not-a-key", []string{"all"})); err == nil || !strings.Contains(err.Error(), "WithWireGuardKeys: invalid private key") {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := update(x, generateKeys(nil)); err == nil {
		t.Fatal("an empty allow list was accepted")
	}
}

// recordingTunnel records the peers an exit was told to accept; every peer
// present reports status, an absent one an error (as a real tunnel does).
type recordingTunnel struct {
	peers  map[string]netip.Addr
	status wg.PeerStatus
}

func (r *recordingTunnel) Start(context.Context, wg.TunnelConfig, *wg.RelayBind) error { return nil }
func (r *recordingTunnel) Net() *netstack.Net                                          { return nil }
func (r *recordingTunnel) Close() error                                                { return nil }
func (r *recordingTunnel) AddPeer(k string, ip netip.Addr) error                       { r.peers[k] = ip; return nil }
func (r *recordingTunnel) RemovePeer(k string) error                                   { delete(r.peers, k); return nil }
func (r *recordingTunnel) Rehandshake(string) error                                    { return nil }
func (r *recordingTunnel) PeerStatus(k string) (wg.PeerStatus, error) {
	if _, ok := r.peers[k]; !ok {
		return wg.PeerStatus{}, errors.New("no peer")
	}
	return r.status, nil
}

// R4-G12: a client with the wrong pairing key sends handshake messages, gives
// up after its own bound and leaves; the relay removes it. The exit names the
// probable pairing-key mismatch then, without key material, and a client
// that reconnects in a loop cannot flood the log.
func TestWireGuardExitReportsAClientThatLeftWithoutAHandshake(t *testing.T) {
	var logs bytes.Buffer
	tun := &recordingTunnel{peers: map[string]netip.Addr{}, status: wg.PeerStatus{RxBytes: 148}}
	w := &tunnel{bind: wg.NewRelayBind(), tunnel: tun, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	_, key, _ := wg.GenerateKeyPair()
	update := func(op string) *pb.HTTPRequest {
		b, _ := json.Marshal(wgwire.PeerUpdate{Op: op, PublicKey: key, IP: netip.MustParseAddr("100.64.0.9")})
		return &pb.HTTPRequest{TransactionId: wgwire.PeerTxnID, Payload: b}
	}
	const warning = "its --e2ee-key-file probably does not match this exit's"
	session := func() {
		w.Handle(update(wgwire.PeerAdd))
		w.Handle(update(wgwire.PeerRemove))
	}
	warnings := func() (lines []string) {
		for line := range strings.SplitSeq(logs.String(), "\n") {
			if strings.Contains(line, warning) {
				lines = append(lines, line)
			}
		}
		return lines
	}

	for range 5 {
		session()
	}
	if got := warnings(); len(got) != 1 {
		t.Fatalf("5 failed sessions logged %d warnings; want 1 (rate-limited):\n%s", len(got), logs.String())
	}
	w.failedLoggedAt = w.failedLoggedAt.Add(-failedHandshakeLogEvery)
	session()
	got := warnings()
	if len(got) != 2 || !strings.Contains(got[1], `"suppressed_since_last":4`) {
		t.Fatalf("after the interval: %q; want a second warning counting 4 left out", got)
	}
	for _, line := range got {
		if strings.Contains(line, key) || strings.Contains(line, "public_key") {
			t.Fatalf("the warning carries key material: %s", line)
		}
	}

	// A client that completed a handshake, or never sent anything, is no failure.
	for _, st := range []wg.PeerStatus{{RxBytes: 148, LastHandshake: time.Now()}, {}} {
		tun.status = st
		w.failedLoggedAt = time.Time{}
		session()
	}
	if n := len(warnings()); n != 2 {
		t.Fatalf("%d warnings; a completed or silent client must not warn", n)
	}
}

// TestWireGuardExitAppliesOnlyValidPeerUpdates: the exit peers with the keys
// the relay vouches for and rejects a malformed update.
func TestWireGuardExitAppliesOnlyValidPeerUpdates(t *testing.T) {
	tun := &recordingTunnel{peers: map[string]netip.Addr{}}
	w := &tunnel{bind: wg.NewRelayBind(), tunnel: tun, logger: slog.New(slog.DiscardHandler)}
	_, key, _ := wg.GenerateKeyPair()
	update := func(u any) *pb.HTTPRequest {
		b, _ := json.Marshal(u)
		return &pb.HTTPRequest{TransactionId: wgwire.PeerTxnID, Payload: b}
	}
	ip := netip.MustParseAddr("100.64.0.9")
	if !w.Handle(update(wgwire.PeerUpdate{Op: wgwire.PeerAdd, PublicKey: key, IP: ip})) || tun.peers[key] != ip {
		t.Fatalf("peers = %v; want %s at %s", tun.peers, key, ip)
	}
	w.Handle(update(map[string]string{"op": "add", "public_key": "not-a-key", "ip": "100.64.0.10"}))
	if len(tun.peers) != 1 {
		t.Fatalf("a malformed update was applied: %v", tun.peers)
	}
	w.Handle(update(wgwire.PeerUpdate{Op: wgwire.PeerRemove, PublicKey: key}))
	if len(tun.peers) != 0 {
		t.Fatalf("peers = %v after remove; want none", tun.peers)
	}
	if w.Handle(&pb.HTTPRequest{TransactionId: "http-txn"}) {
		t.Fatal("an HTTP request was taken as a WireGuard message")
	}
}
