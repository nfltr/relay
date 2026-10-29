// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package wgwire is the WireGuard endpoint protocol between `nfltr wg`
// endpoints and the relay: metadata keys, transaction tags and peer updates.
// Both ends import it; the tunnel (client/wg) and the relay's forwarder
// build on it.
package wgwire

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// The end-to-end WireGuard protocol between `nfltr wg` endpoints and the
// relay. The client and the exit are WireGuard peers of each other; the relay
// forwards their sealed packets and never holds a WireGuard key.
const (
	// ProtocolHeader carries Protocol on connect (endpoint → relay) and in
	// the response (relay → endpoint). Either side refuses a peer without it:
	// the older protocol terminated WireGuard at the relay.
	ProtocolHeader = "x-wg-protocol"
	// Protocol names this protocol version.
	Protocol = "e2e-v1"
	// TxnID is the magic transaction ID that tags WireGuard packet messages
	// on the ConnectHTTP gRPC stream, distinguishing them from regular HTTP
	// proxy traffic.
	TxnID = "__wg__"

	// PeerKeyHeader tells a client its exit's WireGuard public key, as the
	// exit presented it on its authenticated session.
	PeerKeyHeader = "x-wg-peer-pubkey"
	// PairedHeader ("true") says an endpoint mixes a pairing key into its
	// handshakes (--e2ee-key-file), so the relay can refuse a client and exit
	// that disagree instead of letting their handshake fail silently.
	PairedHeader = "x-wg-paired"

	// PeerTxnID tags a PeerUpdate the relay sends an exit.
	PeerTxnID = "__wg_peer__"
)

// PeerUpdate tells an exit to add or remove a client peer the relay vouches
// for: its public key and its tunnel address (the peer's only AllowedIP).
type PeerUpdate struct {
	Op        string     `json:"op"` // PeerAdd or PeerRemove
	PublicKey string     `json:"public_key"`
	IP        netip.Addr `json:"ip"`
}

// PeerUpdate operations.
const (
	PeerAdd    = "add"
	PeerRemove = "remove"
)

// Validate rejects an update an exit must not apply.
func (u PeerUpdate) Validate() error {
	if u.Op != PeerAdd && u.Op != PeerRemove {
		return fmt.Errorf("wg: peer update: unknown op %q", u.Op)
	}
	if _, err := decodeBase64Key(u.PublicKey); err != nil {
		return fmt.Errorf("wg: peer update: %w", err)
	}
	if u.Op == PeerAdd && (!u.IP.IsValid() || u.IP.IsUnspecified()) {
		return fmt.Errorf("wg: peer update: invalid address %v", u.IP)
	}
	return nil
}

// decodeBase64Key decodes a base64-encoded WireGuard key (32 bytes).
func decodeBase64Key(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("wg: decode key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("wg: key must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

// CheckPublicKey rejects a string that is not a base64 WireGuard key.
func CheckPublicKey(b64 string) error {
	_, err := decodeBase64Key(b64)
	return err
}

// ParsePeerUpdate decodes and validates a PeerUpdate payload.
func ParsePeerUpdate(payload []byte) (PeerUpdate, error) {
	var u PeerUpdate
	if err := json.Unmarshal(payload, &u); err != nil {
		return u, fmt.Errorf("wg: peer update: %w", err)
	}
	return u, u.Validate()
}

// ExitPacketTxnID tags a sealed packet on an exit's stream with the client
// peer it is from (relay → exit) or for (exit → relay). A client's stream has
// one peer and uses TxnID.
func ExitPacketTxnID(peer string) string { return TxnID + "/" + peer }

// ExitPacketPeer returns the client peer an exit packet's tag names.
// allow:wrapper — the inverse of ExitPacketTxnID, one tag format.
func ExitPacketPeer(txnID string) (string, bool) {
	return strings.CutPrefix(txnID, TxnID+"/")
}

// IsPacketTxnID reports whether a stream message carries a sealed packet.
func IsPacketTxnID(txnID string) bool {
	return txnID == TxnID || strings.HasPrefix(txnID, TxnID+"/")
}
