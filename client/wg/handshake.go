// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// ErrHandshakeFailed reports that no WireGuard handshake completed with a
// peer in time. The relay forwards sealed packets and cannot tell a wrong
// pairing key from a right one, so a mismatched --e2ee-key-file shows up
// only as this: both ends exchange handshake messages and neither completes
// (R3-G5: the client used to report its SOCKS proxy ready and then hang).
var ErrHandshakeFailed = errors.New("WireGuard handshake failed; check that --e2ee-key-file matches on both ends")

// PeerStatus is what a tunnel knows of one peer.
type PeerStatus struct {
	LastHandshake time.Time // zero until a handshake completed
	RxBytes       uint64    // every message received, handshake messages included
}

// handshakePoll is how often AwaitHandshake looks.
var handshakePoll = 100 * time.Millisecond

// AwaitHandshake starts a handshake with peer and waits up to d for one to
// complete. It returns ErrHandshakeFailed when none does.
func AwaitHandshake(ctx context.Context, t Tunnel, peer string, d time.Duration) error {
	start := time.Now()
	if err := t.Rehandshake(peer); err != nil {
		return err
	}
	return pollHandshake(ctx, t, peer, start, d, func(PeerStatus) error {
		return fmt.Errorf("no handshake with the exit within %s: %w", d, ErrHandshakeFailed)
	})
}

// HandshakeFailed reports whether the peer sent handshake messages but none
// completed. An exit asks when the relay removes a client (the client ended
// its session): with pairing keys, a mismatched --e2ee-key-file. A peer that
// sent nothing never tried, so there is nothing to report. (The exit used to
// watch for 30s on a timer of its own; the client gives up after 20s and
// the peer was gone before the watch ended, so nothing was logged: R4-G12.)
func (st PeerStatus) HandshakeFailed() bool {
	return st.LastHandshake.IsZero() && st.RxBytes > 0
}

func pollHandshake(ctx context.Context, t Tunnel, peer string, since time.Time, d time.Duration, expired func(PeerStatus) error) error {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(handshakePoll)
	defer tick.Stop()
	for {
		st, err := t.PeerStatus(peer)
		if err != nil {
			return err
		}
		if st.LastHandshake.After(since) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return expired(st)
		case <-tick.C:
		}
	}
}

// peerStatus reads one peer's handshake state from the device's UAPI dump.
func peerStatus(dev *device.Device, publicKey string) (PeerStatus, error) {
	if dev == nil {
		return PeerStatus{}, ErrTunnelClosed
	}
	peerHex, err := hexKey(publicKey)
	if err != nil {
		return PeerStatus{}, fmt.Errorf("wg: peer public key: %w", err)
	}
	dump, err := dev.IpcGet()
	if err != nil {
		return PeerStatus{}, fmt.Errorf("wg: read device: %w", err)
	}
	var st PeerStatus
	var sec, nsec int64
	found, inPeer := false, false
	for line := range strings.SplitSeq(dump, "\n") {
		key, value, _ := strings.Cut(line, "=")
		if key == "public_key" {
			inPeer = value == peerHex
			found = found || inPeer
			continue
		}
		if !inPeer {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	if !found {
		return PeerStatus{}, fmt.Errorf("wg: no peer %s", publicKey)
	}
	if sec != 0 || nsec != 0 {
		st.LastHandshake = time.Unix(sec, nsec)
	}
	return st, nil
}
