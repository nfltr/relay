// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"net"
	"time"

	"github.com/pion/webrtc/v4"
)

// Data channel flow control: writes go out in dcChunk messages, and pause
// while more than dcHigh bytes are queued until the queue drains to dcLow.
const (
	dcChunk = 32 << 10
	dcHigh  = 4 << 20
	dcLow   = 1 << 20
)

// rtcNetworkTypes are the kinds of ICE candidate gathered. A test that
// needs ICE to find no path gathers none (TCP without a TCP mux gives no
// candidate) rather than racing a short RTCWait against ICE on loopback.
var rtcNetworkTypes = []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6}

type dcAddr string

func (a dcAddr) Network() string { return "webrtc" }

// String is the candidate address (net.Addr). allow:wrapper
func (a dcAddr) String() string { return string(a) }

// chunkWriter splits writes into chunk-sized data channel messages and
// applies back-pressure: while more than high bytes are queued it waits for
// the low-water signal (re-checking every second, so a missed signal never
// stalls it). Memory stays bounded by high + chunk whatever the file size.
type chunkWriter struct {
	send     func([]byte) error
	buffered func() uint64
	low      <-chan struct{}
	done     chan struct{}
	chunk    int
	high     uint64
}

func (w *chunkWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		for w.buffered() > w.high {
			select {
			case <-w.low:
			case <-w.done:
				return n, net.ErrClosed
			case <-time.After(time.Second):
			}
		}
		select {
		case <-w.done:
			return n, net.ErrClosed
		default:
		}
		c := min(len(b), w.chunk)
		if err := w.send(b[:c]); err != nil {
			return n, err
		}
		n += c
		b = b[c:]
	}
	return n, nil
}
