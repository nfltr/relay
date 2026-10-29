// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestForwardTUNCloseWithReplyPending: Close while the stack hands the TUN
// a packet nobody reads (WriteNotify blocked on its send) neither panics
// (a send on a closed channel) nor leaves that goroutine blocked.
func TestForwardTUNCloseWithReplyPending(t *testing.T) {
	allow, err := ParseDestinationPolicy([]string{"198.51.100.1/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := CreateForwardingTUN(netip.MustParseAddr("10.0.0.1"), 1420, allow, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	// A SYN to a refused destination: the stack answers RST, and nobody reads.
	if _, err := dev.Write([][]byte{tcpSYN(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("192.0.2.1"), 40000, 80)}, 0); err != nil {
		t.Fatal(err)
	}
	waitStacks(t, "the reply pending in WriteNotify", true)
	_ = dev.Close()
	waitStacks(t, "WriteNotify to return after Close", false)
	if _, err := dev.Read([][]byte{make([]byte, 1500)}, []int{0}, 0); err == nil {
		t.Fatal("Read after Close returned no error")
	}
}

func waitStacks(t *testing.T, what string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		if strings.Contains(string(buf[:runtime.Stack(buf, true)]), "(*forwardTUN).WriteNotify") == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func tcpSYN(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(pkt[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    dport,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
	tcp.SetChecksum(^checksum.Checksum(tcp, xsum))
	return pkt
}

// Close ends the Events channel, so the wireguard device's event reader
// goroutine (ranging over it) exits when the device closes.
func TestForwardTUNCloseEndsEvents(t *testing.T) {
	dev, err := CreateForwardingTUN(netip.MustParseAddr("10.0.0.1"), 1420, DestinationPolicy{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	_ = dev.Close()
	select {
	case _, ok := <-dev.Events():
		if ok {
			t.Fatal("event after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Events not closed by Close")
	}
}
