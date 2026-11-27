// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// PCP (RFC 6887) MAP of the direct socket's UDP port, asked before
// NAT-PMP on the gateway's same port 5351 (nfltr
// docs/decisions/hardnat-2026-11-25.md; spec/PortMap.tla Mapped,
// NotMapped). A NAT-PMP-only gateway answers a PCP request with version 0
// (RFC 6887 appendix A): errPCPVersion, and the caller asks NAT-PMP.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

const (
	pcpVersion = 2
	pcpOpMap   = 1
	pcpUDP     = 17
	pcpLen     = 60 // the 24-byte header and the 36-byte MAP opcode, request and answer alike
	// pcpBound bounds one PCP ask (two tries): a NAT-PMP-only gateway that
	// drops version 2 costs this before NAT-PMP is asked.
	pcpBound = 250 * time.Millisecond
)

var errPCPVersion = errors.New("pcp: the gateway speaks NAT-PMP only")

// askPCP asks gw (its PCP port at) to map this endpoint's UDP port for
// life seconds (0 deletes it) with the mapping's nonce: the mapped address.
func (e *DirectEndpoint) askPCP(at netip.AddrPort, nonce [12]byte, life uint32) (netip.AddrPort, error) {
	ua, ok := e.pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, net.UnknownNetworkError("udp")
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(at))
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer c.Close()                                        //nolint:errcheck
	self := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr() // the client address the gateway sees (RFC 6887 8.1)
	port := uint16(ua.Port)                                // #nosec G115 -- a UDP port
	req := pcpMapRequest(self, nonce, port, life)
	b, err := udpAsk(c, req, pcpBound)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return pcpMapAnswer(b, nonce, port)
}

// pcpMapRequest is a MAP request (RFC 6887 7.1, 11.1) for UDP port port of
// client self: suggested external port the same, address any IPv4.
func pcpMapRequest(self netip.Addr, nonce [12]byte, port uint16, life uint32) []byte {
	req := []byte{pcpVersion, pcpOpMap, 0, 0}
	req = binary.BigEndian.AppendUint32(req, life)
	a16 := netip.AddrFrom16(self.As16())
	if self.Is4() {
		a16 = netip.AddrFrom16(netip.AddrFrom4(self.As4()).As16()) // IPv4-mapped
	}
	ip := a16.As16()
	req = append(req, ip[:]...)
	req = append(req, nonce[:]...)
	req = append(req, pcpUDP, 0, 0, 0)
	req = binary.BigEndian.AppendUint16(req, port)
	req = binary.BigEndian.AppendUint16(req, port)
	anyV4 := netip.AddrFrom16(netip.IPv4Unspecified().As16()).As16() // ::ffff:0.0.0.0, RFC 6887 11.1
	return append(req, anyV4[:]...)
}

// pcpMapAnswer reads a MAP answer (RFC 6887 7.2, 11.1) to the request for
// port with nonce: the assigned external address.
func pcpMapAnswer(b []byte, nonce [12]byte, port uint16) (netip.AddrPort, error) {
	switch {
	case len(b) >= 1 && b[0] == 0:
		return netip.AddrPort{}, errPCPVersion
	case len(b) < 4 || b[0] != pcpVersion || b[1] != 0x80|pcpOpMap:
		return netip.AddrPort{}, fmt.Errorf("pcp: unexpected answer % x", b)
	case b[3] != 0:
		return netip.AddrPort{}, fmt.Errorf("pcp: result code %d", b[3])
	case len(b) < pcpLen:
		return netip.AddrPort{}, fmt.Errorf("pcp: answer of %d bytes, want %d", len(b), pcpLen)
	case !bytes.Equal(b[24:36], nonce[:]) || b[36] != pcpUDP || binary.BigEndian.Uint16(b[40:42]) != port:
		return netip.AddrPort{}, errors.New("pcp: the answer is for another mapping")
	}
	ext := netip.AddrFrom16([16]byte(b[44:60])).Unmap()
	return netip.AddrPortFrom(ext, binary.BigEndian.Uint16(b[42:44])), nil
}

// udpAsk sends req on c (connected to the gateway, so it hears only the
// gateway) and returns the first answer, resending (RFC 6886 3.1: 250 ms,
// doubling; RFC 6887 8.1.1) within bound. errNoAnswer: silence.
func udpAsk(c *net.UDPConn, req []byte, bound time.Duration) ([]byte, error) {
	end := time.Now().Add(bound)
	b := make([]byte, 1100) // RFC 6887 7: at most 1100 bytes
	for wait := min(250*time.Millisecond, bound/2); time.Now().Before(end); wait *= 2 {
		d := time.Now().Add(wait)
		if d.After(end) {
			d = end
		}
		if err := c.SetDeadline(d); err != nil {
			return nil, err
		}
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		n, err := c.Read(b)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
	return nil, errNoAnswer
}
