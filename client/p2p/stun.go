// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v4"
)

// STUNServer is the public STUN server used to discover the external (NAT-mapped)
// address of a local listener.  Uses Google's free STUN service by default;
// "" turns discovery off (nfltr p2p with a private relay).
var STUNServer = "stun.l.google.com:19302"

// ErrSTUNOff is DiscoverExternalAddr's error when STUNServer is "".
var ErrSTUNOff = errors.New("stun: no STUN server configured")

// DiscoverExternalAddr sends one STUN Binding Request from localPort to
// STUNServer and returns the server-reflexive address ("ip:port") observed
// by the STUN server.  This is the "server-reflexive candidate" in ICE
// terminology — the external IP:port that peers outside the local NAT can
// try to reach.
func DiscoverExternalAddr(localPort int) (string, error) {
	if STUNServer == "" {
		return "", ErrSTUNOff
	}
	laddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return "", fmt.Errorf("stun: resolve local: %w", err)
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		// Fall back to an ephemeral port — still useful for IP discovery.
		conn, err = net.ListenUDP("udp4", nil)
		if err != nil {
			return "", fmt.Errorf("stun: listen: %w", err)
		}
	}
	defer conn.Close() //nolint:errcheck

	remote, err := net.ResolveUDPAddr("udp4", STUNServer)
	if err != nil {
		return "", fmt.Errorf("stun: resolve remote: %w", err)
	}

	// RFC 8489 Binding Request with a fresh random transaction ID.
	req, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return "", fmt.Errorf("stun: build request: %w", err)
	}

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	if _, err := conn.WriteToUDP(req.Raw, remote); err != nil {
		return "", fmt.Errorf("stun: write: %w", err)
	}

	// The answer is the response from the server with our transaction ID;
	// anything else on the socket (a spoofed or stale reply) is skipped
	// (RFC 8489 §6.3.1).
	server := remote.AddrPort()
	var buf [1500]byte
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			return "", fmt.Errorf("stun: read: %w", err)
		}
		if from.Addr().Unmap() != server.Addr().Unmap() || from.Port() != server.Port() {
			continue
		}
		addr, err := parseSTUNMappedAddr(buf[:n], req.TransactionID)
		if errors.Is(err, errSTUNOtherTransaction) {
			continue
		}
		return addr, err
	}
}

// GatherHostCandidates returns "ip:port" strings for every non-loopback IPv4
// address on the local machine.  These "host candidates" are directly reachable
// on the LAN without NAT traversal.
func GatherHostCandidates(port int) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d", ip.String(), port))
		}
	}
	return out
}

// errSTUNOtherTransaction: a well-formed STUN message for another request.
var errSTUNOtherTransaction = errors.New("stun: response for another transaction")

// parseSTUNMappedAddr extracts the IPv4 external address from the Binding
// Success Response to transaction txid. XOR-MAPPED-ADDRESS takes precedence
// over MAPPED-ADDRESS; a FINGERPRINT, when present, must match.
func parseSTUNMappedAddr(data []byte, txid [stun.TransactionIDSize]byte) (string, error) {
	m := &stun.Message{Raw: append([]byte(nil), data...)}
	if err := m.Decode(); err != nil {
		return "", fmt.Errorf("stun: %w", err)
	}
	if m.TransactionID != txid {
		return "", errSTUNOtherTransaction
	}
	if m.Type != stun.BindingSuccess {
		return "", fmt.Errorf("stun: unexpected response %s", m.Type)
	}
	if m.Contains(stun.AttrFingerprint) {
		if err := stun.Fingerprint.Check(m); err != nil {
			return "", fmt.Errorf("stun: %w", err)
		}
	}
	var ip net.IP
	var port int
	var xa stun.XORMappedAddress
	var ma stun.MappedAddress
	switch {
	case xa.GetFrom(m) == nil:
		ip, port = xa.IP, xa.Port
	case ma.GetFrom(m) == nil:
		ip, port = ma.IP, ma.Port
	default:
		return "", errors.New("stun: no mapped address found")
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("stun: mapped address %s is not IPv4", ip)
	}
	return fmt.Sprintf("%s:%d", ip.To4(), port), nil
}
