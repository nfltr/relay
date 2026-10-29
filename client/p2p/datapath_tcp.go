// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"net"
	"time"
)

// PathTCP is a file transfer on the direct TCP channel (same mutual HMAC and
// encryption as before WebRTC): the fast path on a LAN.
const PathTCP = "tcp-direct"

// pathTCPPrefix announces the TCP path with the chosen connection's ConnID
// ("tcp:<id>"), so the receiver uses exactly that connection.
const pathTCPPrefix = "tcp:"

// TCPDirect is the direct TCP channel a file transfer races against WebRTC:
// this side's listener (from ListenHostCandidates), the peer's candidates, and
// the session's token and ID. nil: no race (--force-relay, or the peer sent
// no candidates).
type TCPDirect struct {
	Listener   *net.TCPListener
	Candidates []string
	Token      []byte
	SessionID  string
}

// tcpRace holds every connection the direct channel authenticated, keyed by
// ConnID, until a path is chosen.
type tcpRace struct {
	cancel func()
	conns  map[string]net.Conn // nil once settled
	first  chan net.Conn       // the first authenticated connection (sender)
	added  chan struct{}       // a connection arrived (receiver's wait)
}

// startTCP dials and accepts the direct channel in the background.
func (s *rtcSession) startTCP(ctx context.Context, d *TCPDirect) {
	tctx, cancel := context.WithCancel(ctx)
	s.tcp = &tcpRace{cancel: cancel, conns: map[string]net.Conn{}, first: make(chan net.Conn, 1), added: make(chan struct{}, 1)}
	go dialAndAccept(tctx, d.Listener, d.Candidates, d.Token, d.SessionID, func(c net.Conn) {
		s.mu.Lock()
		if s.tcp.conns == nil {
			s.mu.Unlock()
			c.Close() //nolint:errcheck // a path is already chosen
			return
		}
		s.tcp.conns[ConnID(c)] = c
		s.mu.Unlock()
		select {
		case s.tcp.first <- c:
		default:
		}
		select {
		case s.tcp.added <- struct{}{}:
		default:
		}
	})
}

// tcpFirst is the sender's ready signal (nil channel when not racing TCP).
func (s *rtcSession) tcpFirst() <-chan net.Conn {
	if s.tcp == nil {
		return nil
	}
	return s.tcp.first
}

// settleTCP ends the race: it stops dialing and closes every connection but
// keep (a ConnID; "" closes all), which it returns.
func (s *rtcSession) settleTCP(keep string) net.Conn {
	if s.tcp == nil {
		return nil
	}
	s.tcp.cancel()
	s.mu.Lock()
	conns := s.tcp.conns
	s.tcp.conns = nil
	s.mu.Unlock()
	var kept net.Conn
	for id, c := range conns {
		if id == keep && keep != "" {
			kept = c
			continue
		}
		c.Close() //nolint:errcheck
	}
	return kept
}

// waitTCP is the receiver: the connection the sender chose, which its own
// handshake completes at the same moment (both sides verify each other).
func (s *rtcSession) waitTCP(ctx context.Context, id string) net.Conn {
	if s.tcp == nil {
		return nil
	}
	timeout := time.After(RTCWait)
	for {
		s.mu.Lock()
		_, ok := s.tcp.conns[id]
		s.mu.Unlock()
		if ok {
			return s.settleTCP(id)
		}
		select {
		case <-s.tcp.added:
		case <-timeout:
			s.settleTCP("")
			return nil
		case <-ctx.Done():
			s.settleTCP("")
			return nil
		}
	}
}
