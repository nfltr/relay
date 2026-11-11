// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Direct paths (nfltr docs/decisions/direct-paths-2026-11-11.md, lanes
// DIRECTPATH and DIRECTPATH3): an organisation-mode tcp session moves
// between the relayed path and a QUIC connection straight between its two
// machines, under its own end-to-end TLS (link pathswitch, checked as link
// spec/DirectPath.tla). This file holds what both ends share: the
// process's UDP socket (DirectEndpoint), QAD, the path token and the path
// streams. direct_server.go is the agent's half, direct_client.go the
// client's. Whether a session asks for a direct path is in band: its
// relayed stream starts with a TLS record (no) or a pathswitch frame (yes).

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/quic-go"
)

// DirectMode is a service's (or a client's) direct-path setting
// (direct-paths doc O1: opt-in at both ends).
type DirectMode string

const (
	// DirectOff: relayed only, never a candidate sent (the default).
	DirectOff DirectMode = ""
	// DirectOn: the public (reflexive, QAD) address only.
	DirectOn DirectMode = "on"
	// DirectLAN: also this machine's interface addresses (host candidates).
	DirectLAN DirectMode = "lan"
)

// ParseDirectMode reads a mode: "", "off", "false" (off), "on", "true",
// "lan".
func ParseDirectMode(s string) (DirectMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "false":
		return DirectOff, nil
	case "on", "true":
		return DirectOn, nil
	case "lan":
		return DirectLAN, nil
	}
	return DirectOff, fmt.Errorf("direct %q: want on, off or lan", s)
}

// DirectServiceName is the reserved service every agent with a direct
// service serves (organisation mode, the direct services' groups): the
// control sessions that carry candidates, and the relayed re-attaches of a
// session whose direct path died. The design's "_direct" is no valid
// service name on the wire (agentservices.ValidName), hence this one; a
// service of the table may not take it.
const DirectServiceName = "nfltr-direct"

// QADALPN is the relay's address answer (relay-core core/session/qad.go).
const QADALPN = "nfltr-qad/1"

// Path names, as events and status show them.
const (
	PathRelayed = "relayed"
	PathDirect  = "direct"
)

// directLiveness: a direct connection is dead after 1.5 s + 3 s of
// silence (link.LivenessFast), then the session falls back to the relay.
const directKeepAlive = 1500 * time.Millisecond

// tlsRecordHandshake is the first byte of a TLS ClientHello: a session
// that starts with it asked for no direct path.
const tlsRecordHandshake = 0x16

// DirectEndpoint is a process's one UDP socket for direct paths: the
// agent link's QUIC connection to the relay (QUICDialer.Transport), QAD
// and the direct connections share it, so the NAT mapping QAD reports is
// the one a punch uses.
type DirectEndpoint struct {
	pc *net.UDPConn
	tr *quic.Transport
}

// NewDirectEndpoint opens the socket on an ephemeral port.
func NewDirectEndpoint() (*DirectEndpoint, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("direct paths: udp socket: %w", err)
	}
	return &DirectEndpoint{pc: pc, tr: &quic.Transport{Conn: pc}}, nil
}

// Transport is the socket's quic.Transport.
func (e *DirectEndpoint) Transport() *quic.Transport { return e.tr }

// Close closes the socket.
func (e *DirectEndpoint) Close() error { return e.tr.Close() }

// QAD asks the relay at addr (its agent link's UDP port) for this
// socket's address as it sees it: a candidate, never more (the relay's
// word). tc is the relay's TLS (its certificate checked as for the agent
// link).
func (e *DirectEndpoint) QAD(ctx context.Context, addr string, tc *tls.Config) (netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	tc = tc.Clone()
	tc.NextProtos = []string{QADALPN}
	q, err := e.tr.Dial(ctx, ua, tc, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("qad: %w", err)
	}
	defer q.CloseWithError(0, "") //nolint:errcheck
	s, err := q.AcceptUniStream(ctx)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("qad: %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(s, 64))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("qad: %w", err)
	}
	return parseCandidate(string(b))
}

// hostCandidates are this machine's interface addresses on the socket's
// port (DirectLAN only): global and private unicast, no loopback.
func (e *DirectEndpoint) hostCandidates() []netip.AddrPort {
	port := uint16(e.pc.LocalAddr().(*net.UDPAddr).Port) // #nosec G115 -- a UDP port
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr().Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	return out
}

// candidateAddr is an address a candidate may name: unicast, never
// loopback (a test's seam).
var candidateAddr = func(a netip.Addr) bool { return a.IsGlobalUnicast() || a.IsPrivate() }

// parseCandidate reads one candidate: a unicast address and a port.
func parseCandidate(s string) (netip.AddrPort, error) {
	a, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("candidate %q: %w", s, err)
	}
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	if a.Port() == 0 || !candidateAddr(a.Addr()) {
		return netip.AddrPort{}, fmt.Errorf("candidate %q: not a unicast address and port", s)
	}
	return a, nil
}

// Path token (e2ee_tcp.pv tokC, tokS, tokR): an HMAC keyed with an
// exporter of the session's TLS (BIND:direct.token) over the sender's role
// (BIND:direct.role), the attach's epoch (BIND:direct.epoch) and, on a
// direct connection, an exporter of that QUIC connection's TLS
// (BIND:direct.quic; empty on a relayed re-attach, the model's tokR).
const (
	directSessionLabel = "EXPORTER-nfltr-direct-session"
	directQUICLabel    = "EXPORTER-nfltr-direct-quic"
	directKeyLen       = 32
	roleClient         = 'C'
	roleServer         = 'S'
)

// sessionKey is the session's exporter: the token's key.
func sessionKey(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(directSessionLabel, nil, directKeyLen)
}

// quicKey is a direct connection's exporter.
func quicKey(q *quic.Conn) ([]byte, error) {
	cs := q.ConnectionState().TLS
	return cs.ExportKeyingMaterial(directQUICLabel, nil, directKeyLen)
}

// pathToken is a token of role for epoch, bound to the direct connection
// whose exporter is qk (nil: a relayed stream).
func pathToken(key []byte, role byte, epoch uint64, qk []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte{role})
	m.Write(binary.AppendUvarint(nil, epoch))
	m.Write(qk)
	return m.Sum(nil)
}

// pathStream is a path stream over a net.Conn (a relayed link session, a
// gRPC stream's session, a QUIC stream of a quiclink Node): its Reset is
// the conn's own (link's Abort, a QUIC stream's cancel) where it has one,
// else a Close. Bytes are counted per path (the client's metrics).
type pathStream struct {
	net.Conn
	sent, recv *atomic.Uint64
}

func (s pathStream) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if s.recv != nil {
		s.recv.Add(uint64(n)) // #nosec G115 -- n >= 0
	}
	return n, err
}

func (s pathStream) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p)
	if s.sent != nil {
		s.sent.Add(uint64(n)) // #nosec G115 -- n >= 0
	}
	return n, err
}

func (s pathStream) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return s.Conn.Close()
}

func (s pathStream) Reset() error {
	if r, ok := s.Conn.(interface{ Reset() error }); ok {
		return r.Reset()
	}
	return s.Conn.Close()
}

// peekConn replays the byte peekFirst read.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// peekFirst reads s's first byte (bounded by d) and returns s with it put
// back.
func peekFirst(s net.Conn, d time.Duration) (byte, net.Conn, error) {
	_ = s.SetReadDeadline(time.Now().Add(d))
	r := bufio.NewReaderSize(s, 512)
	b, err := r.Peek(1)
	_ = s.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, nil, err
	}
	return b[0], peekConn{s, r}, nil
}

// psConn is a pathswitch Conn as the net.Conn crypto/tls runs on. A read
// deadline (SetDeadline, SetReadDeadline: the agent's handshake bound)
// resets the session when it passes; write deadlines are ignored
// (crypto/tls sets one to now after its close_notify, which must still
// go out). Reset is the session's reset. first is the first stream, for
// the addresses.
type psConn struct {
	*pathswitch.Conn
	first    net.Conn
	deadline atomic.Pointer[time.Timer]
}

func newPSConn(c *pathswitch.Conn, first net.Conn) *psConn { return &psConn{Conn: c, first: first} }

// Close ends the session in the background: this end's END, then the
// peer's awaited (crypto/tls sends close_notify above but never ends the
// stream under it, so each end's Close ends its direction), then
// pathswitch's clean Close; a peer that does not end within the detach
// bound gets a reset.
func (c *psConn) Close() error {
	go func() {
		_ = c.CloseWrite()
		t := time.AfterFunc(psCloseBound, c.Abort)
		defer t.Stop()
		_, _ = io.Copy(io.Discard, c.Conn)
		_ = c.Conn.Close()
	}()
	return nil
}

// psCloseBound: how long a closed session waits for its peer's end.
const psCloseBound = 30 * time.Second

func (c *psConn) LocalAddr() net.Addr  { return c.first.LocalAddr() }
func (c *psConn) RemoteAddr() net.Addr { return c.first.RemoteAddr() }

// Reset: the session's reset (tlsend.Conn.Reset closes its raw conn
// without close_notify).
func (c *psConn) Reset() error { c.Abort(); return nil }

func (c *psConn) SetDeadline(t time.Time) error {
	var nt *time.Timer
	if !t.IsZero() {
		nt = time.AfterFunc(time.Until(t), c.Abort)
	}
	if old := c.deadline.Swap(nt); old != nil {
		old.Stop()
	}
	return nil
}
func (c *psConn) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *psConn) SetWriteDeadline(time.Time) error  { return nil }

// errDirectRefused: a direct path refused by its binding check.
var errDirectRefused = errors.New("direct path refused")
