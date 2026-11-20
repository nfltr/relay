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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
)

// DirectMode is a service's (or a client's) direct-path setting. The
// caller resolves an unset setting (nfltr: on in organisation mode, owner
// 2026-11-16 "direct is always preferred and relay is when direct not
// possible"); this package takes the mode it is given.
type DirectMode string

const (
	// DirectOff: relayed only, never a candidate sent: the one opt-out,
	// which keeps this machine's addresses from its peers.
	DirectOff DirectMode = ""
	// DirectOn: every candidate this machine has: the public (reflexive,
	// QAD) address, a port-mapped one and the interface addresses (host
	// candidates). Only the organisation peer of the control session sees
	// them; the punch keeps a LAN path first (DirectEndpoint.punch).
	DirectOn DirectMode = "on"
)

// ParseDirectMode reads a mode: "", "off", "false" (off), "on", "true".
// "public" was removed (2026-11-16): every direct path tries the LAN.
func ParseDirectMode(s string) (DirectMode, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", "off", "false":
		return DirectOff, nil
	case "on", "true":
		return DirectOn, nil
	case "public":
		return DirectOff, errors.New(`direct "public" was removed (2026-11-16): want on or off`)
	}
	return DirectOff, fmt.Errorf("direct %q: want on or off", s)
}

// DirectServiceName is the reserved service every agent with a direct
// service serves (organisation mode, the direct services' groups): the
// control sessions that carry candidates, and the relayed re-attaches of a
// session whose direct path died. The design's "_direct" is no valid
// service name on the wire (agentservices.ValidName), hence this one; a
// service of the table may not take it.
const DirectServiceName = "nfltr-direct"

// directControlMark is the first byte of a control exchange on a direct
// service's own route (a group dial's first exchange toward an instance,
// whose agent's name the client does not know yet: nfltr
// docs/decisions/service-discovery-2026-11-12.md "Direct paths under a
// group dial"): neither a TLS record (tlsRecordHandshake) nor a path
// frame. The exchange's TLS follows, bound as the route's sessions.
const directControlMark = 'C'

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
	pc net.PacketConn
	tr *quic.Transport
	// loopback admits loopback candidates (tests on one machine); else a
	// peer could aim this machine's probes and punches at its own
	// loopback services.
	loopback bool
	probes   probeWaiters              // the tagged probes' readers (direct_prflx.go)
	pm       portMap                   // the gateway's mapping of the socket (direct_portmap.go)
	lan      func(netip.AddrPort) bool // tests: which candidates are LAN ones (nil: isLAN)
	noHost   bool                      // tests: no host candidates (the reflexive one only)
	hosts    []netip.AddrPort          // tests: the host candidates (nil: the interfaces')
	grace    time.Duration             // tests: the LAN grace (0: lanGrace)
	gateway  func() (net.IP, error)    // tests: the LAN gateway (nil: discoverGateway, which only init sets)
	natpmp   int                       // tests: the gateway's NAT-PMP port (0: natpmpPort), a fake gateway's own
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

// Close deletes the port mapping, if any, and closes the socket: the
// Transport, then the UDP socket it was given (a quic.Transport closes only
// a socket it opened itself).
func (e *DirectEndpoint) Close() error {
	e.unmap()
	err := e.tr.Close()
	if cerr := e.pc.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
		err = errors.Join(err, cerr)
	}
	return err
}

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
	return e.candidate(string(b))
}

// gather is this end's candidates, trickled (RFC 8838; nfltr
// docs/decisions/direct-paths-2026-11-11.md "Trickle", spec/DirectPunch.tla
// NoWait): first the host candidates at once (with none, the first slow
// source's answer), late each later slow source's answer as it comes (the
// relay's address check, up to 3 s; the port mapping, up to 500 ms),
// closed once every source ended. first is empty only when every source
// ended with none; it leaves room for one candidate per slow source
// within MaxCandidates.
func (e *DirectEndpoint) gather(slow ...func() []netip.AddrPort) (first []netip.AddrPort, late <-chan []netip.AddrPort) {
	ch := make(chan []netip.AddrPort, len(slow))
	var wg sync.WaitGroup
	for _, f := range slow {
		wg.Go(func() {
			if a := f(); len(a) > 0 {
				ch <- a
			}
		})
	}
	go func() { wg.Wait(); close(ch) }()
	// Room kept for the slow ones, which once led the list: a machine
	// with many interface addresses still sends its reflexive one.
	first = e.hostCandidates()
	first = first[:min(len(first), quiclink.MaxCandidates-len(slow))]
	for len(first) == 0 {
		a, ok := <-ch
		if !ok {
			break
		}
		first = a
	}
	return compactCandidates(first), ch
}

// mappedSource is the port mapping as a slow source of gather.
func (e *DirectEndpoint) mappedSource() []netip.AddrPort {
	if a := <-e.mapping(); a.IsValid() {
		return []netip.AddrPort{a}
	}
	return nil
}

// sendLate writes late's candidates on a control exchange, one
// directCandidates line each, none sent before (sent: the first line's),
// MaxCandidates in all; it ends with late or the first failed write (the
// exchange ended).
func sendLate(w io.Writer, sent []netip.AddrPort, late <-chan []netip.AddrPort) {
	enc := json.NewEncoder(w)
	sent = slices.Clone(sent)
	for as := range late {
		var out directCandidates
		for _, a := range as {
			if !slices.Contains(sent, a) && len(sent) < quiclink.MaxCandidates {
				sent = append(sent, a)
				out.Candidates = append(out.Candidates, a.String())
			}
		}
		if len(out.Candidates) > 0 && enc.Encode(out) != nil {
			return
		}
	}
}

// readLate reads the peer's later candidates lines on a control exchange
// and hands each new candidate to add, until r ends.
func (e *DirectEndpoint) readLate(r *bufio.Reader, add func(netip.AddrPort)) {
	for {
		var c directCandidates
		if readJSONLine(r, &c) != nil {
			return
		}
		as, err := e.candidates(c.Candidates)
		if err != nil {
			return
		}
		for _, a := range as {
			add(a)
		}
	}
}

// hostCandidates are this machine's interface addresses on the socket's
// port (DirectOn only): global and private unicast, no loopback.
func (e *DirectEndpoint) hostCandidates() []netip.AddrPort {
	if e.hosts != nil {
		return e.hosts
	}
	ua, ok := e.pc.LocalAddr().(*net.UDPAddr)
	if !ok || e.noHost {
		return nil
	}
	port := uint16(ua.Port) // #nosec G115 -- a UDP port
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

// candidate reads one candidate: a unicast address (global or private;
// loopback only with e.loopback) and a port.
func (e *DirectEndpoint) candidate(s string) (netip.AddrPort, error) {
	a, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("candidate %q: %w", s, err)
	}
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	if a.Port() == 0 || !(a.Addr().IsGlobalUnicast() || e.loopback && a.Addr().IsLoopback()) {
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
	heard      *atomic.Bool // set by its first byte read (nil: none kept)
	end        *streamEnd   // told the read error that ended it (nil: none)
}

func (s pathStream) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if s.recv != nil {
		s.recv.Add(uint64(n)) // #nosec G115 -- n >= 0
	}
	if n > 0 && s.heard != nil {
		s.heard.Store(true)
	}
	if err != nil && s.end != nil {
		if f := s.end.fn.Load(); f != nil {
			(*f)(err)
		}
	}
	return n, err
}

// streamEnd is a stream's end hook: fn, once set, is called with the read
// error that ended the stream, before the path layer reads it.
type streamEnd struct{ fn atomic.Pointer[func(error)] }

func (e *streamEnd) set(fn func(error)) { e.fn.Store(&fn) }

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

// peekConn replays the byte peekFirst read, then reads the conn itself
// (no buffer on the session's data path).
type peekConn struct {
	net.Conn
	first []byte
}

// CloseWriteSync is the session's (a relayed link session's: TLS on it
// syncs its end through it, tlsend.Conn.CloseWriteSync); nil on a conn
// without one.
func (c *peekConn) CloseWriteSync() error {
	if s, ok := c.Conn.(interface{ CloseWriteSync() error }); ok {
		return s.CloseWriteSync()
	}
	return nil
}

func (c *peekConn) Read(p []byte) (int, error) {
	if len(c.first) > 0 && len(p) > 0 {
		n := copy(p, c.first)
		c.first = c.first[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite and Reset are the conn's (tlsend resets a link session with
// its Reset, link's Abort), as pathStream's.
func (c *peekConn) CloseWrite() error { return pathStream{Conn: c.Conn}.CloseWrite() }
func (c *peekConn) Reset() error      { return pathStream{Conn: c.Conn}.Reset() }

// peekFirst reads s's first byte (bounded by d) and returns s with it put
// back.
func peekFirst(s net.Conn, d time.Duration) (byte, net.Conn, error) {
	_ = s.SetReadDeadline(time.Now().Add(d))
	var b [1]byte
	_, err := io.ReadFull(s, b[:])
	_ = s.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, nil, err
	}
	return b[0], &peekConn{Conn: s, first: b[:]}, nil
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

// Close ends this end's reading (a Read waiting on another goroutine
// returns net.ErrClosed at once: TestPSConnCloseWakesARead) and its
// direction (END), and returns once the peer acknowledged every byte and
// the END: a caller that ends the stream under it or exits right after
// Close loses none of them (TestPSConnCloseDeliversTheTail). When the
// session fails first, nothing is heard from the peer for
// pathswitch.Config.Linger (it is gone: TestPSConnCloseGonePeerWithinLinger),
// nothing is acknowledged for pathswitch.Config.Detach while the peer
// keeps answering (WaitAcked's progress rule: a broken or hostile peer
// holds no Close longer; link spec/RelayedClose.tla, mutant
// liveness-counts-as-progress) or psCloseBound passes, it resets the session and returns an error: the
// peer may not hold them (TestPSConnCloseReportsAnUnackedEnd). Then, in
// the background, pathswitch's Close waits for the peer's end (crypto/tls
// sends close_notify above but never ends the stream under it, so each
// end's Close ends its direction; the peer's bytes are taken and dropped
// meanwhile) and ends the session cleanly, or resets it once the peer is
// silent for its Linger.
func (c *psConn) Close() error {
	_ = c.CloseRead()
	_ = c.CloseWrite()
	if !c.WaitAcked(c.Written()+1, psCloseBound) { // +1: the END
		c.Abort()
		return fmt.Errorf("close: the peer did not acknowledge the stream's end: %w", pathswitch.ErrReset)
	}
	go func() { _ = c.Conn.Close() }()
	return nil
}

// psCloseBound: how long Close waits for the peer to acknowledge its end
// while acknowledgements keep advancing: a full window (tcpDataWindow,
// 16 MiB) at 256 kbit/s. A gone peer ends the wait at Linger, one that
// acknowledges nothing at Detach; a 30 s bound on the whole wait reset
// a lossy direct session still delivering its tail (lane DIRECTCLOSE:
// net-100mbit-150ms-loss1-direct, 4 MiB took 33 s).
const psCloseBound = 10 * time.Minute

func (c *psConn) LocalAddr() net.Addr  { return c.first.LocalAddr() }
func (c *psConn) RemoteAddr() net.Addr { return c.first.RemoteAddr() }

// Reset: the session's reset (tlsend.Conn.Reset closes its raw conn
// without close_notify). It returns once the peer has the ABORT (the
// session's end), at most psResetBound: a caller that exits right after
// it still resets its peer, which otherwise read the stream's end as a
// lost path and failed only at its detach bound
// (TestPSConnResetReachesAPeerBeforeExit).
func (c *psConn) Reset() error {
	c.Abort()
	t := time.NewTimer(psResetBound)
	defer t.Stop()
	select {
	case <-c.Done():
	case <-t.C:
	}
	return nil
}

// psResetBound: how long Reset waits for the peer to take the ABORT.
const psResetBound = 2 * time.Second

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
