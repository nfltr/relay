// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nfltr/relay/proto/wire/turnwire"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
)

// ICEConfig is what a file transfer's WebRTC data path gathers with, the same
// ICE servers as a call: the STUN server ("host:port"; "" for none) and the
// TURN servers (relay-issued credentials or --turn).
type ICEConfig struct {
	STUN string
	TURN []turnwire.ICEServer

	// ipFilter, when set, keeps only the addresses it accepts as host
	// candidates (nil: every interface). A test on one machine keeps
	// loopback: with every interface (Docker bridges, VPNs, IPv6 privacy
	// addresses) ICE checks hundreds of pairs, which on a loaded machine
	// outlasts RTCWait (TestICEOnLoopbackConnectsWellWithinRTCWait).
	ipFilter func(net.IP) bool
}

// Data path names (the CLI's "data path:" line, the NAT lab's matrix).
const (
	pathWebRTC     = "webrtc" // the sender chose the data channel (FrameDataPath)
	PathHost       = "webrtc-host"
	PathSrflx      = "webrtc-srflx" // through a NAT mapping (srflx/prflx)
	PathTURN       = "webrtc-turn"  // a TURN relay candidate
	PathRelay      = "relay"        // the nfltr relay (ICE found no path, or --force-relay)
	dataChannelTag = "nfltr-file"
)

// RTCWait bounds how long the sender waits for the data channel to open
// before it falls back to the relay.
var RTCWait = 10 * time.Second

// Data channel flow control: writes go out in dcChunk messages, and pause
// while more than dcHigh bytes are queued until the queue drains to dcLow.
const (
	dcChunk = 32 << 10
	dcHigh  = 4 << 20
	dcLow   = 1 << 20
)

// DataPath is the conn a file transfer runs on and how it got there.
type DataPath struct {
	Conn net.Conn
	Path string // PathHost, PathSrflx, PathTURN or PathRelay
	Pair string // selected ICE candidate pair ("srflx -> prflx"); empty on the relay
}

// rtcSignal is a FrameRTC's Text on a file transfer's SignalConn.
type rtcSignal struct {
	SDP       *webrtc.SessionDescription `json:"sdp,omitempty"`
	Candidate *webrtc.ICECandidateInit   `json:"candidate,omitempty"`
}

// OpenDataPath races the direct TCP channel (tcp; nil for none) against a
// WebRTC data channel negotiated over sc, and returns a conn on whichever is
// ready first (TCP on a LAN, the data channel across NATs); when neither is
// within RTCWait, the relay stream's data conn. The initiator (the sender)
// chooses and tells the responder (FrameDataPath), which uses exactly that
// connection; the losing paths are closed. forceRelay skips both. sc keeps
// being read until it ends (late candidates), so the relay stream never
// stalls.
//
// sc must come from E2E.SignalConn: the returned conn is that E2E's Secure
// conn on the chosen path, so every path carries only ciphertext.
func OpenDataPath(ctx context.Context, sc *SignalConn, mux *RelayMux, ice ICEConfig, tcp *TCPDirect, initiator, forceRelay bool) (*DataPath, error) {
	if sc.e2e == nil {
		return nil, errors.New("p2p: a file transfer needs an end-to-end SignalConn (E2E.SignalConn)")
	}
	dp, err := openDataPath(ctx, sc, mux, ice, tcp, initiator, forceRelay)
	if err != nil {
		return nil, err
	}
	dp.Conn = sc.e2e.Secure(dp.Conn)
	return dp, nil
}

func openDataPath(ctx context.Context, sc *SignalConn, mux *RelayMux, ice ICEConfig, tcp *TCPDirect, initiator, forceRelay bool) (*DataPath, error) {
	s := &rtcSession{
		sc:      sc,
		ice:     ice,
		opened:  make(chan io.ReadWriteCloser, 1),
		failed:  make(chan struct{}),
		path:    make(chan string, 1),
		sigDone: make(chan struct{}),
	}
	relay := &DataPath{Conn: mux.DataConn(), Path: PathRelay}
	if initiator && forceRelay {
		go s.signalLoop()
		if err := sc.WriteFrame(&Frame{Type: FrameDataPath, Text: PathRelay}); err != nil {
			return nil, err
		}
		return relay, nil
	}
	if tcp != nil {
		s.startTCP(ctx, tcp)
	}
	if initiator {
		if err := s.offer(); err != nil {
			s.closePC()
			s.settleTCP("")
			return nil, err
		}
	}
	go s.signalLoop()
	if initiator {
		return s.choose(ctx, relay)
	}
	return s.follow(ctx, relay)
}

type rtcSession struct {
	sc  *SignalConn
	ice ICEConfig

	mu        sync.Mutex
	pc        *webrtc.PeerConnection
	dc        *webrtc.DataChannel
	remoteSet bool
	queued    []webrtc.ICECandidateInit

	opened   chan io.ReadWriteCloser
	failed   chan struct{}
	failOnce sync.Once
	path     chan string
	sigDone  chan struct{}

	tcp *tcpRace // nil when not racing the direct TCP channel
}

// rtcNetworkTypes are the kinds of ICE candidate gathered. A test that
// needs ICE to find no path gathers none (TCP without a TCP mux gives no
// candidate) rather than racing a short RTCWait against ICE on loopback.
var rtcNetworkTypes = []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6}

// newPC builds the peer connection and its pre-negotiated data channel (id 0
// on both sides, so neither waits for the other to announce it).
func (s *rtcSession) newPC() error {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes(rtcNetworkTypes)
	if s.ice.ipFilter != nil {
		se.SetIPFilter(s.ice.ipFilter)
	}
	se.SetICETimeouts(5*time.Second, 10*time.Second, 2*time.Second)
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled // PION_LOG_* still enables scopes
	se.LoggerFactory = lf
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{ICEServers: s.iceServers()})
	if err != nil {
		return fmt.Errorf("p2p: webrtc: %w", err)
	}
	negotiated, id := true, uint16(0)
	dc, err := pc.CreateDataChannel(dataChannelTag, &webrtc.DataChannelInit{Negotiated: &negotiated, ID: &id})
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("p2p: webrtc data channel: %w", err)
	}
	dc.OnOpen(func() {
		rwc, err := dc.Detach()
		if err != nil {
			s.fail()
			return
		}
		s.opened <- rwc
	})
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			init := c.ToJSON()
			s.send(rtcSignal{Candidate: &init})
		}
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed {
			s.fail()
		}
	})
	s.mu.Lock()
	s.pc, s.dc = pc, dc
	s.mu.Unlock()
	return nil
}

func (s *rtcSession) iceServers() []webrtc.ICEServer {
	var out []webrtc.ICEServer
	if s.ice.STUN != "" {
		out = append(out, webrtc.ICEServer{URLs: []string{"stun:" + s.ice.STUN}})
	}
	for _, t := range s.ice.TURN {
		out = append(out, webrtc.ICEServer{URLs: t.URLs, Username: t.Username, Credential: t.Credential})
	}
	return out
}

func (s *rtcSession) send(m rtcSignal) {
	b, _ := json.Marshal(m)
	_ = s.sc.WriteFrame(&Frame{Type: FrameRTC, Text: string(b)})
}

// fail marks the session failed (once): the sender falls back to the
// relay. allow:wrapper
func (s *rtcSession) fail() { s.failOnce.Do(func() { close(s.failed) }) }

func (s *rtcSession) closePC() {
	s.mu.Lock()
	pc := s.pc
	s.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (s *rtcSession) offer() error {
	if err := s.newPC(); err != nil {
		return err
	}
	offer, err := s.pc.CreateOffer(nil)
	if err == nil {
		err = s.pc.SetLocalDescription(offer)
	}
	if err != nil {
		return fmt.Errorf("p2p: webrtc offer: %w", err)
	}
	s.send(rtcSignal{SDP: &offer})
	return nil
}

// signalLoop applies the peer's SDP and candidates and records the sender's
// path choice, until sc ends.
func (s *rtcSession) signalLoop() {
	defer close(s.sigDone)
	for {
		f, err := s.sc.ReadFrame()
		if err != nil {
			return
		}
		switch f.Type {
		case FrameDataPath:
			select {
			case s.path <- f.Text:
			default:
			}
		case FrameRTC:
			var m rtcSignal
			if json.Unmarshal([]byte(f.Text), &m) != nil || s.applyRTC(m) != nil {
				s.fail()
			}
		}
	}
}

func (s *rtcSession) applyRTC(m rtcSignal) error {
	if m.SDP != nil {
		if m.SDP.Type == webrtc.SDPTypeOffer {
			if err := s.newPC(); err != nil {
				return err
			}
		}
		s.mu.Lock()
		pc := s.pc
		s.mu.Unlock()
		if pc == nil {
			return errors.New("p2p: webrtc answer before offer")
		}
		if err := pc.SetRemoteDescription(*m.SDP); err != nil {
			return err
		}
		if m.SDP.Type == webrtc.SDPTypeOffer {
			answer, err := pc.CreateAnswer(nil)
			if err == nil {
				err = pc.SetLocalDescription(answer)
			}
			if err != nil {
				return err
			}
			s.send(rtcSignal{SDP: &answer})
		}
		s.mu.Lock()
		s.remoteSet = true
		queued := s.queued
		s.queued = nil
		s.mu.Unlock()
		for _, c := range queued {
			_ = pc.AddICECandidate(c)
		}
	}
	if m.Candidate != nil {
		s.mu.Lock()
		pc, ready := s.pc, s.remoteSet
		if !ready {
			s.queued = append(s.queued, *m.Candidate) // before the SDP: keep it
		}
		s.mu.Unlock()
		if ready {
			_ = pc.AddICECandidate(*m.Candidate)
		}
	}
	return nil
}

// choose is the sender's decision: the first of the direct TCP channel and
// the data channel to be ready within RTCWait, else the relay.
func (s *rtcSession) choose(ctx context.Context, relay *DataPath) (*DataPath, error) {
	timer := time.NewTimer(RTCWait)
	defer timer.Stop()
	select {
	case c := <-s.tcpFirst():
		return s.chooseTCP(c)
	case rwc := <-s.opened:
		select { // both ready: TCP is the faster of the two
		case c := <-s.tcpFirst():
			_ = rwc.Close()
			return s.chooseTCP(c)
		default:
		}
		s.settleTCP("")
		if err := s.sc.WriteFrame(&Frame{Type: FrameDataPath, Text: pathWebRTC}); err != nil {
			_ = rwc.Close()
			s.closePC()
			return nil, err
		}
		return s.dcPath(rwc), nil
	case <-s.failed:
	case <-timer.C:
	case <-ctx.Done():
		s.closePC()
		s.settleTCP("")
		return nil, ctx.Err()
	}
	s.closePC()
	s.settleTCP("")
	if err := s.sc.WriteFrame(&Frame{Type: FrameDataPath, Text: PathRelay}); err != nil {
		return nil, err
	}
	return relay, nil
}

func (s *rtcSession) chooseTCP(c net.Conn) (*DataPath, error) {
	s.closePC()
	c = s.settleTCP(ConnID(c))
	if err := s.sc.WriteFrame(&Frame{Type: FrameDataPath, Text: pathTCPPrefix + ConnID(c)}); err != nil {
		c.Close() //nolint:errcheck
		return nil, err
	}
	return &DataPath{Conn: c, Path: PathTCP, Pair: "tcp"}, nil
}

// follow is the receiver: whatever path the sender chose.
func (s *rtcSession) follow(ctx context.Context, relay *DataPath) (*DataPath, error) {
	var choice string
	select {
	case choice = <-s.path:
	case <-s.sigDone:
		s.closePC()
		s.settleTCP("")
		return nil, errors.New("p2p: the sender left before choosing a data path")
	case <-ctx.Done():
		s.closePC()
		s.settleTCP("")
		return nil, ctx.Err()
	}
	if id, ok := strings.CutPrefix(choice, pathTCPPrefix); ok {
		s.closePC()
		if c := s.waitTCP(ctx, id); c != nil {
			return &DataPath{Conn: c, Path: PathTCP, Pair: "tcp"}, nil
		}
		return nil, errors.New("p2p: the sender chose the direct TCP channel but that connection is not here")
	}
	s.settleTCP("")
	if choice != pathWebRTC {
		s.closePC()
		return relay, nil
	}
	select {
	case rwc := <-s.opened:
		return s.dcPath(rwc), nil
	case <-s.failed:
	case <-time.After(RTCWait):
	case <-ctx.Done():
	}
	s.closePC()
	return nil, errors.New("p2p: the sender chose WebRTC but the data channel did not open here")
}

func (s *rtcSession) dcPath(rwc io.ReadWriteCloser) *DataPath {
	s.mu.Lock()
	pc, dc := s.pc, s.dc
	s.mu.Unlock()
	p := &DataPath{Path: PathHost}
	local, remote := "webrtc-local", "webrtc-peer"
	if pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair(); err == nil && pair != nil {
		p.Path = pathName(pair.Local.Typ, remoteType(*pair.Remote))
		p.Pair = pair.Local.Typ.String() + " -> " + pair.Remote.Typ.String()
		local = fmt.Sprintf("%s:%d", pair.Local.Address, pair.Local.Port)
		remote = fmt.Sprintf("%s:%d", pair.Remote.Address, pair.Remote.Port)
	}
	p.Conn = newDCConn(rwc, dc, pc, local, remote)
	return p
}

// remoteType is c's type, except that a peer-reflexive candidate at a
// link-local address or at one of this machine's own addresses is a host
// one: no NAT or router forwards link-local traffic, and a check from an
// address of this machine never crossed one. ICE learns a peer socket as
// prflx when a check arrives from an address it never signaled, as pion's
// link-local IPv6 host sockets on one machine do, and a multi-homed
// machine's sockets do when the kernel picks another source address than
// the candidate's (a check to 172.17.0.1 leaving from eth0's address).
func remoteType(c webrtc.ICECandidate) webrtc.ICECandidateType {
	if a, err := netip.ParseAddr(c.Address); err == nil && c.Typ == webrtc.ICECandidateTypePrflx && (a.IsLinkLocalUnicast() || isLocalAddr(a)) {
		return webrtc.ICECandidateTypeHost
	}
	return c.Typ
}

// isLocalAddr reports whether a is assigned to one of this machine's
// interfaces.
func isLocalAddr(a netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	for _, ia := range addrs {
		if n, ok := ia.(*net.IPNet); ok {
			if b, ok := netip.AddrFromSlice(n.IP); ok && b.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// pathName classifies a selected candidate pair.
func pathName(local, remote webrtc.ICECandidateType) string {
	switch {
	case local == webrtc.ICECandidateTypeRelay || remote == webrtc.ICECandidateTypeRelay:
		return PathTURN
	case local == webrtc.ICECandidateTypeHost && remote == webrtc.ICECandidateTypeHost:
		return PathHost
	default:
		return PathSrflx
	}
}

// dcConn is a byte stream (net.Conn) on a detached data channel, so the
// existing transfer code runs on it unchanged.
type dcConn struct {
	rwc   io.ReadWriteCloser
	w     *chunkWriter
	pc    *webrtc.PeerConnection
	rbuf  []byte
	rest  []byte
	once  sync.Once
	local dcAddr
	peer  dcAddr
}

func newDCConn(rwc io.ReadWriteCloser, dc *webrtc.DataChannel, pc *webrtc.PeerConnection, local, remote string) *dcConn {
	low := make(chan struct{}, 1)
	dc.SetBufferedAmountLowThreshold(dcLow)
	dc.OnBufferedAmountLow(func() {
		select {
		case low <- struct{}{}:
		default:
		}
	})
	c := &dcConn{
		rwc:   rwc,
		pc:    pc,
		rbuf:  make([]byte, 64<<10),
		local: dcAddr(local),
		peer:  dcAddr(remote),
		w: &chunkWriter{
			send:     func(b []byte) error { _, err := rwc.Write(b); return err },
			buffered: dc.BufferedAmount,
			low:      low,
			done:     make(chan struct{}),
			chunk:    dcChunk,
			high:     dcHigh,
		},
	}
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			_ = c.Close() // a dead path fails the transfer (no resume)
		}
	})
	return c
}

func (c *dcConn) Read(p []byte) (int, error) {
	if len(c.rest) == 0 {
		n, err := c.rwc.Read(c.rbuf)
		if err != nil {
			return 0, err
		}
		c.rest = c.rbuf[:n]
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// Write sends b in chunks with back-pressure (net.Conn). allow:wrapper
func (c *dcConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func (c *dcConn) Close() error {
	c.once.Do(func() {
		close(c.w.done)
		_ = c.rwc.Close()
		_ = c.pc.Close()
	})
	return nil
}

func (c *dcConn) LocalAddr() net.Addr                { return c.local }
func (c *dcConn) RemoteAddr() net.Addr               { return c.peer }
func (c *dcConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dcConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dcConn) SetWriteDeadline(_ time.Time) error { return nil }

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
