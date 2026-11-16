// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

// The agent's side of an nf1 address's direct path for browser visitors
// (nfltr docs/decisions/browser-peer-2026-11-16.md section 2, "BP3 wire";
// spec/BrowserPeer.tla, spec/proverif/browser_peer.pv). A control session
// is an nf1 session over the relay's WebSocket whose answer said HintBrowser
// and whose first byte was the visitor's mark (client/agent direct_nf1.go):
// once Admit took its proof, the visitor's SDP offer and the agent's answer
// travel inside its TLS (BIND:browser.signal), and the agent holds one
// RTCPeerConnection for it. Each data channel is a stream: its own nf1
// session (answer, pinned TLS, proof) before one byte reaches the service
// (BIND:browser.dc.nf1); DTLS is transport only. A stream never changes
// path: when the connection goes, its streams fail. The agent closes the
// connection and its channels when the control session ends or the
// connection fails.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/client/nf1"
	"github.com/pion/datachannel"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
)

// Browser direct path limits (the decision's section 5).
const (
	// BrowserMaxDC bounds a connection's data channels at once (MaxDC 0).
	BrowserMaxDC = 16
	// BrowserMaxPeers bounds a BrowserDirect's connections at once
	// (MaxPeers 0): one per admitted control session.
	BrowserMaxPeers = 8
	// BrowserMaxSignal bounds one SDP message on the control session.
	BrowserMaxSignal = 16 << 10
	// BrowserDCLabel is the label of a stream's data channel (ordered,
	// reliable); a channel of another label or kind is closed.
	BrowserDCLabel = "nf1"
	// BrowserMaxMessage is the largest data channel message the agent
	// takes (its answer's a=max-message-size).
	BrowserMaxMessage = 64 << 10
)

// Bounds of a control session's exchange: the visitor's offer after Admit,
// and the agent's ICE gathering before its answer.
var (
	browserOfferWait = 10 * time.Second
	browserGather    = 5 * time.Second
)

// BrowserDirect serves the direct path of one nf1 service's browser
// visitors (client/agent Service.BrowserDirect). Its zero value serves with
// the default caps and host candidates only. Safe for concurrent use.
type BrowserDirect struct {
	// STUN is the STUN server ("host:port") the agent gathers a
	// server-reflexive candidate with, named in its answer; "" for none.
	// No TURN: the WebSocket is the relayed path.
	STUN string
	// MaxDC bounds each connection's data channels at once (0:
	// BrowserMaxDC); a channel past it is closed and the visitor opens
	// the stream on the WebSocket.
	MaxDC int
	// MaxPeers bounds the connections at once (0: BrowserMaxPeers); a
	// control session past it gets an empty answer (no direct path now).
	MaxPeers int

	peers  atomic.Int32
	offers atomic.Int64 // connections made (tests: none without Admit)

	ipFilter func(net.IP) bool // tests: loopback only
}

// ServeBrowser serves ctl, a control session whose answer the listener l
// wrote and whose mark was read: Admit, the SDP exchange, then the
// connection until ctl ends or the connection fails. serve gets each data
// channel's admitted nf1 session and serves it (dials the target and
// joins); it closes tc. ServeBrowser returns once ctl, the connection and
// every stream ended; it closes ctl.
func (b *BrowserDirect) ServeBrowser(ctx context.Context, ctl net.Conn, l *nf1.Listener, serve func(ctx context.Context, tc net.Conn)) {
	maxDC := b.MaxDC
	if maxDC <= 0 {
		maxDC = BrowserMaxDC
	}
	p := &browserPeer{b: b, l: l, serve: serve, ctx: ctx, maxDC: maxDC, ctl: ctl, dcs: map[int]*bpConn{}, tr: newBPTrace(maxDC)}
	p.run(ctx)
}

func (b *BrowserDirect) take() bool {
	maxPeers := int32(b.MaxPeers) // #nosec G115 -- a small cap
	if maxPeers <= 0 {
		maxPeers = BrowserMaxPeers
	}
	if b.peers.Add(1) > maxPeers {
		b.peers.Add(-1)
		return false
	}
	return true
}

// browserPeer is one control session and its connection. mu orders the
// agent's steps; each step's trace line is written under it
// (spec/TraceBrowserPeer.tla).
type browserPeer struct {
	b     *BrowserDirect
	l     *nf1.Listener
	serve func(context.Context, net.Conn)
	ctx   context.Context
	maxDC int
	ctl   net.Conn
	tr    *bpTrace

	mu    sync.Mutex
	pc    *webrtc.PeerConnection
	held  bool   // the agent holds pc (BrowserPeer.tla agentPC = "held")
	state string // pc: "", "connecting", "up", "failed", "closed"
	ended bool   // the control session ended
	dcs   map[int]*bpConn
	next  int // the last stream's number
	wg    sync.WaitGroup
}

func (p *browserPeer) run(ctx context.Context) {
	defer p.tr.close()
	defer p.wg.Wait()
	defer p.end()
	p.step("CtlOpen", 0)
	hctx, cancel := context.WithTimeout(ctx, nf1.HandshakeTimeout)
	_ = p.ctl.SetDeadline(time.Now().Add(nf1.HandshakeTimeout))
	tc, err := p.l.Admit(hctx, p.ctl)
	cancel()
	if err != nil {
		return
	}
	p.step("CtlAdmit", 0)
	stop := context.AfterFunc(ctx, func() { _ = p.ctl.Close() })
	defer stop()
	_ = tc.SetDeadline(time.Now().Add(browserOfferWait))
	offer, err := readSignal(tc)
	if err != nil || offer == nil || offer.Type != webrtc.SDPTypeOffer {
		return
	}
	if !p.b.take() {
		_ = writeSignal(tc, nil) // no direct path now: the visitor stays on the WebSocket
		return
	}
	defer p.b.peers.Add(-1)
	answer, err := p.answer(*offer)
	if err != nil || writeSignal(tc, answer) != nil {
		return
	}
	// The control session holds the connection: its end, or any byte
	// (one connection per control session), ends it.
	_ = tc.SetDeadline(time.Time{})
	var x [1]byte
	_, _ = tc.Read(x[:])
}

// step writes one trace line under mu.
func (p *browserPeer) step(ev string, s int) {
	p.mu.Lock()
	p.tr.emit(ev, s)
	p.mu.Unlock()
}

// end is the control session's end (CtlEnd) and, while the agent holds
// the connection, its reap.
func (p *browserPeer) end() {
	_ = p.ctl.Close()
	p.mu.Lock()
	p.ended = true
	p.tr.emit("CtlEnd", 0)
	closers := p.reapLocked()
	p.mu.Unlock()
	closers()
}

// reapLocked is Reap when the agent holds the connection: the connection
// and its data channels closed (by the returned func, outside mu).
func (p *browserPeer) reapLocked() func() {
	if !p.held {
		return func() {}
	}
	p.held = false
	if p.state != "failed" {
		p.state = "closed"
	}
	p.tr.emit("Reap", 0)
	conns := make([]*bpConn, 0, len(p.dcs))
	for _, c := range p.dcs {
		conns = append(conns, c)
	}
	clear(p.dcs)
	pc := p.pc
	return func() {
		for _, c := range conns {
			_ = c.Close()
		}
		_ = pc.Close()
	}
}

// answer creates the connection for the visitor's offer (Offer) and
// returns the agent's answer, its candidates gathered (bounded).
func (p *browserPeer) answer(offer webrtc.SessionDescription) (*webrtc.SessionDescription, error) {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes(rtcNetworkTypes)
	if p.b.ipFilter != nil {
		se.SetIPFilter(p.b.ipFilter)
	}
	se.SetSCTPMaxMessageSize(BrowserMaxMessage)
	se.SetICETimeouts(5*time.Second, 10*time.Second, 2*time.Second)
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	se.LoggerFactory = lf
	var ice []webrtc.ICEServer
	if p.b.STUN != "" {
		ice = []webrtc.ICEServer{{URLs: []string{"stun:" + p.b.STUN}}}
	}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{ICEServers: ice})
	if err != nil {
		return nil, err
	}
	p.b.offers.Add(1)
	p.mu.Lock()
	p.pc, p.held, p.state = pc, true, "connecting"
	p.tr.emit("Offer", 0)
	p.mu.Unlock()
	pc.OnConnectionStateChange(p.onState)
	pc.OnDataChannel(p.onDataChannel)
	if err := pc.SetRemoteDescription(offer); err != nil {
		return nil, err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		return nil, err
	}
	select {
	case <-gathered:
	case <-time.After(browserGather): // the candidates gathered so far
	}
	return pc.LocalDescription(), nil
}

// upLocked is PCUp once: the connection's state said so, or a data
// channel opened on it (pion may report the two in either order).
func (p *browserPeer) upLocked() {
	if p.held && p.state == "connecting" {
		p.state = "up"
		p.tr.emit("PCUp", 0)
	}
}

func (p *browserPeer) onState(st webrtc.PeerConnectionState) {
	p.mu.Lock()
	switch st {
	case webrtc.PeerConnectionStateConnected:
		p.upLocked()
		p.mu.Unlock()
		return
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		// Closed while held: the visitor's end closed it.
		if !p.held || (p.state != "connecting" && p.state != "up") {
			p.mu.Unlock()
			return
		}
	default:
		p.mu.Unlock()
		return
	}
	p.state = "failed"
	p.tr.emit("PCFail", 0)
	closers := p.reapLocked()
	p.mu.Unlock()
	go func() {
		closers()
		_ = p.ctl.Close() // the control session ends with its connection
	}()
}

func (p *browserPeer) onDataChannel(d *webrtc.DataChannel) {
	if d.Label() != BrowserDCLabel || !d.Ordered() || d.MaxRetransmits() != nil || d.MaxPacketLifeTime() != nil {
		_ = d.Close()
		return
	}
	d.OnOpen(func() {
		rwc, err := d.DetachWithDeadline()
		if err != nil {
			_ = d.Close()
			return
		}
		c := newBPConn(rwc, d)
		p.mu.Lock()
		p.upLocked()
		if !p.held || p.state != "up" || len(p.dcs) >= p.maxDC {
			p.mu.Unlock()
			_ = c.Close() // past the cap: the visitor opens the stream on the WebSocket
			return
		}
		p.next++
		s := p.next
		p.dcs[s] = c
		p.tr.emit("OpenDC", s)
		p.wg.Add(1)
		p.mu.Unlock()
		go p.stream(s, c)
	})
}

// liveLocked: stream s's path is live (BrowserPeer.tla PathLive).
func (p *browserPeer) liveLocked(s int) bool {
	return p.held && p.state == "up" && p.dcs[s] != nil
}

// stream serves data channel s: its own nf1 session, then the service.
func (p *browserPeer) stream(s int, c *bpConn) {
	defer p.wg.Done()
	defer c.Close() //nolint:errcheck
	tc, err := p.l.Accept(p.ctx, c)
	p.mu.Lock()
	live := p.liveLocked(s)
	switch {
	case err != nil && live:
		p.tr.emit("Refuse", s) // its own proof or TLS failed
	case err != nil || !live:
		p.tr.emit("Break", s)
	default:
		p.tr.emit("Deliver", s)
	}
	if err != nil || !live {
		delete(p.dcs, s)
		p.mu.Unlock()
		if tc != nil {
			_ = tc.Close()
		}
		return
	}
	p.mu.Unlock()
	p.serve(p.ctx, tc)
	p.mu.Lock()
	if p.liveLocked(s) {
		p.tr.emit("Complete", s)
	} else {
		p.tr.emit("Break", s)
	}
	delete(p.dcs, s)
	p.mu.Unlock()
}

// readSignal reads one SDP message: u16 length, then its JSON
// (RTCSessionDescriptionInit); length 0 is none (nil).
func readSignal(r io.Reader) (*webrtc.SessionDescription, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(n[:]))
	if size == 0 {
		return nil, nil
	}
	if size > BrowserMaxSignal {
		return nil, errors.New("p2p: browser signal too large")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	var sd webrtc.SessionDescription
	if err := json.Unmarshal(b, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

// writeSignal writes sd as one SDP message (nil: length 0).
func writeSignal(w io.Writer, sd *webrtc.SessionDescription) error {
	var b []byte
	if sd != nil {
		var err error
		if b, err = json.Marshal(sd); err != nil {
			return err
		}
		if len(b) > BrowserMaxSignal {
			return errors.New("p2p: browser signal too large")
		}
	}
	_, err := w.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)) // #nosec G115 -- bounded above
	return err
}

// bpConn is a byte stream (net.Conn) on a stream's detached data channel:
// writes in chunks with back-pressure, the deadlines the channel's.
type bpConn struct {
	rwc  datachannel.ReadWriteCloserDeadliner
	w    *chunkWriter
	rbuf []byte
	rest []byte
	once sync.Once
}

func newBPConn(rwc datachannel.ReadWriteCloserDeadliner, d *webrtc.DataChannel) *bpConn {
	low := make(chan struct{}, 1)
	d.SetBufferedAmountLowThreshold(dcLow)
	d.OnBufferedAmountLow(func() {
		select {
		case low <- struct{}{}:
		default:
		}
	})
	return &bpConn{
		rwc:  rwc,
		rbuf: make([]byte, BrowserMaxMessage),
		w: &chunkWriter{
			send:     func(b []byte) error { _, err := rwc.Write(b); return err },
			buffered: d.BufferedAmount,
			low:      low,
			done:     make(chan struct{}),
			chunk:    dcChunk,
			high:     dcHigh,
		},
	}
}

func (c *bpConn) Read(b []byte) (int, error) {
	if len(c.rest) == 0 {
		n, err := c.rwc.Read(c.rbuf)
		if err != nil {
			return 0, err
		}
		c.rest = c.rbuf[:n]
	}
	n := copy(b, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// Write sends b in chunks with back-pressure (net.Conn). allow:wrapper
func (c *bpConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func (c *bpConn) Close() error {
	c.once.Do(func() {
		close(c.w.done)
		_ = c.SetDeadline(time.Time{}) // ends pion's deadline timers now, not at the deadline
		_ = c.rwc.Close()
	})
	return nil
}

func (c *bpConn) LocalAddr() net.Addr  { return dcAddr("webrtc-local") }
func (c *bpConn) RemoteAddr() net.Addr { return dcAddr("webrtc-peer") }
func (c *bpConn) SetDeadline(t time.Time) error {
	return errors.Join(c.rwc.SetReadDeadline(t), c.rwc.SetWriteDeadline(t))
}

// SetReadDeadline is the channel's (net.Conn). allow:wrapper
func (c *bpConn) SetReadDeadline(t time.Time) error { return c.rwc.SetReadDeadline(t) }

// SetWriteDeadline is the channel's (net.Conn). allow:wrapper
func (c *bpConn) SetWriteDeadline(t time.Time) error { return c.rwc.SetWriteDeadline(t) }
