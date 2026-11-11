// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
)

// DirectMachine is a client's organisation identity for direct paths:
// its certificate, and the check of an agent machine's (nfltr's orgpki:
// the chain to the root, the name the session asked for, NotAfter, CRL).
type DirectMachine interface {
	Certificate() (*tls.Certificate, error)
	CheckServer(certs []*x509.Certificate, name string, now time.Time) (time.Time, error)
}

// DirectClientConfig is what a client's direct paths use. Every policy
// is the caller's: whether a session asks (DirectClient.Start), its mode
// (DirectSession.Run).
type DirectClientConfig struct {
	Machine DirectMachine
	// Relayed opens a session through the relay to agent's
	// DirectServiceName (organisation mode), answered: a control
	// exchange's or a fallback's stream. Its bytes are this file's.
	Relayed func(ctx context.Context, agent string) (net.Conn, error)
	// QADTLS is the TLS QAD dials the relay at addr with.
	QADTLS func(addr string) *tls.Config
}

// Punch results and fallback reasons, as path events carry them.
const (
	ReasonWithheld     = "withheld"      // no control exchange (the relay withheld it, an agent without direct paths)
	ReasonOff          = reasonOff       // the agent's service takes no direct path
	ReasonNoQAD        = reasonNoAddr    // an end knows no address of its own
	ReasonNoAnswer     = "no_answer"     // no candidate answered the punch
	ReasonRefusedCert  = "refused_cert"  // a candidate answered with another certificate
	ReasonRefusedToken = "refused_token" // the answer did not prove the session
	ReasonDirectLost   = "direct_lost"   // the direct path died: back on the relay
	ReasonRelayLost    = "relay_lost"    // the relayed stream died: a new one
)

// PathEvent is a session's change of path: Path direct (Peer the agent's
// address it learned) or relayed (Reason why).
type PathEvent struct {
	Path   string
	Reason string
	Peer   netip.AddrPort
}

// DirectStats are a client's direct-path counts: bytes per path (path
// frames included), punches by result, sessions by path. No label names a
// machine.
type DirectStats struct {
	DirectSent, DirectReceived, RelayedSent, RelayedReceived uint64
	Punches                                                  map[string]uint64
	Sessions                                                 map[string]int
}

// DirectClient is a client process's direct paths: its DirectEndpoint,
// one direct connection per agent (a quiclink Node dialling by Punch) and
// the sessions that asked.
type DirectClient struct {
	cfg  DirectClientConfig
	ep   *DirectEndpoint
	node *quiclink.Node

	directSent, directRecv, relayedSent, relayedRecv atomic.Uint64

	mu       sync.Mutex
	pairs    map[string]*directPair
	punches  map[string]uint64
	sessions map[*DirectSession]struct{}
}

// directPair is the client's state toward one agent: the direct
// connection, the candidates its next punch dials, the backoff.
type directPair struct {
	mu      sync.Mutex // one exchange at a time
	agent   string
	machine string
	cands   []netip.AddrPort
	refused atomic.Bool // the last punch met a certificate the check refused
	q       *quic.Conn
	qk      []byte
	fails   int
	next    time.Time
}

// directBackoff is the wait after the nth failed punch toward a pair (at
// most three punches in ten minutes after the first two: the design's
// bound).
var directBackoff = []time.Duration{20 * time.Second, time.Minute, 10 * time.Minute}

// NewDirectClient opens the client's endpoint.
func NewDirectClient(cfg DirectClientConfig) (*DirectClient, error) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		return nil, err
	}
	d := &DirectClient{cfg: cfg, ep: ep, pairs: map[string]*directPair{}, punches: map[string]uint64{},
		sessions: map[*DirectSession]struct{}{}}
	d.node, err = quiclink.New(quiclink.Config{Dial: d.dial, Liveness: link.LivenessFast})
	if err != nil {
		_ = ep.Close()
		return nil, err
	}
	return d, nil
}

// Stats are the client's counts now.
func (d *DirectClient) Stats() DirectStats {
	st := DirectStats{DirectSent: d.directSent.Load(), DirectReceived: d.directRecv.Load(),
		RelayedSent: d.relayedSent.Load(), RelayedReceived: d.relayedRecv.Load(),
		Punches: map[string]uint64{}, Sessions: map[string]int{PathDirect: 0, PathRelayed: 0}}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range d.punches {
		st.Punches[k] = v
	}
	for s := range d.sessions {
		st.Sessions[s.c.Path()]++
	}
	return st
}

func (d *DirectClient) count(result string) {
	d.mu.Lock()
	d.punches[result]++
	d.mu.Unlock()
}

func (d *DirectClient) pair(agent, machine string) *directPair {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.pairs[agent]
	if p == nil {
		p = &directPair{agent: agent, machine: machine}
		d.pairs[agent] = p
	}
	return p
}

// DirectSession is a client session framed for direct paths from its
// first byte (pathswitch), its TLS above it.
type DirectSession struct {
	d     *DirectClient
	c     *pathswitch.Conn
	nc    *psConn
	moved chan struct{} // a fallback happened: the loop tries again

	mu      sync.Mutex
	key     []byte
	agent   string
	service string
	mode    DirectMode
	on      func(PathEvent)
	pair    *directPair
	moveAt  time.Time // the last fallback's move
}

// Start frames a session whose first stream (relayed) is first: the
// session's TLS runs on Conn. Run starts its moves once TLS is up.
func (d *DirectClient) Start(first net.Conn) *DirectSession {
	s := &DirectSession{d: d, moved: make(chan struct{}, 1)}
	s.c = pathswitch.Client(pathStream{Conn: first, sent: &d.relayedSent, recv: &d.relayedRecv}, PathRelayed,
		pathswitch.Config{OnStreamEnd: s.fallback})
	s.nc = newPSConn(s.c, first)
	return s
}

// Conn is the net.Conn the session's TLS runs on.
func (s *DirectSession) Conn() net.Conn { return s.nc }

// Done is closed once the session is over.
func (s *DirectSession) Done() <-chan struct{} { return s.c.Done() }

// Path is the session's current path.
func (s *DirectSession) Path() string { return s.c.Path() }

// Run takes the session's TLS state (the token's key) and moves the
// session to a direct path toward agent (its machine name machine, its
// service service) when one can be punched, back to the relay when it
// dies, and to a direct one again after the pair's backoff; on gets each
// change; mode DirectOn sends this machine's public address only,
// DirectLAN its interface addresses too. It returns at once.
func (s *DirectSession) Run(cs tls.ConnectionState, agent, machine, service string, mode DirectMode, on func(PathEvent)) error {
	key, err := sessionKey(cs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.key, s.agent, s.service, s.mode, s.on = key, agent, service, mode, on
	s.pair = s.d.pair(agent, machine)
	s.mu.Unlock()
	s.d.mu.Lock()
	s.d.sessions[s] = struct{}{}
	s.d.mu.Unlock()
	go s.loop()
	return nil
}

func (s *DirectSession) emit(e PathEvent) {
	if s.on != nil {
		s.on(e)
	}
}

// loop tries a direct path while the session lasts.
func (s *DirectSession) loop() {
	defer func() {
		s.d.mu.Lock()
		delete(s.d.sessions, s)
		s.d.mu.Unlock()
	}()
	for {
		if reason := s.tryDirect(); reason != "" && reason != "backoff" {
			s.emit(PathEvent{Path: PathRelayed, Reason: reason})
		}
		s.pair.mu.Lock()
		wait := time.Until(s.pair.next)
		s.pair.mu.Unlock()
		if s.c.Path() == PathDirect {
			wait = -1 // until the direct path dies
		}
		var timer <-chan time.Time
		if wait >= 0 {
			timer = time.After(max(wait, time.Second))
		}
		select {
		case <-s.c.Done():
			return
		case <-s.moved:
		case <-timer:
		}
	}
}

// tryDirect moves the session onto the pair's direct connection, punched
// first when there is none; "" when it moved, else why not.
func (s *DirectSession) tryDirect() string {
	p := s.pair
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.q == nil || p.q.Context().Err() != nil {
		p.q = nil
		if time.Now().Before(p.next) {
			return "backoff"
		}
		reason := s.punch(p)
		if reason == "" {
			s.d.count("ok")
		} else {
			s.d.count(reason)
		}
		if reason != "" {
			p.fails++
			p.next = time.Now().Add(directBackoff[min(p.fails, len(directBackoff))-1])
			return reason
		}
		p.fails = 0
		q := p.q
		context.AfterFunc(q.Context(), func() { // the next punch after a death waits the first backoff
			p.mu.Lock()
			if p.q == q {
				p.q, p.fails, p.next = nil, 1, time.Now().Add(directBackoff[0])
			}
			p.mu.Unlock()
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.d.node.Open(ctx, p.agent, nil)
	if err != nil {
		return ReasonNoAnswer
	}
	tc := &tokenCheck{pathStream: pathStream{Conn: st, sent: &s.d.directSent, recv: &s.d.directRecv}, ready: make(chan struct{})}
	peer, _ := netip.ParseAddrPort(p.q.RemoteAddr().String())
	tc.ok = func() { s.emit(PathEvent{Path: PathDirect, Peer: peer}) }
	tc.bad = func() { s.emit(PathEvent{Path: PathRelayed, Reason: ReasonRefusedToken}) }
	qk := p.qk
	if _, err := s.c.Move(tc, PathDirect, func(e uint64) []byte {
		tc.want = pathToken(s.key, roleServer, e, qk)
		close(tc.ready)
		return pathToken(s.key, roleClient, e, qk)
	}); err != nil {
		return ReasonNoAnswer
	}
	return ""
}

// punch runs one control exchange and the punch it starts; p.mu held.
func (s *DirectSession) punch(p *directPair) string {
	ctx, cancel := context.WithTimeout(context.Background(), directControlBound)
	defer cancel()
	raw, err := s.d.cfg.Relayed(ctx, p.agent)
	if err != nil {
		return ReasonWithheld
	}
	tc := tls.Client(raw, s.d.controlTLS(p.machine))
	defer tc.Close() //nolint:errcheck
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if err := tc.HandshakeContext(ctx); err != nil {
		return ReasonWithheld
	}
	enc, r := json.NewEncoder(tc), bufio.NewReader(io.LimitReader(tc, 8<<10))
	var offer directOffer
	if enc.Encode(directRequest{Service: s.service}) != nil || readJSONLine(r, &offer) != nil {
		return ReasonWithheld
	}
	if offer.Error != "" {
		return offer.Error
	}
	theirs, err := s.d.ep.candidates(offer.Candidates)
	if err != nil {
		return ReasonNoQAD
	}
	var mine []netip.AddrPort
	if offer.QAD != "" && s.d.cfg.QADTLS != nil {
		if a, err := s.d.ep.QAD(ctx, offer.QAD, s.d.cfg.QADTLS(offer.QAD)); err == nil {
			mine = append(mine, a)
		}
	}
	if s.mode == DirectLAN {
		mine = append(mine, s.d.ep.hostCandidates()...)
	}
	mine = compactCandidates(mine)
	if len(mine) == 0 {
		return ReasonNoQAD
	}
	out := directCandidates{}
	for _, a := range mine {
		out.Candidates = append(out.Candidates, a.String())
	}
	if enc.Encode(out) != nil {
		return ReasonWithheld
	}
	p.cands = theirs
	p.refused.Store(false)
	q, err := s.d.dialPair(ctx, p)
	if err != nil {
		if p.refused.Load() {
			return ReasonRefusedCert
		}
		return ReasonNoAnswer
	}
	p.q = q
	return ""
}

// dial is the Node's: the pair's last punch's connection (dialPair made
// it), or none.
func (d *DirectClient) dial(_ context.Context, peer string, _ *quic.Config) (*quic.Conn, error) {
	d.mu.Lock()
	p := d.pairs[peer]
	d.mu.Unlock()
	if p == nil || p.q == nil {
		return nil, errors.New("direct path: no punched connection")
	}
	return p.q, nil
}

// dialPair punches p's candidates on the endpoint (quiclink.Punch, 5 s)
// and keeps the connection's exporter for the tokens.
func (d *DirectClient) dialPair(ctx context.Context, p *directPair) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q, err := quiclink.Punch(ctx, d.ep.tr, p.cands, d.punchTLS(p), d.node.QUICConfig())
	if err != nil {
		return nil, err
	}
	qk, err := quicKey(q)
	if err != nil {
		_ = q.CloseWithError(quiclink.CodeDone, "no exporter")
		return nil, err
	}
	p.qk = qk
	return q, nil
}

// punchTLS is a direct connection's TLS at the client: this machine's
// certificate, and the answer's checked as the organisation's machine the
// session named (BIND:direct.cert, BIND:direct.name) whatever the address
// it came from (the relay chose it).
func (d *DirectClient) punchTLS(p *directPair) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return d.cfg.Machine.Certificate() },
		InsecureSkipVerify:   true, // #nosec G402 -- VerifyConnection checks the organisation's chain and the name
		VerifyConnection: func(cs tls.ConnectionState) error {
			if _, err := d.cfg.Machine.CheckServer(cs.PeerCertificates, p.machine, time.Now()); err != nil {
				p.refused.Store(true)
				return errors.Join(errDirectRefused, err)
			}
			return nil
		},
	}
}

// controlTLS is the control session's TLS: organisation mode, as any
// session to machine.
func (d *DirectClient) controlTLS(machine string) *tls.Config {
	cfg := d.punchTLS(&directPair{machine: machine})
	cfg.NextProtos = nil
	return cfg
}

// fallback is the path layer's OnStreamEnd: the current stream died; a
// relayed one takes the session (tokR) until the detach bound.
func (s *DirectSession) fallback(_ uint64, _ error) {
	s.mu.Lock()
	key, agent, last := s.key, s.agent, s.moveAt
	s.mu.Unlock()
	if key == nil {
		return // before Run: no token yet; the session ends with its stream
	}
	// A stream reset again at once (an agent that no longer holds the
	// session resets its re-attach) gets at most one re-attach a second
	// until the session's detach bound ends it.
	if wait := time.Second - time.Since(last); wait > 0 {
		select {
		case <-s.c.Done():
			return
		case <-time.After(wait):
		}
	}
	reason := ReasonRelayLost
	if s.c.Path() == PathDirect {
		reason = ReasonDirectLost
	}
	for {
		select {
		case <-s.c.Done():
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rs, err := s.d.cfg.Relayed(ctx, agent)
		cancel()
		if err == nil {
			_, err = s.c.Move(pathStream{Conn: rs, sent: &s.d.relayedSent, recv: &s.d.relayedRecv}, PathRelayed,
				func(e uint64) []byte { return pathToken(key, roleClient, e, nil) })
			if err == nil {
				s.mu.Lock()
				s.moveAt = time.Now()
				s.mu.Unlock()
				s.emit(PathEvent{Path: PathRelayed, Reason: reason})
				select {
				case s.moved <- struct{}{}:
				default:
				}
			}
			return
		}
		select {
		case <-s.c.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// tokenCheck is a direct stream at the client: its first bytes must be
// the agent's token for the epoch (BIND:direct.role: the server's, never
// the client's own reflected), else the stream is reset and the session
// falls back.
type tokenCheck struct {
	pathStream
	ready   chan struct{}
	want    []byte
	checked bool
	ok, bad func()
}

func (t *tokenCheck) Read(p []byte) (int, error) {
	if !t.checked {
		<-t.ready
		got := make([]byte, len(t.want))
		if _, err := io.ReadFull(t.pathStream, got); err != nil {
			return 0, err
		}
		if !hmac.Equal(got, t.want) {
			t.bad()
			_ = t.Reset()
			return 0, errDirectRefused
		}
		t.checked = true
		t.ok()
	}
	return t.pathStream.Read(p)
}
