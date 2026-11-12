// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/tlsend"
)

// directServer is an agent's half of direct paths, one per service table
// with a direct service: the table's reserved service DirectServiceName,
// the listener for direct connections on its DirectEndpoint and the
// sessions that may move (by their path token).
type directServer struct {
	ep     *DirectEndpoint
	org    Org
	groups []string              // every direct service's allow groups
	modes  map[string]DirectMode // by service
	node   *quiclink.Node
	logger *slog.Logger
	detach time.Duration // a session's pathswitch Detach; 0: its default

	mu       sync.Mutex
	sessions map[*directSession]struct{}
	quic     map[string][]byte // a direct connection's exporter, by its peer name
	pending  int               // framed sessions in their TLS handshake (handshaking)
	changed  chan struct{}     // closed when one of them ends; nil: none waits
}

// qadTarget is a relay's QAD: its agent link's UDP address and TLS.
type qadTarget struct {
	addr string
	tls  *tls.Config
}

// directSession is a session that may move: its path layer and token key.
type directSession struct {
	c   *pathswitch.Conn
	key []byte
}

// newDirectServer starts the listener on a new endpoint.
func newDirectServer(org Org, groups []string, modes map[string]DirectMode) (*directServer, error) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		return nil, err
	}
	return newDirectServerOn(ep, org, groups, modes)
}

// newDirectServerOn starts the listener on ep, which it owns.
func newDirectServerOn(ep *DirectEndpoint, org Org, groups []string, modes map[string]DirectMode) (*directServer, error) {
	d := &directServer{ep: ep, org: org, groups: groups, modes: modes, logger: slog.Default(),
		sessions: map[*directSession]struct{}{}, quic: map[string][]byte{}}
	var err error
	d.node, err = quiclink.New(quiclink.Config{Transport: ep.tr, TLS: d.listenTLS(), ServedPeer: d.servedPeer,
		Liveness: link.LivenessFast})
	if err != nil {
		_ = ep.Close()
		return nil, err
	}
	go func() { _ = d.node.Serve(d.acceptDirect) }() // ponytail: the process's lifetime: a later table takes it over (Continue)
	return d, nil
}

// listenTLS is a direct connection's TLS at the agent: this machine's
// certificate, a client's certificate of the organisation in a direct
// service's groups. It admits the connection only: a stream on it moves a
// session only on that session's token (acceptDirect).
func (d *directServer) listenTLS() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return d.org.Certificate() },
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := d.org.CheckClient(cs.PeerCertificates, d.groups, time.Now())
			return err
		},
	}
}

// servedPeer names a direct connection by its exporter, which the tokens
// of its streams bind (BIND:direct.quic).
func (d *directServer) servedPeer(q *quic.Conn) (string, error) {
	k, err := quicKey(q)
	if err != nil {
		return "", err
	}
	name := hex.EncodeToString(k[:8])
	d.mu.Lock()
	d.quic[name] = k
	d.mu.Unlock()
	context.AfterFunc(q.Context(), func() {
		d.mu.Lock()
		delete(d.quic, name)
		d.mu.Unlock()
	})
	return name, nil
}

// register makes s movable until it ends.
func (d *directServer) register(c *pathswitch.Conn, key []byte) {
	s := &directSession{c: c, key: key}
	d.mu.Lock()
	d.sessions[s] = struct{}{}
	d.mu.Unlock()
	go func() {
		<-c.Done()
		d.mu.Lock()
		delete(d.sessions, s)
		d.mu.Unlock()
	}()
}

// handshaking counts a framed session's TLS handshake until the returned
// func (idempotent), called after register: the client's TLS 1.3
// handshake ends a flight before this end's, so its OPEN can arrive before
// the session is registered, and find waits for it
// (TestDirectOpenBeforeTheAgentsHandshake).
func (d *directServer) handshaking() func() {
	d.mu.Lock()
	d.pending++
	d.mu.Unlock()
	return sync.OnceFunc(func() {
		d.mu.Lock()
		d.pending--
		if d.changed != nil {
			close(d.changed)
			d.changed = nil
		}
		d.mu.Unlock()
	})
}

// find is the session whose client token for o's epoch, bound to qk, o
// carries (BIND:direct.token, role, epoch, quic). While a session is in
// its handshake it waits for it, at most e2eeHeaderTimeout: a session an
// OPEN names had its client's handshake done, so its handshake here was
// under way and ends within that bound.
func (d *directServer) find(o pathswitch.Open, qk []byte) *directSession {
	var bound <-chan time.Time
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		if s := d.matchLocked(o, qk); s != nil || d.pending == 0 {
			return s
		}
		if bound == nil {
			t := time.NewTimer(e2eeHeaderTimeout)
			defer t.Stop()
			bound = t.C
		}
		if d.changed == nil {
			d.changed = make(chan struct{})
		}
		changed := d.changed
		d.mu.Unlock()
		select {
		case <-changed:
		case <-bound:
			d.mu.Lock()
			return nil
		}
		d.mu.Lock()
	}
}

// matchLocked is find's match; d.mu held.
func (d *directServer) matchLocked(o pathswitch.Open, qk []byte) *directSession {
	for s := range d.sessions {
		if hmac.Equal(o.Token, pathToken(s.key, roleClient, o.Epoch, qk)) {
			return s
		}
	}
	return nil
}

// acceptDirect takes a stream on a direct connection: the session its
// OPEN's token names, after this end's token on it (the client's proof
// that the agent of its session answered), else a refusal.
func (d *directServer) acceptDirect(peer string, _ []byte, s peerlink.Session) {
	d.mu.Lock()
	qk := d.quic[peer]
	d.mu.Unlock()
	ps := pathStream{Conn: s}
	o, err := pathswitch.ReadOpen(ps)
	if err != nil || qk == nil {
		_ = s.Reset()
		return
	}
	sess := d.find(o, qk)
	if sess == nil {
		d.logger.Warn("direct path: an OPEN no session's token names, refused")
		_ = s.Reset() // not Refuse: a stranger's stream resets no session
		return
	}
	if _, err := s.Write(pathToken(sess.key, roleServer, o.Epoch, qk)); err != nil {
		_ = s.Reset()
		return
	}
	if err := sess.c.Attach(o, PathDirect); err != nil {
		_ = s.Reset()
	}
}

// serveService serves a session of the reserved service: a control
// exchange (it starts with TLS, bound to the reserved service as any
// session's to its service: bind) or a relayed re-attach (an OPEN). relay
// is the QAD of the relay the session arrived through (nil: none).
func (d *directServer) serveService(s net.Conn, bind serviceBind, relay *qadTarget, logger *slog.Logger) {
	first, ps, err := peekFirst(s, e2eeHeaderTimeout)
	if err != nil {
		_ = s.Close()
		return
	}
	s = ps
	if first != tlsRecordHandshake {
		d.reattach(pathStream{Conn: s})
		return
	}
	d.controlSession(s, d.org, d.groups, bind, relay, logger)
}

// controlSession runs a control exchange on s: TLS as a session of bind's
// (org, groups), then control. It serves the reserved service's exchanges
// and those on a direct service's own route (directControlMark).
func (d *directServer) controlSession(s net.Conn, org Org, groups []string, bind serviceBind, relay *qadTarget, logger *slog.Logger) {
	var adm orgAdmission
	cfg, err := orgServerConfig(org, groups, bind, &adm, logger)
	if err != nil {
		_ = s.Close()
		return
	}
	tc := tlsend.Server(s, cfg)
	_ = tc.SetDeadline(time.Now().Add(e2eeHeaderTimeout))
	if err := tc.Handshake(); err != nil {
		_ = s.Close()
		return
	}
	_ = tc.SetDeadline(time.Now().Add(directControlBound))
	defer tc.Close() //nolint:errcheck
	if err := d.control(tc, relay, bind.agent); err != nil {
		logger.Info("direct path: control exchange ended", "error", err)
	}
}

// reattach takes a relayed stream of a session whose path died
// (e2ee_tcp.pv tokR: the token without a direct connection's exporter).
func (d *directServer) reattach(s pathStream) {
	o, err := pathswitch.ReadOpen(s)
	if err != nil {
		_ = s.Reset()
		return
	}
	sess := d.find(o, nil)
	if sess == nil {
		d.logger.Info("direct path: a relayed re-attach no session's token names, refused")
		_ = s.Reset()
		return
	}
	if err := sess.c.Attach(o, PathRelayed); err != nil {
		d.logger.Info("direct path: a relayed re-attach refused", "error", err)
		_ = s.Reset()
	}
}

// directControlBound bounds a control exchange: the candidates both ways
// and the punch.
const directControlBound = 15 * time.Second

// Control messages (one JSON object per line, inside the control
// session's TLS): the client's request, the agent's offer, the client's
// candidates. A refusal (the service's mode off, no address) is an offer
// with Error set; the client's session stays relayed.
type directRequest struct {
	Service string `json:"service"`
}

type directOffer struct {
	Candidates []string `json:"candidates,omitempty"`
	QAD        string   `json:"qad,omitempty"`   // the relay's QAD address, for the client's own
	Agent      string   `json:"agent,omitempty"` // this agent's name: a group dial's route to it, <machine>.<agent>
	Error      string   `json:"error,omitempty"`
}

type directCandidates struct {
	Candidates []string `json:"candidates"`
}

// Offer errors, the client's fallback reasons.
const (
	reasonOff    = "off"    // the service takes no direct path
	reasonNoAddr = "no_qad" // the agent knows no address of its own
)

// control runs one exchange on c: the request, this end's candidates, the
// client's, then probes toward them while the client punches. The offer's
// reflexive candidate is relay's answer and its QAD names relay, the one
// that carried this exchange: another relay's answer is never added (under
// an endpoint-dependent NAT it would be wrong, else a duplicate). agent is
// this agent's name, which the offer carries.
func (d *directServer) control(c net.Conn, relay *qadTarget, agent string) error {
	r := bufio.NewReader(io.LimitReader(c, 8<<10))
	var req directRequest
	if err := readJSONLine(r, &req); err != nil {
		return err
	}
	mode := d.modes[req.Service]
	enc := json.NewEncoder(c)
	if mode == DirectOff {
		return enc.Encode(directOffer{Error: reasonOff})
	}
	offer := directOffer{Agent: agent}
	var cands []netip.AddrPort
	if relay != nil {
		offer.QAD = relay.addr
		if a, err := d.ep.QAD(context.Background(), relay.addr, relay.tls); err == nil {
			cands = append(cands, a)
		} else {
			d.logger.Info("direct path: qad", "error", err)
		}
	}
	if mode == DirectOn {
		cands = append(cands, d.ep.hostCandidates()...)
	}
	cands = compactCandidates(cands)
	if len(cands) == 0 {
		return enc.Encode(directOffer{Error: reasonNoAddr})
	}
	for _, a := range cands {
		offer.Candidates = append(offer.Candidates, a.String())
	}
	if err := enc.Encode(offer); err != nil {
		return err
	}
	var theirs directCandidates
	if err := readJSONLine(r, &theirs); err != nil {
		return err
	}
	peer, err := d.ep.candidates(theirs.Candidates)
	if err != nil {
		return err
	}
	// The punch: datagrams toward the client's mappings open this end's
	// NAT while the client's QUIC Initials arrive (quiclink.Punch).
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, r); close(done) }() // the client closes once punched
	for _, wait := range []time.Duration{0, 200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second} {
		select {
		case <-done:
			return nil
		case <-time.After(wait):
		}
		_ = quiclink.Probe(d.ep.tr, peer)
	}
	<-done
	return nil
}

// readJSONLine reads one line of r into v.
func readJSONLine(r *bufio.Reader, v any) error {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// candidates reads at most quiclink.MaxCandidates candidates.
func (e *DirectEndpoint) candidates(ss []string) ([]netip.AddrPort, error) {
	if len(ss) == 0 || len(ss) > quiclink.MaxCandidates {
		return nil, fmt.Errorf("direct path: %d candidates (1 to %d)", len(ss), quiclink.MaxCandidates)
	}
	out := make([]netip.AddrPort, 0, len(ss))
	for _, s := range ss {
		a, err := e.candidate(s)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// compactCandidates drops repeats and keeps at most MaxCandidates.
func compactCandidates(cs []netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range cs {
		if !slices.Contains(out, a) && len(out) < quiclink.MaxCandidates {
			out = append(out, a)
		}
	}
	return out
}

// startDirect is a framed session's path layer at the agent (its first
// stream is s), once its first byte said it is one; nil, s: an unframed
// session (TLS from its first byte). d may be nil (no direct service).
func startDirect(s net.Conn, d *directServer) (*pathswitch.Conn, net.Conn, error) {
	first, ps, err := peekFirst(s, e2eeHeaderTimeout)
	if err != nil {
		_ = s.Close()
		return nil, nil, err
	}
	s = ps
	if first == tlsRecordHandshake {
		return nil, s, nil
	}
	var cfg pathswitch.Config
	if d != nil {
		cfg.Detach = d.detach
	}
	c := pathswitch.Server(pathStream{Conn: s}, PathRelayed, cfg)
	return c, newPSConn(c, s), nil
}
