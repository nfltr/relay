// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
)

// directServer is an agent's half of direct paths, one per service table
// with a direct service: the table's reserved service DirectServiceName,
// the listener for direct connections on its DirectEndpoint and the
// sessions that may move (by their path token).
type directServer struct {
	ep       *DirectEndpoint
	org      Org
	services []string              // every direct service's name: a client a rule admits to one may take direct paths
	modes    map[string]DirectMode // by service
	node     *quiclink.Node
	logger   *slog.Logger
	detach   time.Duration // a session's pathswitch Detach; 0: its default

	mu       sync.Mutex
	sessions map[*directSession]struct{}
	quic     map[string][]byte // a direct connection's exporter, by its peer name
	pending  int               // framed sessions in their TLS handshake (handshaking)
	changed  chan struct{}     // closed when one of them ends; nil: none waits
	stopped  atomic.Bool       // a stop's drain ended: a later stop only resets (stop)
	tr       stopTracer        // spec/AgentStop.tla's trace (-tags relaytrace)
	// beforeAttach, set, runs in acceptDirect just before the attach (a
	// test's hold: TestDatagramDirectOnlyOnceTheAgentAttached)
	beforeAttach atomic.Pointer[func()]
}

// qadTarget is a relay's QAD: its agent link's UDP address and TLS.
type qadTarget struct {
	addr string
	tls  *tls.Config
}

// directSession is a session that may move: its path layer and token key.
type directSession struct {
	c    *pathswitch.Conn
	dg   *sessionDatagrams // its direct datagrams (a datagram service's association)
	key  []byte
	peer string        // the direct connection it last moved to (servedPeer's name); d.mu
	nf1  *nf1.Listener // a capability address's session: its listener (nil: organisation mode)
	// lost ends an anonymous address's session at its current stream's
	// end (never re-attached: anonLost); nil for every other session
	lost func()
	sni  string // ... the server name its direct connection asks for (nf1SNI)
	// revoke is a udp service's association on the session (setDirect):
	// a revocation tells its flows why before the session ends.
	revoke atomic.Pointer[dgram.Server]
	// ended: its Conn is done; it answers re-attaches until it is
	// forgotten (registerSession), and takes no new direct connection
	ended atomic.Bool
	// aborted closes at its first reset, cut once it ended or
	// directCutGrace after that (reset); both made by registerSession
	cutOnce      sync.Once
	aborted, cut chan struct{}
	tr           stopTraceSession // spec/AgentStop.tla's trace (-tags relaytrace)
}

// reset resets s at its first call (an ABORT on its current path): the
// stop's, or its target's reset (setDirect). The channel closes once s
// ended or directCutGrace after that reset: a later stop waits out the
// same grace, not one of its own (TestDirectStopsWaitOneGrace).
func (s *directSession) reset() <-chan struct{} {
	s.cutOnce.Do(func() {
		s.abort()
		go func() {
			t := time.NewTimer(directCutGrace)
			defer t.Stop()
			select {
			case <-s.c.Done():
				s.tr.done()
			case <-t.C:
			}
			s.tr.cut()
			close(s.cut)
		}()
	})
	return s.cut
}

// refuse resets s, refused at its registration: no stop waits for it
// (spec/AgentStop.tla Register), so its cut closes at once and no grace
// runs: a grace goroutine waited directCutGrace for a peer that never
// answers, past the stop and its test's end (lane DIRECTLEAK,
// TestDirectStopRefusesLateSessions).
func (s *directSession) refuse() {
	s.cutOnce.Do(func() {
		s.abort()
		close(s.cut)
	})
}

func (s *directSession) abort() {
	s.tr.abort(s.c.Done())
	s.c.Abort()
	close(s.aborted)
}

// newDirectServer starts the listener on a new endpoint.
func newDirectServer(org Org, services []string, modes map[string]DirectMode) (*directServer, error) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		return nil, err
	}
	return newDirectServerOn(ep, org, services, modes)
}

// newDirectServerOn starts the listener on ep, which it owns.
func newDirectServerOn(ep *DirectEndpoint, org Org, services []string, modes map[string]DirectMode) (*directServer, error) {
	d := &directServer{ep: ep, org: org, services: services, modes: modes, logger: slog.Default(),
		sessions: map[*directSession]struct{}{}, quic: map[string][]byte{}}
	var err error
	d.node, err = quiclink.New(quiclink.Config{Transport: ep.tr, TLS: d.listenTLS(), ServedPeer: d.servedPeer,
		Liveness: link.LivenessFast, Datagrams: true, Window: tcpDataWindow, MaxWindow: directMaxWindow})
	if err != nil {
		_ = ep.Close()
		return nil, err
	}
	go func() { _ = d.node.Serve(d.acceptDirect) }() // ponytail: the process's lifetime: a later table takes it over (Continue)
	return d, nil
}

// listenTLS is a direct connection's TLS at the agent: this machine's
// certificate, a client's certificate of the organisation in a direct
// service's groups; or, for a server name a capability address's session
// asked for (nf1SNI), that address's certificate and no client's
// (nf1ListenTLS). It admits the connection only: a stream on it moves a
// session only on that session's token (acceptDirect).
func (d *directServer) listenTLS() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		GetConfigForClient:     d.nf1ListenTLS,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return d.org.Certificate() },
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if d.org == nil {
				return errors.New("direct path: no organisation direct service")
			}
			_, err := d.org.CheckClient(cs.PeerCertificates, d.services, time.Now())
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
	d.holdConn(q, name)
	return name, nil
}

// holdConn closes q once its client's admission ends (a CRL that revokes
// it, its NotAfter): the revoked machine's direct connection does not
// outlive its sessions, which holdAdmission cuts (nfltr direct-paths doc
// "Lane REVOKEDIRECT"; TestDirectRevokedClientCutOnEveryPath).
func (d *directServer) holdConn(q *quic.Conn, name string) {
	if isNF1SNI(q.ConnectionState().TLS.ServerName) {
		return // a capability address's: no admission to end (its sessions end with the serving process)
	}
	certs := q.ConnectionState().TLS.PeerCertificates
	cut := func() { go d.closeAfterSessions(q, name) }
	changed := d.org.Changed() // before the check: a change after it is seen
	until, err := d.org.CheckClient(certs, d.services, time.Now())
	if err != nil {
		cut()
		return
	}
	go holdAdmission(until, changed, d.org.Changed,
		func(now time.Time) (time.Time, error) { return d.org.CheckClient(certs, d.services, now) },
		cut, q.Context().Done())
}

// directCutGrace bounds how long a direct connection whose admission
// ended waits for the resets of the sessions on it (each its own
// holdAdmission's, an ABORT the peer answers): closed at once, the
// connection would drop the ABORTs, and the peer would re-attach the
// sessions relayed instead of ending them.
const directCutGrace = 5 * time.Second

// closeAfterSessions closes q (named name) once every session on it ended,
// or after directCutGrace.
func (d *directServer) closeAfterSessions(q *quic.Conn, name string) {
	defer q.CloseWithError(quiclink.CodeDone, "admission ended") //nolint:errcheck
	var dones []<-chan struct{}
	d.mu.Lock()
	for s := range d.sessions {
		if s.peer == name {
			dones = append(dones, s.c.Done())
		}
	}
	d.mu.Unlock()
	t := time.NewTimer(directCutGrace)
	defer t.Stop()
	for _, done := range dones {
		select {
		case <-done:
		case <-t.C:
			return
		}
	}
}

// register makes s movable until it ends.
func (d *directServer) register(c *pathswitch.Conn, key []byte) *directSession {
	return d.registerSession(&directSession{c: c, key: key})
}

// registerSession: once a stop's drain ended (stopped), s is refused:
// reset at once and left out of the table, so it never moves to a direct
// path no stop resets and no later stop waits a grace for it (lane
// STOPGAP, spec/AgentStop.tla Register; TestDirectStopRefusesLateSessions).
// stopped is read under the table's lock and stop takes its sessions
// under it after setting stopped: each session is in a later stop's
// sessions or refused.
func (d *directServer) registerSession(s *directSession) *directSession {
	s.dg = &sessionDatagrams{c: s.c}
	s.aborted, s.cut = make(chan struct{}), make(chan struct{})
	d.mu.Lock()
	refused := d.tr.register(&s.tr, d.stopped.Load)
	if !refused {
		d.sessions[s] = struct{}{}
	}
	d.mu.Unlock()
	if refused {
		s.refuse()
		return s
	}
	go func() {
		<-s.c.Done()
		s.tr.done()
		// Ended, it stays findable for the detach bound: a client whose
		// path died or moved before this end's last ACK and FIN (or its
		// ABORT) re-attaches, and Attach answers it (left: count and FIN;
		// reset: ABORT; link spec/DirectPath.tla RLeftAnswer, SLeftAnswer)
		// instead of a stranger's reset that leaves the client
		// re-attaching until its own bound (TestDirectEndedSessionStaysFindable).
		s.ended.Store(true)
		time.AfterFunc(cmp.Or(d.detach, directDetach), func() {
			d.mu.Lock()
			delete(d.sessions, s)
			d.mu.Unlock()
		})
	}()
	return s
}

// directDetach is a session's detach bound when the server sets none
// (pathswitch's default).
const directDetach = 30 * time.Second

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
	return d.findBy(tokenMatch(o, qk))
}

// tokenMatch matches the session whose client token for o's epoch, bound
// to qk, o carries.
func tokenMatch(o pathswitch.Open, qk []byte) func(*directSession) bool {
	return func(s *directSession) bool {
		if hmac.Equal(o.Token, pathToken(s.key, roleClient, o.Epoch, qk)) {
			return true
		}
		return false
	}
}

// findBy is the registered session match takes, waiting as find does.
func (d *directServer) findBy(match func(*directSession) bool) *directSession {
	var bound <-chan time.Time
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		if s := d.matchLocked(match); s != nil || d.pending == 0 {
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

// matchLocked is findBy's match; d.mu held.
func (d *directServer) matchLocked(match func(*directSession) bool) *directSession {
	for s := range d.sessions {
		if match(s) {
			return s
		}
	}
	return nil
}

// acceptDirect takes a stream on a direct connection: the session its
// OPEN's token names, attached, then this end's token on it (the client's
// proof that the agent of its session answered), else a refusal. The
// token goes only after the attach, the stream's first bytes before
// anything the path layer writes (first): the client binds its datagrams
// once it checked the token, so the agent already takes them (spec
// DatagramAssoc.tla BindA, BindC; the token before the attach dropped the
// client's first direct datagram: TestDatagramDirectOnlyOnceTheAgentAttached).
func (d *directServer) acceptDirect(peer string, _ []byte, s peerlink.Session) {
	d.mu.Lock()
	qk := d.quic[peer]
	d.mu.Unlock()
	ps := pathStream{Conn: s, end: &streamEnd{}, first: new(firstWrite)}
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
	if sess.lost != nil {
		ps.end.set(anonLost(sess.c, ps, sess.lost))
	}
	ps.first.b = pathToken(sess.key, roleServer, o.Epoch, qk)
	if q, ok := s.(*quiclink.Session); ok {
		sess.dg.take(ps, q, nil) // its client's token checked (find): bound by both
	}
	if h := d.beforeAttach.Load(); h != nil {
		(*h)()
	}
	if err := sess.c.Attach(o, PathDirect); err != nil {
		_ = s.Reset()
		return
	}
	sess.dg.traceBind("BindA")
	if err := ps.first.send(s); err != nil {
		_ = s.Reset() // the session's stream ended: it re-attaches or ends
		return
	}
	d.mu.Lock()
	sess.peer = peer
	d.mu.Unlock()
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
	d.controlSession(s, d.org, d.services, bind, relay, logger)
}

// controlSession runs a control exchange on s: TLS as a session of bind's
// (org, groups), then control. It serves the reserved service's exchanges
// and those on a direct service's own route (directControlMark).
func (d *directServer) controlSession(s net.Conn, org Org, services []string, bind serviceBind, relay *qadTarget, logger *slog.Logger) {
	var adm orgAdmission
	cfg, err := orgServerConfig(org, services, bind, &adm, logger)
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
	if err := d.control(tc, relay, bind.agent, func(s string) DirectMode { return d.modes[s] }); err != nil {
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
		// ABORT, not a reset: the client's session is gone here (forgotten
		// past the detach bound, or this process restarted), so it ends at
		// once instead of re-attaching until its own bound with its Close
		// waiting on an END ack (link spec/DirectPath.tla: a gone server
		// answers an OPEN with ABORT; TestDirectReattachOfForgottenSessionEndsIt).
		// A direct stream's miss stays a reset (acceptDirect): its
		// exporter may be another connection's; the fallback lands here.
		d.logger.Info("direct path: a relayed re-attach no session's token names, refused")
		pathswitch.Refuse(o)
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
// this agent's name, which the offer carries; modeOf the mode of the
// service the request names (a capability address's exchange: its own).
func (d *directServer) control(c net.Conn, relay *qadTarget, agent string, modeOf func(string) DirectMode) error {
	r := bufio.NewReader(io.LimitReader(c, 8<<10))
	var req directRequest
	if err := readJSONLine(r, &req); err != nil {
		return err
	}
	mode := modeOf(req.Service)
	enc := json.NewEncoder(c)
	if mode == DirectOff {
		return enc.Encode(directOffer{Error: reasonOff})
	}
	offer := directOffer{Agent: agent}
	ctx, cancel := context.WithCancel(context.Background()) // the exchange's: its slow candidates have no reader after it
	defer cancel()
	slow := []func() []netip.AddrPort{d.ep.mappedSource}
	if relay != nil {
		offer.QAD = relay.addr
		slow = append(slow, func() []netip.AddrPort {
			a, err := d.ep.QAD(ctx, relay.addr, relay.tls)
			if err != nil {
				d.logger.Info("direct path: qad", "error", err)
				return nil
			}
			return []netip.AddrPort{a}
		})
	}
	// Trickle: the offer goes with what is known now, the slow candidates
	// follow as they come (gather, sendLate).
	cands, late := d.ep.gather(slow...)
	if len(cands) == 0 {
		return enc.Encode(directOffer{Error: reasonNoAddr})
	}
	for _, a := range cands {
		offer.Candidates = append(offer.Candidates, a.String())
	}
	if err := enc.Encode(offer); err != nil {
		return err
	}
	go sendLate(c, cands, late)
	var theirs directCandidates
	if err := readJSONLine(r, &theirs); err != nil {
		return err
	}
	peer, err := d.ep.candidates(theirs.Candidates)
	if err != nil {
		return err
	}
	// The punch: datagrams toward the client's mappings open this end's
	// NAT while the client's QUIC Initials arrive; their tag lets the
	// client dial where they came from (direct_prflx.go). The client's
	// later candidates are probed as they come, then with the rest.
	tag := probeTag(c)
	done := make(chan struct{})
	more := make(chan netip.AddrPort, quiclink.MaxCandidates)
	go func() { // the client closes once punched
		d.ep.readLate(r, func(a netip.AddrPort) {
			select {
			case more <- a:
			default:
			}
		})
		_, _ = io.Copy(io.Discard, r)
		close(done)
	}()
	waits := []time.Duration{0, 200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}
	tick := time.After(waits[0])
	for i := 0; ; {
		select {
		case <-done:
			return nil
		case a := <-more:
			if !slices.Contains(peer, a) && len(peer) < quiclink.MaxCandidates {
				peer = append(peer, a)
				_ = d.ep.probe([]netip.AddrPort{a}, tag)
			}
		case <-tick:
			_ = d.ep.probe(peer, tag)
			if i++; i < len(waits) {
				tick = time.After(waits[i])
			} else {
				tick = nil
			}
		}
	}
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
	cfg := pathswitch.Config{Window: tcpDataWindow, MaxWindow: directMaxWindow}
	if d != nil {
		cfg.Detach = d.detach
	}
	c := pathswitch.Server(pathStream{Conn: s}, PathRelayed, cfg)
	return c, newPSConn(c, s), nil
}

// stop ends the direct paths at the agent's stop (lane NF1FAULT). A
// session on its direct path no longer holds the relayed stream the
// agent's drain counts, so stop drains them itself: it waits until each
// ended or ctx (the drain) ends, then resets each left (an ABORT on its
// current path) and waits for them at most directCutGrace, so the peer
// ends at once instead of re-attaching to an agent that is gone until its
// detach bound (TestDirectStopDrainsThenResets). The agent's stop runs it
// more than once (its primary's drain, its cycle's end, ServiceTable.Close):
// the drain ends at the first, and each session's grace runs once, from
// its first reset, so a peer that never answers (killed) costs one grace,
// not one per call (TestDirectStopsWaitOneGrace); a session its target
// reset is not drained (TestDirectTargetResetResetsTheSession). d nil: none.
func (d *directServer) stop(ctx context.Context) {
	if d == nil {
		return
	}
	k, drain := d.tr.begin(func() bool { return !d.stopped.Load() })
	if drain {
		deadline := false
		for _, s := range d.liveSessions() {
			select {
			case <-s.c.Done():
				s.tr.done()
			case <-s.aborted: // reset already (its target's): nothing to drain
			case <-ctx.Done():
				deadline = true
			}
		}
		d.tr.drainEnd(k, deadline, func() { d.stopped.Store(true) })
	}
	d.mu.Lock() // the sessions registered by now: later ones are refused (registerSession)
	left := slices.Collect(maps.Keys(d.sessions))
	d.tr.reset(k)
	d.mu.Unlock()
	for _, s := range left {
		s.reset()
	}
	for _, s := range left {
		<-s.reset()
	}
	d.tr.end(k)
}

func (d *directServer) liveSessions() []*directSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Collect(maps.Keys(d.sessions))
}
