// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc/metadata"
)

// The agent link (dataplane's package doc): the agent's sessions on a
// peerlink Link to its relay, over QUIC or link over TLS/TCP, the gRPC
// streams the fallback.

// Transports of the agent link (RelayDialer.Transport).
const (
	// TransportTCP: link over TLS/TCP to the relay's gRPC port.
	TransportTCP = "tcp"
	// TransportQUIC: QUIC to the relay's UDP port, TCP when that fails.
	TransportQUIC = "quic"
	// TransportAuto: QUIC and TCP raced (QUIC with a head start), and a
	// network where QUIC failed goes straight to TCP for a while.
	TransportAuto = "auto"
)

// Transports lists the transport values, for flag help.
var Transports = []string{TransportTCP, TransportQUIC, TransportAuto}

// ParseTransport validates a transport value; "" is TransportTCP.
func ParseTransport(s string) (string, error) {
	switch s {
	case "":
		return TransportTCP, nil
	case TransportTCP, TransportQUIC, TransportAuto:
		return s, nil
	}
	return "", fmt.Errorf("transport %q: want tcp, quic or auto", s)
}

// QUICDialer reaches the relay over QUIC: its host, and the TLS to dial it
// with (grpcclient.RelayTLS; QUIC has no plaintext).
type QUICDialer struct {
	Host string
	TLS  *tls.Config
}

// The agent's choices for TransportAuto: how long QUIC dials alone before
// TCP starts beside it, and how long a network where QUIC failed skips it.
const (
	quicHeadStart = 300 * time.Millisecond
	udpFailureTTL = 30 * time.Minute
)

// A relay that refuses a QUIC agent-link connection was reached over UDP:
// one that does not hold this agent's primary stream, say, behind a load
// balancer that spreads connections over replicas. The first connection
// is redialled then (a new one may land on the replica that holds it), up
// to quicRefusedAttempts times within dataHelloTimeout: a refusal takes
// about 2 RTTs, so 16 attempts take a few seconds at WAN RTTs and bind
// 1-(4/5)^16 = 97 % of agents on 5 replicas, 99.8 % on 3.
const (
	quicRefusedAttempts = 16
	quicRefusedWait     = 50 * time.Millisecond
)

// relayRefused reports whether err is a relay's refusal of a QUIC
// agent-link connection, which UDP reached (not a UDP failure).
func relayRefused(err error) bool {
	var ae *quic.ApplicationError
	return errors.Is(err, dataplane.ErrLinkHelloRefused) || errors.As(err, &ae) && ae.Remote
}

// udpFailures holds, per network (networkKey), when QUIC last failed there.
var udpFailures sync.Map

// networkKey names the network the agent reaches host from: the local
// address its route there takes (a UDP "connection" sends nothing).
func networkKey(host string, port int) string {
	c, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer c.Close() //nolint:errcheck
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func udpFailedRecently(key string) bool {
	t, ok := udpFailures.Load(key)
	return ok && time.Since(t.(time.Time)) < udpFailureTTL
}

// linkRelayPeer is the relay's name on the agent's Link.
const linkRelayPeer = "relay"

// linkTransport is the transport the agent asks its relay for, "" for no
// agent link (it cannot dial one).
func (d RelayDialer) linkTransport() string {
	t, err := ParseTransport(d.Transport)
	if err != nil || d.Data == nil && d.QUIC == nil {
		return ""
	}
	return t
}

// linkPlan is what the agent tries for an offer: QUIC, TCP, both raced.
func (d RelayDialer) linkPlan(offer dataplane.AgentLinkOffer) (quicOK, tcpOK bool) {
	t := d.linkTransport()
	quicOK = t != TransportTCP && t != "" && offer.QUIC && d.QUIC != nil
	tcpOK = t != "" && offer.TCP && d.Data != nil
	return quicOK, tcpOK
}

// agentLink is one primary stream's agent link.
type agentLink struct {
	dial   RelayDialer
	token  string
	offer  dataplane.AgentLinkOffer
	logger *slog.Logger
	growth *tcpStreamGrowth // counts the connections bound (linkUp)

	tcpNode  *peerlink.Node
	quicNode *quiclink.Node
	preTCP   atomic.Pointer[net.Conn]  // the race's winner, for the Node's first dial
	preQUIC  atomic.Pointer[quic.Conn] // likewise
}

// runAgentLink connects the agent link of the primary whose token and
// offer these are, and serves its sessions with ls until ctx (the
// primary's) ends. It reports whether it connected; when not, the
// sessions stay on the gRPC streams.
func runAgentLink(ctx context.Context, dial RelayDialer, token string, offer dataplane.AgentLinkOffer, ls *linkSessions, logger *slog.Logger) bool {
	l, node := dialAgentLink(ctx, dial, token, offer, ls.growth, logger)
	if node == nil {
		return false
	}
	stop := context.AfterFunc(ctx, func() { drainNow(node) }) // the primary ended: so does its link
	defer stop()
	l.serve(node, ls.accept)
	return true
}

// dialAgentLink makes the agent link's first connection and returns the
// Node to serve it; node is nil when it could not connect (or the offer
// leaves nothing to try).
func dialAgentLink(ctx context.Context, dial RelayDialer, token string, offer dataplane.AgentLinkOffer, g *tcpStreamGrowth, logger *slog.Logger) (*agentLink, peerlink.Link) {
	quicOK, tcpOK := dial.linkPlan(offer)
	if !quicOK && !tcpOK {
		return nil, nil
	}
	l := &agentLink{dial: dial, token: token, offer: offer, logger: logger, growth: g}
	var err error
	l.tcpNode, err = peerlink.New(peerlink.Config{
		Dial:    l.dialTCPNode,
		Connect: []string{linkRelayPeer},
		Link: link.Config{
			Window: tcpDataWindow, MaxSessions: tcpDataMaxSessions, Liveness: dial.Liveness,
			Auth: dataplane.BindToken(token),
		},
		Pool:     link.PoolConfig{Min: 1, Backoff: linkBackoff},
		Observer: func(string) link.Observer { return linkConnObserver{g: g} },
	})
	if err == nil {
		l.quicNode, err = quiclink.New(quiclink.Config{
			Dial:     l.dialQUICNode,
			Connect:  []string{linkRelayPeer},
			Liveness: dial.Liveness,
			Window:   tcpDataWindow, MaxSessions: tcpDataMaxSessions,
		})
	}
	var transport string
	if err == nil {
		transport, err = l.connect(ctx, quicOK, tcpOK)
	}
	if err != nil {
		logger.Info("agent link unavailable; sessions stay on the gRPC streams", "error", err)
		return nil, nil
	}
	logger.Info("agent link connected", "transport", transport)
	if transport == TransportQUIC {
		return l, l.quicNode
	}
	return l, l.tcpNode
}

// serve serves node's sessions with accept until it is drained, then closes a
// first connection its Node never took.
func (l *agentLink) serve(node peerlink.Link, accept func(string, []byte, peerlink.Session)) {
	_ = node.Serve(accept)
	if nc := l.preTCP.Swap(nil); nc != nil {
		_ = (*nc).Close()
	}
	if q := l.preQUIC.Swap(nil); q != nil {
		_ = q.CloseWithError(quiclink.CodeDone, "closed")
	}
}

// drainNow drains node at once.
func drainNow(node peerlink.Link) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	_ = node.Drain(done)
}

// lazyLink is one primary stream's agent link, dialled when the relay
// asks (dataplane.AgentLinkDial on the primary) and closed when the relay
// retired it (dataplane.AgentLinkClose): an idle agent holds no link
// connection. Concurrent requests make one dial; a link that cannot
// connect is not tried again on this primary (failed closes), and its
// sessions stay on the gRPC streams. The Node's redialling while the link
// is up is link's (linkBackoff), as before.
type lazyLink struct {
	ctx    context.Context // the primary's
	park   *linkPark       // where the link waits for the next primary when this one ends; nil: none
	dial   RelayDialer
	header func() (metadata.MD, error) // the primary's response header
	ls     *linkSessions
	logger *slog.Logger
	failed chan struct{}

	mu      sync.Mutex
	node    peerlink.Link // the link up; nil when none
	token   string        // its bind token
	acc     *linkAccept   // what serves its sessions
	dialing bool
	retired bool // the relay retired the link while it was being dialled
	gaveUp  bool
}

func newLazyLink(ctx context.Context, dial RelayDialer, header func() (metadata.MD, error), ls *linkSessions, logger *slog.Logger) *lazyLink {
	z := &lazyLink{ctx: ctx, park: dial.park, dial: dial, header: header, ls: ls, logger: logger, failed: make(chan struct{})}
	context.AfterFunc(ctx, z.end)
	return z
}

// end is the primary's end: a link that is up waits for the next primary
// to resume it (linkPark) while the agent runs on, its sessions going on;
// otherwise it closes.
func (z *lazyLink) end() {
	if z.park == nil || z.park.ctx.Err() != nil {
		z.close()
		return
	}
	z.mu.Lock()
	node, token, acc := z.node, z.token, z.acc
	z.node = nil
	if node == nil && z.dialing {
		z.retired = true
	}
	z.mu.Unlock()
	if node != nil { // its sessions dial in the agent's context (newLinkSessions)
		z.park.park(parkedLink{token: token, node: node, acc: acc})
	}
}

// linkAccept serves a link's sessions with the linkSessions of the
// primary that holds the link now (a resumed link changes primary).
type linkAccept struct{ ls atomic.Pointer[linkSessions] }

func (a *linkAccept) accept(peer string, header []byte, s peerlink.Session) {
	a.ls.Load().accept(peer, header, s)
}

// adopt makes node, the link a previous primary of token parked, this
// primary's: the relay resumed it (the primary's bind token is token).
func (z *lazyLink) adopt(p parkedLink) {
	z.mu.Lock()
	ok := z.node == nil && !z.dialing && z.ctx.Err() == nil
	if ok {
		z.node, z.token, z.acc = p.node, p.token, p.acc
		p.acc.ls.Store(z.ls)
	}
	z.mu.Unlock()
	if !ok {
		drainNow(p.node)
	}
}

// control acts on the relay's agent-link control frame.
func (z *lazyLink) control(what string) {
	switch what {
	case dataplane.AgentLinkDial:
		z.open()
	case dataplane.AgentLinkClose:
		z.close()
	}
}

// open dials the link unless it is up, being dialled, or failed.
func (z *lazyLink) open() {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.node != nil || z.dialing || z.gaveUp || z.ctx.Err() != nil {
		return
	}
	md, err := z.header()
	if err != nil {
		return
	}
	token := firstValue(md, tcpBindHeader)
	offer := dataplane.ParseAgentLinkOffer(md.Get(dataplane.AgentLinkHeader), md.Get(dataplane.AgentLinkQUICHeader))
	if token == "" {
		return
	}
	z.dialing, z.retired = true, false
	go z.run(token, offer)
}

func (z *lazyLink) run(token string, offer dataplane.AgentLinkOffer) {
	l, node := dialAgentLink(z.ctx, z.dial, token, offer, z.ls.growth, z.logger)
	z.mu.Lock()
	z.dialing = false
	if node == nil {
		z.gaveUp = true
		z.mu.Unlock()
		close(z.failed)
		return
	}
	acc := &linkAccept{}
	acc.ls.Store(z.ls)
	retired := z.retired || z.ctx.Err() != nil
	if !retired {
		z.node, z.token, z.acc = node, token, acc
	}
	z.mu.Unlock()
	if retired {
		drainNow(node)
	}
	l.serve(node, acc.accept)
	z.mu.Lock()
	if z.node == node {
		z.node = nil
	}
	z.mu.Unlock()
}

// close closes the link: the relay opens no more sessions on it (it
// retired it, or the primary ended).
func (z *lazyLink) close() {
	z.mu.Lock()
	node := z.node
	z.node = nil
	if node == nil && z.dialing {
		z.retired = true
	}
	z.mu.Unlock()
	if node != nil {
		drainNow(node)
	}
}

// An agent link outlives its primary stream (a connection that broke, as
// when the agent's address changes: TCP cannot follow, a QUIC link can)
// for the agent's next primary to resume: that primary asks for it
// (linkResumeHeader, the old bind token), and a relay that still holds the
// link answers with that token as the new primary's bind token, so the
// sessions open on the link go on and new ones ride it at once. A link
// the next primary does not resume (another replica, an older relay) or
// none comes for within linkParkTTL closes, as it did with its primary.
// The relay's guard: nfltr-relay's TestAgentLinkSurvivesReconnect.
const (
	linkResumeHeader = "x-nfltr-agent-link-resume"
	linkParkTTL      = 10 * time.Second
)

// linkPark holds an agent's link between two of its primaries.
type linkPark struct {
	ctx   context.Context // the agent's
	mu    sync.Mutex
	link  parkedLink
	timer *time.Timer
}

// parkedLink is a link whose primary ended: its bind token, the link, and
// what serves its sessions.
type parkedLink struct {
	token string
	node  peerlink.Link
	acc   *linkAccept
}

// newLinkPark is an agent's park; the link in it closes when ctx (the
// agent's) ends.
func newLinkPark(ctx context.Context) *linkPark {
	p := &linkPark{ctx: ctx}
	context.AfterFunc(ctx, func() {
		if l := p.take(); l.node != nil {
			drainNow(l.node)
		}
	})
	return p
}

// park keeps l for linkParkTTL; a link parked before closes.
func (p *linkPark) park(l parkedLink) {
	if p.ctx.Err() != nil { // the agent stopped
		drainNow(l.node)
		return
	}
	p.mu.Lock()
	old := p.takeLocked()
	p.link = l
	p.timer = time.AfterFunc(linkParkTTL, func() {
		p.mu.Lock()
		var n peerlink.Link
		if p.link.node == l.node {
			n = p.takeLocked().node
		}
		p.mu.Unlock()
		if n != nil {
			drainNow(n)
		}
	})
	p.mu.Unlock()
	if old.node != nil {
		drainNow(old.node)
	}
}

// parked is the token of the link parked, "" for none.
func (p *linkPark) parked() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.link.token
}

// take removes the parked link.
func (p *linkPark) take() parkedLink {
	if p == nil {
		return parkedLink{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.takeLocked()
}

func (p *linkPark) takeLocked() parkedLink {
	l := p.link
	if p.timer != nil {
		p.timer.Stop()
	}
	p.link, p.timer = parkedLink{}, nil
	return l
}

// linkBackoff is the wait before redialling the relay after attempt
// failed dials.
func linkBackoff(attempt int) time.Duration {
	return min(100*time.Millisecond<<min(attempt-1, 6), 5*time.Second)
}

// connect makes the link's first connection: QUIC first when it may, TCP
// beside it after a head start (TransportAuto) or once it failed; the
// winner waits for its Node.
func (l *agentLink) connect(ctx context.Context, quicOK, tcpOK bool) (string, error) {
	key := ""
	if quicOK && l.dial.linkTransport() == TransportAuto {
		key = networkKey(l.dial.QUIC.Host, l.offer.QUICPort)
		if key != "" && udpFailedRecently(key) {
			quicOK = false
		}
	}
	if !quicOK {
		nc, err := l.dialTCP(ctx)
		if err != nil {
			return "", err
		}
		l.preTCP.Store(&nc)
		return TransportTCP, nil
	}
	headStart := quicHeadStart
	if l.dial.linkTransport() == TransportQUIC {
		headStart = -1 // TCP only once QUIC failed
	}
	type result struct {
		q   *quic.Conn
		nc  net.Conn
		err error
	}
	qch, tch := make(chan result, 1), make(chan result, 1)
	tctx, cancelTCP := context.WithCancel(ctx)
	defer cancelTCP()
	reached := make(chan struct{}) // closed when a relay refused QUIC: UDP works
	go func() {
		q, err := l.dialQUICFirst(ctx, func() { close(reached) })
		qch <- result{q: q, err: err}
	}()
	var head <-chan time.Time
	if headStart >= 0 {
		t := time.NewTimer(headStart)
		defer t.Stop()
		head = t.C
	}
	tcpStarted := false
	startTCP := func() {
		if tcpStarted || !tcpOK {
			return
		}
		tcpStarted = true
		go func() {
			nc, err := l.dialTCP(tctx)
			tch <- result{nc: nc, err: err}
		}()
	}
	var errs []error
	pending := 1
	for pending > 0 {
		select {
		case r := <-qch:
			pending--
			if r.err == nil {
				l.preQUIC.Store(r.q)
				if tcpStarted {
					go func() { // the loser's connection, if any
						if r := <-tch; r.err == nil {
							_ = r.nc.Close()
						}
					}()
				}
				return TransportQUIC, nil
			}
			l.logger.Info("agent link: QUIC failed", "error", r.err)
			if key != "" && !relayRefused(r.err) {
				udpFailures.Store(key, time.Now())
			}
			errs = append(errs, fmt.Errorf("quic: %w", r.err))
			qch = nil
			if !tcpStarted && tcpOK {
				startTCP()
				pending++
			}
		case <-reached: // TCP waits for QUIC's redials
			reached, head = nil, nil
		case <-head:
			head = nil
			if !tcpStarted && tcpOK {
				startTCP()
				pending++
			}
		case r := <-tch:
			pending--
			if r.err == nil {
				l.preTCP.Store(&r.nc)
				if qch != nil {
					go func() { // QUIC's outcome: remembered when it failed
						r := <-qch
						if r.err != nil {
							if key != "" && !relayRefused(r.err) {
								udpFailures.Store(key, time.Now())
							}
							return
						}
						_ = r.q.CloseWithError(quiclink.CodeDone, "lost the race")
					}()
				}
				return TransportTCP, nil
			}
			errs = append(errs, fmt.Errorf("tcp: %w", r.err))
			tch = nil
		}
	}
	return "", errors.Join(errs...)
}

// dialTCP opens an agent-link connection to the relay's gRPC port: TLS,
// then the magic; the link hello is the Node's.
func (l *agentLink) dialTCP(ctx context.Context) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, dataHelloTimeout)
	defer cancel()
	nc, err := l.dial.Data(dctx)
	if err != nil {
		return nil, err
	}
	if d, ok := dctx.Deadline(); ok {
		_ = nc.SetWriteDeadline(d)
	}
	if _, err := nc.Write([]byte(dataplane.AgentLinkMagic)); err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetWriteDeadline(time.Time{})
	return nc, nil
}

func (l *agentLink) dialTCPNode(ctx context.Context, _ string) (net.Conn, error) {
	if nc := l.preTCP.Swap(nil); nc != nil {
		return *nc, nil
	}
	return l.dialTCP(ctx)
}

// dialQUIC dials the relay's UDP port and sends the bind token on the
// connection's first stream (dataplane.WriteLinkHello).
func (l *agentLink) dialQUIC(ctx context.Context, qc *quic.Config) (*quic.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, dataHelloTimeout)
	defer cancel()
	tc := l.dial.QUIC.TLS.Clone()
	tc.NextProtos = dataplane.AgentLinkALPNs()
	addr := net.JoinHostPort(l.dial.QUIC.Host, strconv.Itoa(l.offer.QUICPort))
	q, err := quic.DialAddr(dctx, addr, tc, qc)
	if err != nil {
		return nil, relaytrust.Explain(err)
	}
	st, err := q.OpenStreamSync(dctx)
	if err == nil {
		if d, ok := dctx.Deadline(); ok {
			_ = st.SetDeadline(d)
		}
		err = dataplane.WriteLinkHello(st, l.token)
		_ = st.Close()
	}
	if err != nil {
		_ = q.CloseWithError(quiclink.CodeDone, "hello failed")
		return nil, err
	}
	return q, nil
}

// dialQUICFirst dials the link's first QUIC connection, redialling one a
// relay refused (quicRefusedAttempts); reached is called at the first
// refusal. The Node's own redials (dialQUICNode) keep going with its
// backoff and remember no UDP failure.
func (l *agentLink) dialQUICFirst(ctx context.Context, reached func()) (*quic.Conn, error) {
	deadline := time.Now().Add(dataHelloTimeout)
	for attempt := 1; ; attempt++ {
		q, err := l.dialQUIC(ctx, l.quicNode.QUICConfig())
		if err == nil || !relayRefused(err) || attempt == quicRefusedAttempts || time.Now().After(deadline) {
			return q, err
		}
		if attempt == 1 {
			reached()
		}
		l.logger.Debug("agent link: the relay refused QUIC; redialling", "attempt", attempt, "error", err)
		select {
		case <-time.After(quicRefusedWait):
		case <-ctx.Done():
			return nil, err
		}
	}
}

func (l *agentLink) dialQUICNode(ctx context.Context, _ string, qc *quic.Config) (*quic.Conn, error) {
	q := l.preQUIC.Swap(nil)
	if q == nil {
		var err error
		if q, err = l.dialQUIC(ctx, qc); err != nil {
			return nil, err
		}
	}
	// ponytail: counted from the hello sent, not the relay's answer: a
	// connection another replica refuses counts for its round trip.
	l.growth.linkConn(1)
	context.AfterFunc(q.Context(), func() { l.growth.linkConn(-1) })
	return q, nil
}
