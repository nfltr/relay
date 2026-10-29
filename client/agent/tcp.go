// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/internal/bytequeue"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// tcpRelayBufSize is the read buffer size for TCP relay loops: the largest
// data frame the agent sends. A buffer stays pinned while its session's
// Read waits, so it is sized for per-frame throughput, not bulk memory.
const tcpRelayBufSize = 64 * 1024

// tcpWriteBatch bounds the queued bytes a session writes to its conn at
// once: a backlog of frames goes out in one writev instead of one write
// each.
const tcpWriteBatch = 256 << 10

// tcpSessionQueueBytes bounds the bytes queued for one session's target
// on a gRPC stream of a relay that keeps no per-session credit there. The
// stream's receive loop waits on a session holding this much unwritten
// data only while its target keeps taking, and at most tcpSessionStall
// (resetSession). Sessions with credit (a data connection, a gRPC stream
// whose relay announced its window) queue up to tcpDataWindow and the
// loop never waits.
// ponytail: against such a relay a target slower than its sender still
// paces the stream's other sessions; a relay with credit removes the wait.
const tcpSessionQueueBytes = 1 << 20

// tcpSessionStall is how long a gRPC stream's receive loop waits on one
// session's full queue, without credit, for its target to take anything
// before it resets that session (the relay's tcpSessionStall).
var tcpSessionStall = 10 * time.Second

// tcpRelayBufPool recycles read buffers used by TCP relay goroutines,
// reducing GC pressure during sustained high-throughput transfers.
var tcpRelayBufPool = sync.Pool{
	New: func() any { return make([]byte, tcpRelayBufSize) },
}

// tcpStream is a ConnectTCP gRPC stream or a data connection
// (github.com/nfltr/relay/proto/wire/dataplane).
type tcpStream interface {
	Send(*pb.TCPData) error
	Recv() (*pb.TCPData, error)
}

// tcpTunnel is one agent's ConnectTCP stream and its sessions.
type tcpTunnel struct {
	stream tcpStream
	logger *slog.Logger

	// sendCh feeds the stream's only sender: grpc-go forbids concurrent
	// SendMsg on one stream, and every session's reader shares this stream.
	// The queue also lets a reader read its next chunk while the previous
	// one is being sent. Unused on a data connection: sessions write it
	// themselves (enqueue).
	sendCh   chan *pb.TCPData
	stop     chan struct{} // closed when runTCPTunnel returns
	sendDone chan struct{} // closed when the sender stops

	mu       sync.Mutex
	sessions map[string]*bytequeue.Queue // relay -> target bytes per session
	aborts   map[string]func()           // cuts a session's target (resetSession)
	// peerHalf marks the queues the relay half-closed (TCPData.half): the
	// target's write side ends after them, its bytes keep going.
	peerHalf map[*bytequeue.Queue]bool
	// lost marks the queues the stream ended under (closeAll), neither
	// closed nor half-closed by the relay: their targets are reset.
	lost map[*bytequeue.Queue]bool

	growth *tcpStreamGrowth // shared by the agent's streams

	// dc is the stream when it is a data connection (tcp_dataplane.go).
	dc *dataplane.Conn
	// cr is the per-session credit: dc's, or a gRPC stream's whose relay
	// announced its window (dataplane.CreditHeader); nil without credit.
	cr *link.Credit
}

// tcpGrowAtSessions is how many sessions must be open at once before the
// agent opens the further streams its relay asked for.
const tcpGrowAtSessions = 2

// tcpStreamGrowth opens the further streams a relay asks for
// (tcpStreamsHeader) once the agent has tcpGrowAtSessions sessions open at
// once. Every stream costs the relay buffers and goroutines (about 40 KiB
// per stream), and most agents idle: one that never serves concurrent
// sessions keeps its one stream. A stream that ends (an auxiliary
// connection the relay retired after idling) is opened again the next time
// the agent is busy.
type tcpStreamGrowth struct {
	want   atomic.Int32 // streams the relay asked for in all; 0 until its header arrives
	active atomic.Int32 // sessions open on all of the agent's streams
	extra  atomic.Int32 // further streams open or opening
	open   func()       // opens one further stream and serves it until it ends
	// linkConns counts the primary's agent-link connections the relay
	// bound (link.Observer's ConnUp on TCP; a QUIC connection the Node
	// dialled, until it closes): the link is up while there is one, as
	// the relay counts it (TCPDispatcher.LinkUp), so the agent answers the
	// relay's heartbeats whenever the relay cannot see the link.
	linkConns atomic.Int32
}

func (g *tcpStreamGrowth) maybeGrow() {
	if g == nil || g.active.Load() < tcpGrowAtSessions {
		return
	}
	for {
		n := g.extra.Load()
		if n >= g.want.Load()-1 {
			return
		}
		if g.extra.CompareAndSwap(n, n+1) {
			go func() {
				g.open()
				g.extra.Add(-1)
			}()
		}
	}
}

// growOne opens one further stream unless one is open or opening.
func (g *tcpStreamGrowth) growOne() {
	if g != nil && g.want.Load() > 1 && g.extra.CompareAndSwap(0, 1) {
		go func() {
			g.open()
			g.extra.Add(-1)
		}()
	}
}

// linkUp reports whether the relay has an agent-link connection of the
// primary bound (TestAgentLinkUpOnlyWhileBound).
func (g *tcpStreamGrowth) linkUp() bool { return g != nil && g.linkConns.Load() > 0 }

func (g *tcpStreamGrowth) linkConn(n int32) {
	if g != nil {
		g.linkConns.Add(n)
	}
}

// linkConnObserver counts a TCP agent link's bound connections.
type linkConnObserver struct {
	link.NopObserver
	g *tcpStreamGrowth
}

func (o linkConnObserver) ConnUp(link.Identity)          { o.g.linkConn(1) }
func (o linkConnObserver) ConnDown(link.Identity, error) { o.g.linkConn(-1) }

func (g *tcpStreamGrowth) add(n int32) {
	if g != nil {
		g.active.Add(n)
		g.maybeGrow()
	}
}

// tcpSendQueueFrames bounds the frames waiting for the stream's sender.
const tcpSendQueueFrames = 64

func (t *tcpTunnel) runSender() {
	defer close(t.sendDone)
	for {
		select {
		case f := <-t.sendCh:
			if t.stream.Send(f) != nil {
				return
			}
		case <-t.stop:
			return
		}
	}
}

// send queues f for the stream. It fails once the stream is broken.
func (t *tcpTunnel) send(f *pb.TCPData) error {
	if t.cr != nil && isSessionData(f) {
		return t.sendData(f)
	}
	return t.enqueue(f)
}

func (t *tcpTunnel) enqueue(f *pb.TCPData) error {
	if t.dc != nil {
		// Written inline, or with other sessions' frames when a write is
		// in flight (dataplane.Conn): no hand-off to the sender.
		err := t.dc.Send(f)
		if err == nil {
			err = t.dc.Flush()
		}
		if err != nil {
			_ = t.dc.Close()
		}
		return err
	}
	select {
	case t.sendCh <- f:
		return nil
	case <-t.sendDone:
		return io.ErrClosedPipe
	}
}

// openSession registers a session's queue. Data frames that arrive before
// its conn exists wait there, in order.
func (t *tcpTunnel) openSession(id string) *bytequeue.Queue {
	q := bytequeue.New(tcpSessionQueueBytes)
	if t.cr != nil {
		q.SetLimit(tcpDataWindow)
		t.cr.Open(id)
		q.OnPop(func(n int) { t.cr.Consumed(id, n) })
	}
	t.mu.Lock()
	old := t.sessions[id]
	if old != nil {
		old.Close()
	}
	t.sessions[id] = q
	t.mu.Unlock()
	if old == nil {
		t.growth.add(1)
	}
	return q
}

func (t *tcpTunnel) session(id string) *bytequeue.Queue {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[id]
}

// closeSession forgets a session and closes its queue: its writer delivers
// what is queued, then closes the conn.
func (t *tcpTunnel) closeSession(id string, q *bytequeue.Queue) {
	t.mu.Lock()
	ours := t.sessions[id] == q
	if ours {
		delete(t.sessions, id)
		delete(t.aborts, id)
	}
	delete(t.peerHalf, q)
	t.mu.Unlock()
	q.Close()
	if ours {
		t.growth.add(-1)
		if t.cr != nil {
			t.cr.Forget(id)
		}
	}
}

// resetSession ends a session whose target took none of its bytes for
// tcpSessionStall on a stream without credit: the queued bytes are
// dropped, the target is cut and the relay told, so the stream's receive
// loop serves its other sessions again.
func (t *tcpTunnel) resetSession(id string, q *bytequeue.Queue) {
	t.mu.Lock()
	abort := t.aborts[id]
	t.mu.Unlock()
	t.closeSession(id, q)
	for {
		if _, ok := q.Pop(); !ok {
			break
		}
	}
	if abort != nil {
		abort()
	}
	go func() { _ = t.send(&pb.TCPData{SessionId: id, Close: true}) }() // the sender may be busy
}

// closeFrame ends a session at the relay's close, or its relay -> target
// direction at a half close (TCPData.half): the target reads EOF after
// what is queued, its bytes keep going. A whole close after a half one
// cuts the target, whose write side already ended.
func (t *tcpTunnel) closeFrame(id string, q *bytequeue.Queue, half bool) {
	t.mu.Lock()
	wasHalf := t.peerHalf[q]
	if half && t.sessions[id] == q {
		t.peerHalf[q] = true
	}
	abort := t.aborts[id]
	t.mu.Unlock()
	if half {
		q.Close()
		return
	}
	t.closeSession(id, q)
	if wasHalf && abort != nil {
		abort()
	}
}

// answerOpen answers session id's open: it is open (its target reached).
// On failure the session is closed.
func (t *tcpTunnel) answerOpen(id string, q *bytequeue.Queue) error {
	err := t.send(&pb.TCPData{SessionId: id, Data: dataplane.AppendAnswer(nil, 0, "")})
	if err != nil {
		t.closeSession(id, q)
	}
	return err
}

// refuseAnswered answers session id's open with reason and err, then
// closes it: its opener reads the answer, then the end.
func (t *tcpTunnel) refuseAnswered(id string, q *bytequeue.Queue, reason relayv1.ErrorReason, err error) {
	_ = t.send(&pb.TCPData{SessionId: id, Data: dataplane.AppendAnswer(nil, reason, err.Error())})
	t.closeSession(id, q)
	_ = t.send(&pb.TCPData{SessionId: id, Close: true})
}

// closeAll ends the sessions the stream ended under: a target the relay
// had not half-closed is reset, never ended cleanly, so it cannot take a
// truncated stream of the client's for a whole one
// (TestTCPTunnelStreamLossResetsTargets).
func (t *tcpTunnel) closeAll() {
	t.mu.Lock()
	n := len(t.sessions)
	t.lost = make(map[*bytequeue.Queue]bool, n)
	for id, q := range t.sessions {
		delete(t.sessions, id)
		if !t.peerHalf[q] {
			t.lost[q] = true
		}
		q.Close()
	}
	clear(t.aborts)
	clear(t.peerHalf)
	t.mu.Unlock()
	t.growth.add(-int32(n))
}

// pump moves bytes both ways between the stream and conn: the session's
// queue -> conn in a writer goroutine, conn -> stream here. It owns conn;
// the writer closes it once the queue is closed and drained.
func (t *tcpTunnel) pump(id string, q *bytequeue.Queue, conn net.Conn) {
	t.mu.Lock()
	if t.sessions[id] == q {
		t.aborts[id] = func() { _ = conn.Close() }
	}
	t.mu.Unlock()
	written := make(chan struct{})
	go func() {
		defer close(written)
		var bufs [][]byte
		for {
			var ok bool
			if bufs, ok = q.PopBatch(bufs[:0], tcpWriteBatch); !ok {
				t.mu.Lock()
				half, lost := t.peerHalf[q], t.lost[q]
				t.mu.Unlock()
				if cw, isTCP := conn.(interface{ CloseWrite() error }); half && isTCP {
					_ = cw.CloseWrite() // the relay's half close: the target's bytes keep going
					return
				}
				if tc, isTCP := conn.(*net.TCPConn); lost && isTCP {
					_ = tc.SetLinger(0) // an RST
				}
				_ = conn.Close()
				return
			}
			nb := net.Buffers(bufs) // one writev for a backlog
			_, err := nb.WriteTo(conn)
			clear(bufs)
			if err != nil {
				t.logger.Debug("tcp tunnel: target write error", "session", id, "error", err)
				t.closeSession(id, q)
				_ = conn.Close()
				return
			}
		}
	}()

	buf := tcpRelayBufPool.Get().([]byte)
	defer tcpRelayBufPool.Put(buf) //nolint:staticcheck
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			// buf is reused while the frame waits for the sender: copy.
			if t.send(&pb.TCPData{SessionId: id, Data: append([]byte(nil), buf[:n]...)}) != nil {
				break
			}
		}
		if readErr == io.EOF {
			// The target half-closed: so does the session, and the relay's
			// bytes keep going to the target until the relay's side ends
			// (a close no longer cuts them: closeFrame).
			t.mu.Lock()
			if t.sessions[id] == q {
				delete(t.aborts, id)
			}
			t.mu.Unlock()
			_ = t.send(&pb.TCPData{SessionId: id, Close: true, Half: true})
			<-written
			break
		}
		if readErr != nil {
			t.logger.Debug("tcp tunnel: target read error", "session", id, "error", readErr)
			_ = t.send(&pb.TCPData{SessionId: id, Close: true})
			break
		}
	}
	_ = conn.Close()
	t.closeSession(id, q)
}

// runTCPTunnel opens the ConnectTCP bidirectional gRPC stream and serves
// incoming open/data/close frames from the server.
//
// For each open frame the agent dials the requested target address (e.g.
// "localhost:22" for SSH or "localhost:3389" for RDP) and relays bytes in both
// directions until either side closes the connection. Each session writes to
// its target from its own goroutine, so one slow target does not block the
// receive loop that every session shares.
//
// When forwardAddr is non-empty, it overrides the server-provided target
// address for all sessions — useful for forwarding to non-localhost services
// (e.g. "kubernetes.default.svc:443").
//
// dial opens further connections to the relay: a busy agent puts its
// further streams on connections of their own (tcpBindHeader, RelayDialer).
//
// runTCPTunnel returns when the stream ends or ctx is cancelled.
// growth, when not nil, counts the tunnel's sessions for its caller.
func runTCPTunnel(ctx context.Context, client pb.DispatcherClient, dial RelayDialer, streamCtx context.Context, targets sessionTargets, e2eeTLS *e2eeTLSConfig, logger *slog.Logger, growth *tcpStreamGrowth) error {
	if targets.services != nil {
		for _, code := range targets.services.shareCodes() {
			streamCtx = metadata.AppendToOutgoingContext(streamCtx, sharePolicyHeader, code)
		}
	}
	if e2eeTLS != nil {
		// Name the shares whose policy this agent enforces on E2EE
		// sessions: the relay forwards a protected share only to a stream
		// that names it (relay tcpSharePolicyHeader).
		for _, code := range e2eeTLS.shareCodes {
			streamCtx = metadata.AppendToOutgoingContext(streamCtx, sharePolicyHeader, code)
		}
	}
	// Ask for per-session credit on the tunnel's gRPC streams: a relay that
	// keeps it there answers with its window (dataplane.CreditHeader).
	streamCtx = metadata.AppendToOutgoingContext(streamCtx, dataplane.CreditHeader, strconv.Itoa(tcpDataWindow))
	// Answer the opens that ask (TCPData.answer) once the target is reached.
	streamCtx = metadata.AppendToOutgoingContext(streamCtx, dataplane.AnswerHeader, "1")
	if v := targets.httpSessionsValue(); v != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, dataplane.HTTPSessionsHeader, v)
	}
	if t := dial.linkTransport(); t != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, dataplane.AgentLinkHeader, t)
	}
	if t := dial.park.parked(); t != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, linkResumeHeader, t)
	}
	stream, err := client.ConnectTCP(streamCtx)
	if err != nil {
		return err
	}
	logger.Info("tcp tunnel stream connected")
	// A relay that spreads sessions over several streams of one agent says
	// how many to open in its response header (relay dispatcher_tcp.go).
	// Each stream has its own gRPC write quota and sender, so concurrent
	// sessions stop queueing behind one another; the agent opens them once
	// it is busy (tcpStreamGrowth). An older relay sends no such header:
	// one stream, as before. A relay that also sends a bind token gets the
	// further streams each on a connection of its own, so they stop sharing
	// one HTTP/2 writer and reader at each end; it retires them once idle.
	// A relay that also offers the data plane (tcpDataPlaneHeader) takes
	// those connections as data connections: session frames without gRPC
	// or HTTP/2. One that fails falls back to gRPC for the tunnel's life.
	extraCtx, stopExtra := context.WithCancel(streamCtx)
	defer stopExtra()
	var token string // written before growth.want, read after
	var data bool    // the relay takes data connections (dataplane.Header); likewise
	var noData atomic.Bool
	if growth == nil {
		growth = &tcpStreamGrowth{}
	}
	serve := func(st tcpStream) error {
		return serveTCPStream(ctx, st, targets, nil, e2eeTLS, logger, growth, nil)
	}
	growth.open = func() {
		if data && dial.Data != nil && !noData.Load() {
			err := serveDataConn(extraCtx, dial, token, serve)
			if err == nil {
				return
			}
			logger.Debug("tcp tunnel: data connection failed; further streams use gRPC", "error", err)
			noData.Store(true)
		}
		if token == "" || dial.GRPC == nil {
			extra, err := client.ConnectTCP(extraCtx)
			if err != nil {
				growth.want.Store(1) // one failed to open: no more until the tunnel reconnects
				return
			}
			_ = serve(extra)
			return
		}
		if err := serveAuxConn(extraCtx, dial.GRPC, token, serve); err != nil {
			logger.Debug("tcp tunnel: auxiliary connection refused", "error", err)
			growth.want.Store(1) // one failed to open: no more until the tunnel reconnects
		}
	}
	// The agent link, where the relay offers it, is dialled when the relay
	// asks (lazyLink); its sessions ride the primary until then. Only an
	// agent link that failed leaves the further streams to open as before.
	lazy := newLazyLink(extraCtx, dial, stream.Header,
		newLinkSessions(dial.park, ctx, targets, e2eeTLS, logger, growth), logger)
	go func() {
		md, err := stream.Header()
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(firstValue(md, tcpStreamsHeader))
		token = firstValue(md, tcpBindHeader)
		if parked := dial.park.take(); parked.node != nil {
			if parked.token == token { // the relay resumed the link: its sessions go on
				logger.Info("agent link resumed by the new tcp tunnel stream")
				lazy.adopt(parked)
			} else {
				drainNow(parked.node)
			}
		}
		data = dataplane.PickVersion(md.Get(dataplane.Header)) > 0
		offer := dataplane.ParseAgentLinkOffer(md.Get(dataplane.AgentLinkHeader), md.Get(dataplane.AgentLinkQUICHeader))
		if quicOK, tcpOK := dial.linkPlan(offer); token != "" && (quicOK || tcpOK) {
			select {
			case <-lazy.failed:
			case <-extraCtx.Done():
				return // the primary ended; its sessions rode the agent link or the primary
			}
		}
		growth.want.Store(int32(min(n, tcpMaxStreams)))
		growth.maybeGrow()
	}()
	return serveTCPStream(ctx, stream, targets, e2eeTLS, e2eeTLS, logger, growth, lazy)
}

// serveAuxConn opens a connection with dial, binds a stream on it to the
// primary stream with token and serves it until it ends. It fails when the
// connection or the binding fails.
func serveAuxConn(ctx context.Context, dial func() (*grpc.ClientConn, error), token string, serve func(tcpStream) error) error {
	conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck
	st, err := pb.NewDispatcherClient(conn).ConnectTCP(metadata.AppendToOutgoingContext(ctx, tcpBindHeader, token))
	if err != nil {
		return err
	}
	md, err := st.Header()
	if err != nil {
		return err
	}
	if firstValue(md, tcpBindHeader) != token {
		_, err = st.Recv() // the refusal
		return fmt.Errorf("relay did not bind the connection: %w", err)
	}
	_ = serve(st)
	return nil
}

// tcpStreamsHeader is the ConnectTCP response header in which the relay
// asks for that many streams in all (relay tcpAgentStreamsHeader).
const tcpStreamsHeader = "x-nfltr-tcp-streams"

// tcpBindHeader is the relay's token for binding auxiliary connections to
// the primary stream: in the primary's response header, then in the
// request metadata of each stream on an auxiliary connection, echoed in its
// response header once bound (relay tcpBindHeader).
const tcpBindHeader = "x-nfltr-tcp-bind"

// tcpMaxStreams caps the streams one agent opens, whatever a relay asks.
const tcpMaxStreams = 8

func firstValue(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// serveTCPStream serves one ConnectTCP stream until it ends. Certificate
// rotation notices go out on it when rotate is set (one stream per agent);
// e2ee, when set, terminates E2EE sessions; lazy, when set (the primary),
// takes the relay's agent-link control frames.
func serveTCPStream(ctx context.Context, stream tcpStream, targets sessionTargets, rotate, e2ee *e2eeTLSConfig, logger *slog.Logger, growth *tcpStreamGrowth, lazy *lazyLink) error {
	t := &tcpTunnel{
		stream:   stream,
		logger:   logger,
		sendCh:   make(chan *pb.TCPData, tcpSendQueueFrames),
		stop:     make(chan struct{}),
		sendDone: make(chan struct{}),
		sessions: make(map[string]*bytequeue.Queue),
		aborts:   make(map[string]func()),
		peerHalf: make(map[*bytequeue.Queue]bool),
		growth:   growth,
	}
	t.dc, _ = stream.(*dataplane.Conn)
	if t.dc == nil { // a data connection is written inline (enqueue)
		go t.runSender()
	}
	defer close(t.stop)
	defer t.closeAll()
	if t.cr = t.streamCredit(stream); t.cr != nil && t.dc == nil {
		defer t.cr.Close() // senders waiting for credit give up
	}

	// Wire cert-rotation callback to send a _fingerprint control frame so
	// the server can update the endpoint registry without reconnecting.
	if rotate != nil {
		rotate.mu.Lock()
		rotate.onRotate = func(newFingerprint string) {
			if sendErr := t.send(&pb.TCPData{
				SessionId: fingerprintControlSessionID,
				Data:      []byte(newFingerprint),
			}); sendErr != nil {
				logger.Warn("failed to send fingerprint update", "error", sendErr)
			} else {
				logger.Info("sent fingerprint update to server", "fingerprint", newFingerprint)
			}
		}
		rotate.mu.Unlock()
		defer func() {
			rotate.mu.Lock()
			rotate.onRotate = nil
			rotate.mu.Unlock()
		}()
	}

	for {
		frame, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		id := frame.GetSessionId()
		switch {
		case id == dataplane.WindowSID && t.cr != nil && t.dc == nil:
			sid, n, err := dataplane.ParseWindowFrame(frame)
			if err == nil {
				err = t.cr.Grant(sid, n)
			}
			if err != nil {
				return err
			}

		case id == dataplane.AgentLinkSID && lazy != nil:
			lazy.control(string(frame.Data))

		case strings.HasPrefix(id, "_"):
			// Control frames (e.g. _heartbeat) belong to no session.

		case frame.Open:
			answer := frame.GetAnswer()
			p, err := planSession(frame, targets, e2ee)
			if err != nil {
				logSessionRefused(logger, id, err, targets)
				if answer {
					t.refuseAnswered(id, t.openSession(id), refusalReason(err), err)
					continue
				}
				_ = t.send(&pb.TCPData{SessionId: id, Close: true})
				continue
			}
			q := t.openSession(id)
			switch p.kind {
			case sessionHTTP:
				// HTTP sessions take a further stream (a data connection)
				// from the first one on; an idle agent holds none, and a
				// relay without HTTP sessions (nfltr-relay <= v0.15) never
				// makes it open one.
				growth.growOne()
				go t.serveHTTPSession(id, q, targets.http)
			case sessionE2EE:
				if answer && t.answerOpen(id, q) != nil {
					continue
				}
				go t.serveE2EE(id, q, e2ee, p.backend, p.client, p.wrap)
			default:
				go func() {
					conn, reason, dialErr := dialTarget(ctx, p.network, p.target)
					if dialErr != nil {
						logger.Warn("tcp tunnel: dial target failed",
							"session", id, "target", p.target, "error", dialErr)
						if answer {
							t.refuseAnswered(id, q, reason, dialErr)
							return
						}
						t.closeSession(id, q)
						_ = t.send(&pb.TCPData{SessionId: id, Close: true})
						return
					}
					if answer && t.answerOpen(id, q) != nil {
						_ = conn.Close()
						return
					}
					if p.kind == sessionE2EETCP {
						serveE2EETCP(newSessionConn(t, id, q), conn, e2ee, logger)
						return
					}
					t.pump(id, q, conn)
				}()
			}

		case frame.Close:
			if q := t.session(id); q != nil {
				t.closeFrame(id, q, frame.Half)
			}

		case len(frame.Data) > 0:
			q := t.session(id)
			if q == nil {
				continue
			}
			if t.cr != nil {
				if t.dc == nil { // a data connection charges its own frames
					if err := t.cr.Received(id, len(frame.Data)); err != nil {
						return err
					}
				}
				q.Push(frame.Data) // within its credit: never waits
				continue
			}
			if errors.Is(q.PushWithin(frame.Data, tcpSessionStall), bytequeue.ErrStalled) {
				logger.Warn("tcp tunnel: session reset: its target took none of its bytes",
					"session", id, "stall", tcpSessionStall)
				t.resetSession(id, q)
			}
		}
	}
}

// streamCredit is the per-session credit of t's stream: a data
// connection's, or a gRPC stream's whose relay announced its window in its
// response header (dataplane.CreditHeader); nil without. Its window
// updates go out as control frames on the stream (dataplane.WindowFrame).
func (t *tcpTunnel) streamCredit(stream tcpStream) *link.Credit {
	if t.dc != nil {
		return t.dc.Credit()
	}
	h, ok := stream.(interface{ Header() (metadata.MD, error) })
	if !ok {
		return nil
	}
	md, err := h.Header() // the relay sends it as it accepts the stream
	if err != nil {
		return nil
	}
	w, err := dataplane.ParseCreditHeader(firstValue(md, dataplane.CreditHeader))
	if err != nil {
		return nil
	}
	return link.NewCredit(tcpDataWindow, w, func(sid string, n int) { _ = t.enqueue(dataplane.WindowFrame(sid, n)) })
}

// RunTCPTunnel opens a raw TCP sidecar stream for commands that already manage
// their own HTTP tunnel lifecycle but still want to expose SSH, RDP, or other
// TCP services under the same agent identity.
//
// dial opens further connections to the relay for a busy tunnel; a zero
// RelayDialer keeps every stream on client's connection.
func RunTCPTunnel(ctx context.Context, client pb.DispatcherClient, dial RelayDialer, streamCtx context.Context, forwardAddr string, logger *slog.Logger) error {
	return runTCPTunnel(ctx, client, dial, streamCtx, sessionTargets{forwardAddr: forwardAddr}, nil, logger, nil)
}

// sessionTargets is where a tunnel's sessions go.
type sessionTargets struct {
	forwardAddr    string        // pins every raw session; "" dials the relay's target_addr
	defaultBackend string        // the backend of E2EE sessions
	services       *ServiceTable // when set, the only targets (the fields above unused)
	http           http.Handler  // serves sessions to dataplane.HTTPSessionTarget
	noRaw          bool          // refuses sessions that would dial a target
}

// RunServiceTunnel serves the ConnectTCP stream of an agent that serves
// named services (ServiceTable): raw sessions reach its tcp services, E2EE
// sessions (when e2ee is set) its http services, each under that service's
// share policy. Anything else is refused. dial is as for RunTCPTunnel.
func RunServiceTunnel(ctx context.Context, client pb.DispatcherClient, dial RelayDialer, streamCtx context.Context, services *ServiceTable, e2ee *E2EESetup, logger *slog.Logger) error {
	var cfg *e2eeTLSConfig
	if e2ee != nil {
		cfg = e2ee.cfg
	}
	return runTCPTunnel(ctx, client, dial, streamCtx, sessionTargets{services: services}, cfg, logger, nil)
}
