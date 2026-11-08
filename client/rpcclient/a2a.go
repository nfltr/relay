// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package rpcclient provides a gRPC-like client library for agent-to-agent and
// cluster-to-agent communication through the RPC server.
//
// The library hides the protocol details (pb.TunnelFrame, transaction IDs,
// heartbeat filtering, metadata encoding, EOM signaling) behind standard
// gRPC-style Send/Recv/CloseSend interfaces.
//
// # Agent-to-Agent (AgentTunnel)
//
// Agent is for on-premise agents that register with an AgentID and maintain a
// persistent multiplexed AgentTunnel connection. An Agent can both initiate
// calls to other agents and handle incoming calls.
//
// Client side (initiating calls):
//
//	agent, _ := rpcclient.Dial(ctx, "relay:9090", rpcclient.WithAgentID("agent-a"), rpcclient.WithAPIKey(key))
//	defer agent.Close()
//
//	// Unary call
//	resp, err := agent.Invoke(ctx, "agent-b", []byte("hello"))
//
//	// Streaming call
//	stream, _ := agent.NewStream(ctx, "agent-b")
//	stream.Send([]byte("msg1"))
//	stream.Send([]byte("msg2"))
//	stream.CloseSend()
//	for {
//	    resp, err := stream.Recv()
//	    if err == io.EOF { break }
//	}
//
// Server side (handling incoming calls):
//
//	agent, _ := rpcclient.Dial(ctx, "relay:9090", rpcclient.WithAgentID("agent-b"), rpcclient.WithAPIKey(key))
//	agent.Handle(func(stream rpcclient.ServerStream) error {
//	    for {
//	        data, err := stream.Recv()
//	        if err == io.EOF { break }
//	    }
//	    stream.SetHeader(rpcclient.MD{"content-type": "text/plain"})
//	    stream.Send([]byte("response"))
//	    return nil // or status.Errorf(codes.Internal, "...")
//	})
package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/grpcclient"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// MD is a set of key-value pairs carried alongside messages, analogous to
// gRPC metadata headers.
type MD map[string]string

// Response is a single response message from the target agent.
type Response struct {
	Data []byte
}

// AgentTunnel is the minimal interface required for the bidirectional stream.
// pb.Dispatcher_AgentTunnelClient satisfies this interface.
type AgentTunnel interface {
	Send(*pb.TunnelFrame) error
	Recv() (*pb.TunnelFrame, error)
}

// Handler processes incoming agent-to-agent calls. It mirrors a gRPC service
// method implementation: read requests via stream.Recv(), send responses via
// stream.Send(). Return nil for success or a gRPC status error
// (status.Errorf(codes.X, "...")).
type Handler func(stream ServerStream) error

// ---------------------------------------------------------------------------
// DialOption / CallOption
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

// Agent manages a single AgentTunnel connection to the RPC server. It can both
// initiate calls to other agents (client role) and handle incoming calls
// (server role). Heartbeats are consumed silently.
type Agent struct {
	agentID string
	ref     string           // the ref the relay registered it under (Ref)
	conn    *grpc.ClientConn // nil when created via NewAgent
	stream  AgentTunnel

	// a2aKeyring, when set, turns A2A E2EE on, both ways (keyed only): every
	// call it makes or serves is sealed under a key a peer must prove
	// (WithA2AE2EEPairingKeyFile, WithA2AE2EEKeyring, EnableA2AE2EE).
	a2aKeyring atomic.Pointer[A2AE2EEKeyring]
	// sessions are the keyed handshakes later calls reuse (a2a_e2ee_session.go).
	sessions a2aSessions
	// (tests: a restarted responder).

	// sendCh buffers outgoing TunnelFrames. A dedicated sendLoop goroutine
	// drains this channel and sends to the gRPC stream, eliminating mutex
	// contention under high concurrency while still reporting real transport
	// send success or failure back to the caller.
	sendCh chan outboundFrame
	// heartbeatCh keeps liveness frames from sitting behind large outbound
	// payload backlogs such as chunked artifact transfers.
	heartbeatCh chan *pb.TunnelFrame

	handler   Handler
	handlerMu sync.RWMutex

	// pending maps txnID → *clientStream for outgoing calls.
	pending sync.Map
	// incoming maps txnID → *serverStream for in-progress incoming calls.
	incoming sync.Map
	// drainAcks maps a Drain's txnID → the channel its acknowledgement closes.
	drainAcks sync.Map
	// callCredit and serveCredit are the per-call credit of the calls this
	// agent makes and serves (call_credit.go).
	callCredit, serveCredit *link.Credit

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// streamIO counts the stream's Send and Recv calls in flight: they run
	// on goroutines of their own so the loops can stop on ctx; Close waits
	// for them once it closed the connection (which ends them).
	streamIO sync.WaitGroup

	// done is closed when the receive loop exits (stream ended or error).
	done chan struct{}
	// streamErr holds the error that terminated the receive loop.
	streamErrMu   sync.RWMutex
	streamErr     error
	streamErrOnce sync.Once
	// heartbeatInterval is the per-agent heartbeat send frequency (0 = use global default).
	heartbeatInterval time.Duration
	liveness          agentwire.Liveness // how long past the relay's stated heartbeat recvLoop waits
	// outboundDataPending covers queued and in-flight non-heartbeat frames.
	outboundDataPending atomic.Int64
	// sendStallEpoch is the monotonic reference captured at agent creation;
	// lastFrameSentAt stores nanoseconds-since-this-epoch (monotonic, not
	// wall-clock) of the most recent successful stream.Send. Using a monotonic
	// offset means the watchdog ignores wall-clock jumps from system suspend
	// (e.g. laptop sleep on macOS, where mach_absolute_time pauses) or NTP
	// corrections — it only fires on real wakeful stalls, not on the host
	// having been frozen for 30+ minutes between ticks.
	sendStallEpoch  time.Time
	lastFrameSentAt atomic.Int64
}

// Conn returns the underlying gRPC client connection, or nil when the
// Agent was created via NewAgent (bufconn / in-process).
func (a *Agent) Conn() *grpc.ClientConn { return a.conn }

// sendFrame queues a non-heartbeat TunnelFrame for sending on the shared gRPC
// stream and waits until the dedicated sendLoop has written it or failed.
func (a *Agent) sendFrame(f *pb.TunnelFrame) error {
	a.outboundDataPending.Add(1)
	defer a.outboundDataPending.Add(-1)
	request := outboundFrame{frame: f, result: make(chan error, 1)}
	select {
	case a.sendCh <- request:
	case <-a.ctx.Done():
		if err := a.Err(); err != nil {
			return err
		}
		return a.ctx.Err()
	}

	select {
	case err := <-request.result:
		return err
	case <-a.ctx.Done():
		select {
		case err := <-request.result:
			return err
		default:
			return a.sendUnconfirmed() // queued: the send loop may have written it
		}
	}
}

// ErrSendUnconfirmed marks a frame the agent accepted for sending but closed
// before the write was reported: the peer may or may not have received it.
// Unlike a failed write, it is not proof that nothing was delivered.
var ErrSendUnconfirmed = errors.New("rpcclient: send unconfirmed")

type sendUnconfirmedError struct{ cause error }

func (e sendUnconfirmedError) Error() string {
	return ErrSendUnconfirmed.Error() + ": " + e.cause.Error()
}
func (e sendUnconfirmedError) Unwrap() error        { return e.cause }
func (e sendUnconfirmedError) Is(target error) bool { return target == ErrSendUnconfirmed }

// sendUnconfirmed is the agent's closing error marked ErrSendUnconfirmed.
func (a *Agent) sendUnconfirmed() error {
	cause := a.Err()
	if cause == nil {
		cause = a.ctx.Err()
	}
	return sendUnconfirmedError{cause: cause}
}

// Dial connects to the RPC server at target ("host:port") and opens an
// AgentTunnel bidirectional stream. It returns once the relay has
// registered the agent (ctx bounds the wait); a refused stream is its
// error. A background receive loop starts automatically.
// InstanceHeader carries a connection's process instance id (one per
// process, the same on every Dial of it) to the relay.
const InstanceHeader = "x-agent-instance"

// processInstanceID is this process's instance id (InstanceHeader).
var processInstanceID = uuid.New().String()

func Dial(ctx context.Context, target string, opts ...DialOption) (*Agent, error) {
	var do dialOptions
	for _, o := range opts {
		o(&do)
	}
	if do.agentID == "" {
		return nil, fmt.Errorf("rpcclient: AgentID required (use WithAgentID)")
	}
	keyring := do.a2aKeyring
	if do.a2aPairingKeyFile != "" {
		if keyring != nil {
			return nil, fmt.Errorf("rpcclient: give an A2A E2EE pairing key file or a keyring, not both")
		}
		key, err := LoadA2AE2EEPairingKey(do.a2aPairingKeyFile)
		if err != nil {
			return nil, err
		}
		keyring = a2aE2EEPairingKey(key)
	}
	if keyring != nil && !do.a2aE2EE {
		return nil, fmt.Errorf("rpcclient: an A2A E2EE pairing key needs E2EE on (--e2ee / NFLTR_A2A_E2EE)")
	}
	if do.a2aE2EE && keyring == nil {
		return nil, ErrA2AE2EENoKey
	}

	host, port := parseTarget(target)

	var conn *grpc.ClientConn
	var err error

	keepaliveParams := grpcclient.KeepaliveParams()
	if do.keepalive != nil {
		keepaliveParams = *do.keepalive
	}
	grpcClientOpts := []grpcclient.Option{grpcclient.WithKeepalive(keepaliveParams)}

	// mTLS: use client certificate authentication
	switch {
	case do.clientTLS != nil:
		conn, err = grpcclient.NewMTLSClientConn(host, port, do.clientTLS, grpcClientOpts...)
	case do.clientCert != "":
		tlsCfg, tlsErr := grpcclient.NewMTLSClientConfig(do.clientCert, do.clientKey, do.caFile)
		if tlsErr != nil {
			return nil, fmt.Errorf("rpcclient: mTLS config: %w", tlsErr)
		}
		conn, err = grpcclient.NewMTLSClientConn(host, port, tlsCfg, grpcClientOpts...)
	default:
		conn, err = grpcclient.NewClientConn(do.tlsEnable, host, port, grpcClientOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("rpcclient: dial %s: %w", target, err)
	}

	// ── Authentication ──────────────────────────────────────────────────
	var streamCtx context.Context
	switch {
	case do.apiKey != "":
		// Preferred: server-generated API key. The server derives the AgentID
		// from its key store — the agent cannot forge its own identity.
		streamCtx = grpcmd.NewOutgoingContext(ctx, grpcmd.Pairs("x-api-key", do.apiKey))
	case do.clientCert != "" || do.clientTLS != nil:
		// mTLS: the TLS handshake already authenticates the agent.
		streamCtx = ctx
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("rpcclient: no authentication configured — use WithAPIKey() or WithClientCert()")
	}

	// ── Fleet Labels ────────────────────────────────────────────────────
	if labels := agentwire.EncodeLabels(do.labels); labels != "" {
		streamCtx = grpcmd.AppendToOutgoingContext(streamCtx, agentwire.LabelsKey, labels)
	}

	// ── Capabilities ────────────────────────────────────────────────────
	// Attach capabilities as "x-agent-capabilities" header: p2p,ssh,http
	if len(do.capabilities) > 0 {
		streamCtx = grpcmd.AppendToOutgoingContext(streamCtx, "x-agent-capabilities", strings.Join(do.capabilities, ","))
	}

	// Send the agent identity so the server can apply --name scoping via
	// ScopedAgentID. Without this, the server only sees the key's base
	// identity and custom names from WithAgentID are ignored.
	streamCtx = grpcmd.AppendToOutgoingContext(streamCtx, "x-agent-id", do.agentID)
	// This process's instance: the relay tells a reconnect of this process
	// (it silently ends the older stream) from another process taking the
	// same agent id (the older one is told it was replaced, which is final).
	streamCtx = grpcmd.AppendToOutgoingContext(streamCtx, InstanceHeader, processInstanceID)
	liveness := do.liveness
	if liveness == (agentwire.Liveness{}) {
		liveness = agentwire.LivenessDefault
	}
	streamCtx = grpcmd.AppendToOutgoingContext(streamCtx, agentwire.HeartbeatPairs(agentwire.HeartbeatAskKey, liveness.Interval)...)

	client := pb.NewDispatcherClient(conn)
	upStream, err := client.AgentTunnel(streamCtx)
	ref := do.agentID
	if err == nil {
		// The relay sends its headers once it has registered the agent:
		// from Dial's return the agent is routable. A stream that ended
		// first (nil headers) says why on Recv.
		md, _ := upStream.Header()
		if md == nil {
			_, err = upStream.Recv()
		}
		if v := md.Get(agentwire.AgentRefKey); len(v) > 0 {
			ref = v[0]
		}
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("rpcclient: upstream: %w", err)
	}

	a := newAgent(do.agentID, ref, upStream, ctx, do.heartbeatInterval, true, liveness)
	if keyring != nil {
		a.a2aKeyring.Store(&keyring)
	}
	a.conn = conn
	return a, nil
}

// NewAgent creates an Agent from an existing AgentTunnel (useful for testing or
// when the caller manages the gRPC connection).
func NewAgent(agentID string, s AgentTunnel, opts ...AgentOption) *Agent {
	var options agentOptions
	for _, opt := range opts {
		opt(&options)
	}
	ref := options.ref
	if ref == "" {
		ref = agentID
	}
	return newAgent(agentID, ref, s, context.Background(), 0, !options.noHeartbeat, agentwire.LivenessDefault)
}

func newAgent(agentID, ref string, s AgentTunnel, ctx context.Context, heartbeatInterval time.Duration, heartbeat bool, liveness agentwire.Liveness) *Agent {
	agentCtx, cancel := context.WithCancel(ctx)
	a := &Agent{
		agentID:           agentID,
		ref:               ref,
		stream:            s,
		ctx:               agentCtx,
		cancel:            cancel,
		done:              make(chan struct{}),
		sendCh:            make(chan outboundFrame, 256), // buffered send queue
		heartbeatCh:       make(chan *pb.TunnelFrame, 1),
		heartbeatInterval: heartbeatInterval,
		liveness:          liveness,
	}
	a.newCallCredits()
	context.AfterFunc(agentCtx, func() { // senders waiting for credit give up
		a.callCredit.Close()
		a.serveCredit.Close()
	})
	// Seed the stall watchdog so it measures from agent creation forward and
	// uses a monotonic reference (immune to wall-clock jumps from suspend/NTP).
	a.sendStallEpoch = time.Now()
	a.lastFrameSentAt.Store(int64(time.Since(a.sendStallEpoch)))
	a.wg.Add(1)
	go a.recvLoop()
	if heartbeat {
		a.wg.Add(1)
		go a.heartbeatLoop()
	}
	a.wg.Add(1)
	go a.sendLoop() // dedicate goroutine drains sendCh → stream.Send
	return a
}

// Ref is the ref the relay registered this agent under ("<machine
// id>-<service>", its AgentRefKey header on Dial), else its agent id: the
// callee its A2A E2EE calls name, and the caller its calls state.
func (a *Agent) Ref() string { return a.ref }

// Close shuts down the Agent, cancels in-flight calls, and closes the
// underlying gRPC connection (if created by Dial). It does not drain: a call
// still running ends with its handler's context cancelled and its end is not
// sent (the relay ends it for its caller as its target disconnected); Drain
// before Close answers every delivered call first. A Dial'd agent's Close
// returns once every goroutine it started has ended, a Send or Recv still
// running on the stream included (closing the connection ends them). The
// AgentTunnel given to NewAgent is its caller's: a Send or Recv blocked on
// it ends when the caller ends that tunnel, not by Close.
func (a *Agent) Close() error {
	a.cancel()
	a.wg.Wait()
	if a.conn == nil {
		return nil
	}
	err := a.conn.Close()
	a.streamIO.Wait()
	return err
}

// Done returns a channel that is closed when the agent's receive loop exits
// (stream ended, stream error, or Close was called). Callers can select on
// this to detect when the agent is no longer processing messages.
func (a *Agent) Done() <-chan struct{} { return a.done }

// Err returns the error that caused the receive loop to exit, or nil if the
// agent was closed cleanly. Only valid after Done() is closed.
func (a *Agent) Err() error {
	a.streamErrMu.RLock()
	defer a.streamErrMu.RUnlock()
	return a.streamErr
}

// EnableA2AE2EE turns on transparent end-to-end encryption for A2A streams on
// this Agent, keyed by kr (A2A E2EE is keyed only: a nil kr is
// ErrA2AE2EENoKey). It is for in-process agents created with NewAgent().
func (a *Agent) EnableA2AE2EE(kr A2AE2EEKeyring) error {
	if kr == nil {
		return ErrA2AE2EENoKey
	}
	a.a2aKeyring.Store(&kr)
	return nil
}

// connectionClosed is the error a call pending on this closed connection
// ends with: ErrConnectionClosed, carrying the transport failure if any.
func (a *Agent) connectionClosed() error { return connectionClosedError{cause: a.Err()} }

func (a *Agent) setStreamErr(err error) {
	if err == nil {
		return
	}
	a.streamErrOnce.Do(func() {
		a.streamErrMu.Lock()
		a.streamErr = err
		a.streamErrMu.Unlock()
	})
}

// Handle registers a handler for incoming agent-to-agent calls. Each incoming
// call invokes the handler in a new goroutine.
func (a *Agent) Handle(h Handler) {
	a.handlerMu.Lock()
	a.handler = h
	a.handlerMu.Unlock()
}

// Invoke performs a unary call: sends data to targetAgentID and returns the
// first response. It is a convenience wrapper around NewStream.
func (a *Agent) Invoke(ctx context.Context, targetAgentID string, data []byte, opts ...CallOption) ([]byte, error) {
	cs, err := a.NewStream(ctx, targetAgentID, opts...)
	if err != nil {
		return nil, err
	}
	if err := cs.Send(data); err != nil {
		return nil, err
	}
	if err := cs.CloseSend(); err != nil {
		return nil, err
	}
	resp, err := cs.Recv()
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// WarmA2AE2EE runs the A2A E2EE handshake with targetAgentID alone, with
// no call: the session it leaves makes the next call to it resume, its
// request sent before anything comes back (a2a_e2ee_session.go). Call it
// when a peer process appears, so its first call costs no round trip more
// than later ones. A request never rides the handshake: early data under
// the key alone would be replayable (spec/proverif mutant early-data). A
// no-op with a session already, or to the relay's own agent; without keys
// ErrA2AE2EENoKey.
func (a *Agent) WarmA2AE2EE(ctx context.Context, targetAgentID string) error {
	kr := a.keyring()
	if kr == nil {
		return ErrA2AE2EENoKey
	}
	if targetAgentID == RelayAgentID || a.sessions.hasOut(targetAgentID, kr) {
		return nil
	}
	cs := &clientStream{
		agent:         a,
		txnID:         uuid.New().String(),
		targetAgentID: targetAgentID,
		sourceAgentID: a.agentID,
		responseCh:    make(chan *pb.TunnelFrame, 1),
		done:          make(chan struct{}),
		ended:         make(chan struct{}),
		headerCh:      make(chan struct{}),
		ctx:           ctx,
	}
	if dl, ok := ctx.Deadline(); ok {
		cs.deadlineMs = dl.UnixMilli()
	}
	cs.e2ee = newA2AE2EEState(cs.txnID, a.ref, targetAgentID, kr)
	cs.e2ee.warm = true
	a.pending.Store(cs.txnID, cs)
	defer a.pending.Delete(cs.txnID)
	return cs.ensureE2EEHandshake()
}

// NewStream opens a bidirectional streaming call to targetAgentID. The returned
// ClientStream mirrors grpc.ClientStream.
func (a *Agent) NewStream(ctx context.Context, targetAgentID string, opts ...CallOption) (ClientStream, error) {
	co := callOptions{messageType: "a2a-request"}
	for _, o := range opts {
		o(&co)
	}

	var deadlineMs int64
	if dl, ok := ctx.Deadline(); ok {
		deadlineMs = dl.UnixMilli()
	}

	cs := &clientStream{
		agent:         a,
		txnID:         uuid.New().String(),
		targetAgentID: targetAgentID,
		sourceAgentID: a.agentID,
		msgType:       co.messageType,
		deadlineMs:    deadlineMs,
		responseCh:    make(chan *pb.TunnelFrame, ResponseWindow+1), // + the call's end
		done:          make(chan struct{}),
		ended:         make(chan struct{}),
		headerCh:      make(chan struct{}),
		ctx:           ctx,
	}
	// A stream to the relay's own agent ends at the relay: E2EE to it would
	// protect nothing TLS does not, and the relay cannot hold a pairing key.
	if a.keyring() != nil && targetAgentID != RelayAgentID {
		kr := a.keyring()
		if s, c := a.sessions.takeCall(targetAgentID, kr); s != nil {
			cs.e2ee = newResumedA2AE2EEState(cs.txnID, s, c, kr)
		} else {
			cs.e2ee = newA2AE2EEState(cs.txnID, a.ref, targetAgentID, kr)
		}
	}
	a.callCredit.Open(cs.txnID)
	traceCCOpen(a, cs.txnID, true)
	a.pending.Store(cs.txnID, cs)
	go a.removePendingClientStreamOnContextDone(cs)
	return cs, nil
}

func (a *Agent) removePendingClientStreamOnContextDone(cs *clientStream) {
	defer close(cs.ended)
	defer a.callCredit.Forget(cs.txnID) // a Send waiting for credit returns
	select {
	case <-cs.ctx.Done():
		if pending, ok := a.pending.Load(cs.txnID); ok && pending == cs {
			a.pending.Delete(cs.txnID)
			traceCC(a, "Cancel", cs.txnID, 0)
			// The caller left: its target stops (its handler may be
			// waiting for credit the caller will no longer grant).
			cs.sendCancel()
		}
	case <-cs.done:
	case <-a.ctx.Done():
	}
}

// recvLoop reads messages from the AgentTunnel and routes them to the
// appropriate clientStream (outgoing call response) or serverStream
// (incoming call request). Heartbeats are silently consumed.
//
// A separate reader goroutine ensures Close() can interrupt even when
// stream.Recv() is blocked (e.g. with mock streams in tests).
func (a *Agent) recvLoop() {
	defer a.wg.Done()
	defer close(a.done)

	type recvResult struct {
		msg *pb.TunnelFrame
		err error
	}
	ch := make(chan recvResult)
	limits := make(chan time.Duration, 1)

	a.streamIO.Go(func() {
		if h, ok := a.stream.(interface{ Header() (grpcmd.MD, error) }); ok {
			// The relay sends its headers when it accepts the stream (at the
			// latest with its first frame); they state its heartbeat.
			md, _ := h.Header()
			limits <- a.liveness.DeadAfter(agentwire.Heartbeat(md, agentwire.HeartbeatKey))
		}
		for {
			msg, err := a.stream.Recv()
			select {
			case ch <- recvResult{msg, err}:
			case <-a.ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	})

	// silence fires when the relay sent nothing for its silence limit: a
	// relay that died, or a path that dropped, without a FIN reaching here
	// would otherwise hold this connection until the transport keepalive
	// gives up.
	var silence <-chan time.Time
	var silenceTimer *time.Timer
	var limit time.Duration
	defer func() {
		if silenceTimer != nil {
			silenceTimer.Stop()
		}
	}()
	for {
		select {
		case limit = <-limits:
			if limit > 0 {
				silenceTimer = time.NewTimer(limit)
				silence = silenceTimer.C
			}
		case <-silence:
			a.setStreamErr(fmt.Errorf("rpcclient: no frame from the relay for %s: %w", limit, ErrRelaySilent))
			a.cancel()
			a.closePendingClientStreams()
			return
		case r := <-ch:
			if silenceTimer != nil {
				silenceTimer.Reset(limit)
			}
			if r.err != nil {
				if a.ctx.Err() == nil {
					// The relay closing the tunnel, even cleanly, is a lost
					// connection: Err reports it, so reconnect paths redial.
					if r.err == io.EOF {
						a.setStreamErr(connectionClosedError{})
					} else {
						a.setStreamErr(r.err)
					}
				}
				// The tunnel is gone: end the send and heartbeat loops too.
				a.cancel()
				a.closePendingClientStreams()
				return
			}
			if r.msg == nil || proto.Size(r.msg) == 0 || r.msg.TransactionId == "" {
				continue
			}
			a.handleMessage(r.msg)
		case <-a.ctx.Done():
			a.closePendingClientStreams()
			return
		}
	}
}

// closePendingClientStreams ends every call still pending on this connection
// with ErrConnectionClosed, never io.EOF: the peer did not end them.
func (a *Agent) closePendingClientStreams() {
	err := a.connectionClosed()
	a.pending.Range(func(key, val any) bool {
		cs := val.(*clientStream)
		cs.setResponseError(err)
		cs.closeResponses()
		a.pending.Delete(key)
		return true
	})
}

// sendLoop drains the outbound queues and sends each frame to the gRPC stream.
// Heartbeats are sent ahead of regular traffic so long-lived artifact uploads
// do not starve liveness checks. If a send fails, the error is recorded and
// the context is cancelled to terminate the agent. For transient errors like
// io.EOF during artifact transfers, the orchestrator can detect the error and
// retry with a new stream, so we return early to allow recv to also terminate.
func (a *Agent) sendLoop() {
	defer a.wg.Done()

	for {
		var f *pb.TunnelFrame
		var result chan error
		heartbeat := false
		select {
		case <-a.ctx.Done():
			return
		case f = <-a.heartbeatCh:
			heartbeat = true
		default:
			select {
			case <-a.ctx.Done():
				return
			case f = <-a.heartbeatCh:
				heartbeat = true
			case request := <-a.sendCh:
				f = request.frame
				result = request.result
			}
		}
		if heartbeat && !a.heartbeatNeeded() {
			continue
		}

		// stream.Send can block forever on a full or half-open transport
		// (mock tunnels in tests, stalled gRPC). Race it against a.ctx so
		// Agent.Close always completes instead of wedging on WaitGroup.Wait.
		sendErrCh := make(chan error, 1)
		a.streamIO.Go(func() { sendErrCh <- a.stream.Send(f) })
		var err error
		select {
		case err = <-sendErrCh:
		case <-a.ctx.Done():
			if result != nil {
				result <- a.sendUnconfirmed() // the write is still in flight
			}
			return
		}
		if err != nil {
			wrapped := fmt.Errorf("rpcclient: send: %w", err)
			if result != nil {
				result <- wrapped
			}
			if a.ctx.Err() != nil {
				return
			}
			a.setStreamErr(wrapped)
			// A send failure means the stream is broken. Cancel the agent so
			// recvLoop exits promptly and the worker's retryLoop re-dials.
			//
			// This previously special-cased io.EOF by returning WITHOUT
			// cancelling — "let recvLoop detect the stream error naturally" so
			// an in-flight transfer could retry on a new stream. But on a
			// HALF-OPEN connection (send side dead, recv side silent)
			// stream.Recv() can block indefinitely with no error, so recvLoop
			// never notices, a.ctx is never cancelled, the connection loop
			// never returns, and the worker hangs on a dead stream forever —
			// never reconnecting, so a completed task's terminal status is
			// never re-reported (observed: actor-0 hung 28m after a send EOF).
			// Cancelling here yields the SAME "retry with a new stream"
			// outcome the EOF path wanted, but guaranteed rather than
			// dependent on a Recv that may never return.
			a.cancel()
			return
		}
		// Record successful send time for the stall watchdog in heartbeatLoop.
		// Stored as monotonic-since-sendStallEpoch so suspend gaps don't count.
		a.lastFrameSentAt.Store(int64(time.Since(a.sendStallEpoch)))
		if result != nil {
			result <- nil
		}
	}
}

// handleMessage routes a single incoming message.
func (a *Agent) handleMessage(msg *pb.TunnelFrame) {
	txnID := msg.TransactionId

	switch msg.GetMessageType() {
	case a2aE2EEInitMessageType: // an E2EE call's start
		clLock()
		traceCL(a, a.handleE2EEInit(msg), txnID, msg)
		clUnlock()
		return
	case a2aE2EEWarmMessageType: // a handshake with no call
		clLock()
		traceCL(a, a.handleE2EEWarm(msg), txnID, msg)
		clUnlock()
		return
	case a2aE2EEResumeMessageType: // a call's start on a session
		clLock()
		traceCL(a, a.handleE2EEResume(msg), txnID, msg)
		clUnlock()
		return
	case a2aE2EEResumedMessageType, a2aE2EEUnknownMessageType:
		if val, ok := a.pending.Load(txnID); ok && val.(*clientStream).e2ee != nil {
			val.(*clientStream).resumeAnswered(msg.GetMessageType() == a2aE2EEResumedMessageType)
		}
		return
	case a2aE2EEv1InitMessageType, a2aE2EEv1Init0RTTMessageType: // wire v1's call start
		clLock()
		a.sendA2AControlError(txnID, codes.FailedPrecondition, "rpcclient: "+a2aE2EEv1Refusal+" (this agent speaks v2)")
		traceCL(a, "Refuse", txnID, msg)
		clUnlock()
		return
	case a2aE2EEv1AckMessageType, a2aE2EEv1RetryMessageType:
		if val, ok := a.pending.Load(txnID); ok && val.(*clientStream).e2ee != nil {
			val.(*clientStream).failE2EE(status.Error(codes.FailedPrecondition, "rpcclient: the target answered with "+a2aE2EEv1Refusal))
		}
		return
	case AgentDrainAckMessageType:
		a.handleDrainAck(txnID)
		return
	case WindowMessageType:
		a.handleWindow(msg)
		return
	case a2aE2EEAckMessageType:
		if val, ok := a.pending.Load(txnID); ok {
			cs := val.(*clientStream)
			if cs.e2ee != nil {
				if err := cs.e2ee.complete(msg.GetPayload()); err != nil {
					log.Printf("rpcclient: failed to complete A2A E2EE handshake for txn %s: %v", txnID, err)
				} else if s := cs.e2ee.established; s != nil {
					a.sessions.putOut(cs.targetAgentID, s)
				}
			}
		}
		return
	}

	// Cancel message.
	if msg.GetMessageType() == "cancel" {
		clLock()
		ev := "Drop"
		if val, ok := a.incoming.Load(txnID); ok {
			val.(*serverStream).end()
			ev = "Serve"
		}
		traceCL(a, ev, txnID, msg)
		clUnlock()
		return
	}

	// Response to a pending outgoing call.
	if val, ok := a.pending.Load(txnID); ok {
		cs := val.(*clientStream)

		if cs.e2ee != nil && (cs.e2ee.awaitingHandshake() || cs.e2ee.resuming()) && msg.GetMessageType() == "error" {
			detail := msg.GetStatusDetail()
			code := codes.Code(msg.GetStatusCode())
			if code == 0 {
				code = codes.FailedPrecondition
			}
			err := status.Error(code, detail)
			cs.e2ee.fail(err)
			cs.setResponseError(err)
			cs.closeResponses()
			a.pending.Delete(txnID)
			return
		}

		// Resolve Header() on first response so it doesn't block before Recv().
		// In standard gRPC, Header() returns as soon as the server sends
		// initial metadata; we mirror that by closing headerCh here. An
		// E2EE call's headers are sealed with its first response: Recv
		// resolves them (recvE2EE).
		if cs.e2ee == nil {
			cs.headerOnce.Do(func() {
				if im := msg.GetRouting().GetInitialMetadata(); len(im) > 0 {
					cs.header = MD(im)
				}
				close(cs.headerCh)
			})
		}

		switch err := cs.pushResponse(msg); {
		case errors.Is(err, errPastWindow):
			cs.refuse(err)
			return
		case err != nil: // the call or the agent ended
			if cs.ctx.Err() != nil {
				a.pending.Delete(txnID)
			}
			return
		}
		if msg.GetEom() {
			cs.closeResponses()
			a.pending.Delete(txnID)
		}
		return
	}

	clLock()
	traceCL(a, a.handleRequest(msg), txnID, msg)
	clUnlock()
}

// handleRequest takes a request frame of a call this agent serves or may
// start, and returns the step of spec/CallLifecycle.tla it took ("" for a
// frame that is no request): Serve, Start, Drop or Refuse.
func (a *Agent) handleRequest(msg *pb.TunnelFrame) string {
	txnID := msg.TransactionId
	// Continuation of an existing incoming call.
	if val, ok := a.incoming.Load(txnID); ok {
		ss := val.(*serverStream)
		// 2026-05-24 deflake: route the send through pushRequest +
		// closeRequests so a concurrent close cannot race the send and
		// panic. See serverStream.closeRequests + pushRequest.
		if errors.Is(ss.pushRequest(msg), errPastWindow) {
			a.refuseCall(ss, "its caller sent past the call's window")
			return "Serve"
		}
		if msg.GetEom() {
			ss.closeRequests()
		}
		return "Serve"
	}

	// A unary handler can validly return after consuming the request payload
	// but before the caller's empty CloseSend marker arrives. Once the handler
	// finishes, the incoming stream is removed; that late marker must not be
	// interpreted as a new request.
	if msg.GetEom() && len(msg.GetPayload()) == 0 {
		return "Drop"
	}

	// A response, status or error for a transaction this agent no longer
	// tracks is never a request; nor is a continuation: a later frame of a
	// call whose handler returned (spec/CallLifecycle.tla AtMostOneCall:
	// the frame does not start a second call, and the agent keeps nothing
	// per ended call to know it: NoEndedEntry).
	switch msg.GetMessageType() {
	case "error", "a2a-response", "a2a-status":
		return ""
	}
	if msg.GetContinuation() {
		return "Drop"
	}

	// An agent that encrypts its own streams is keyed: its keys declare the
	// relay untrusted, so it refuses every plaintext request, the relay's too.
	if a.keyring() != nil {
		a.sendA2AControlError(txnID, codes.FailedPrecondition, fmt.Sprintf(
			"rpcclient: agent %s requires end-to-end encrypted A2A streams; %s sent plaintext: call it with its A2A E2EE key, or upgrade the caller",
			a.agentID, msg.GetRouting().GetAgentId()))
		return "Refuse"
	}

	// New incoming call — create serverStream and invoke handler.
	a.handlerMu.RLock()
	h := a.handler
	a.handlerMu.RUnlock()
	if h == nil {
		return "Refuse"
	}

	ss := a.newServerStream(msg, nil)
	a.incoming.Store(txnID, ss)
	// A fresh call's credit and buffer always take its first frame, so it
	// is never refused here (TestFirstFrameFitsAFreshCall;
	// spec/CallLifecycle.tla mutant CL:refused-first-kept: a refusal here
	// kept the entry).
	_ = ss.pushRequest(msg)
	if msg.GetEom() {
		ss.closeRequests()
	}

	a.wg.Add(1)
	go a.handleCall(ss, h)
	return "Start"
}

// refuseCall ends an incoming call whose caller broke its credit (why):
// the handler's context is cancelled, the caller gets ResourceExhausted,
// and the call's later frames are dropped (pushRequest: the call ended).
// The connection's other calls go on.
func (a *Agent) refuseCall(ss *serverStream, why string) {
	ss.end()
	ss.closeRequests()
	log.Printf("rpcclient: refused incoming call %s: %s", ss.txnID, why)
	go a.sendA2AControlError(ss.txnID, codes.ResourceExhausted, fmt.Sprintf( // the receive loop never waits on a send
		"rpcclient: agent %s refused the call: %s", a.agentID, why))
}

// endServed deletes the entry of a call this agent served once its handler
// returned (spec/CallLifecycle.tla Return): nothing of it is kept.
func (a *Agent) endServed(txnID string) {
	clLock()
	a.incoming.Delete(txnID)
	traceCL(a, "Return", txnID, nil)
	clUnlock()
}

// handleCall runs the handler and sends the final status trailer.
func (a *Agent) handleCall(ss *serverStream, h Handler) {
	defer a.wg.Done()
	defer a.endServed(ss.txnID)
	defer ss.end()

	err := h(ss)

	// Send trailing status with EOM (mirrors gRPC trailing metadata + status).
	var code codes.Code
	var detail string
	if err != nil {
		if st, ok := status.FromError(err); ok {
			code = st.Code()
			detail = st.Message()
		} else {
			code = codes.Internal
			detail = err.Error()
		}
	}

	// An E2EE call's end is sealed (END, or ERROR with the code and
	// detail): the caller takes it only from the handler.
	var statusPayload []byte
	if ss.e2ee != nil {
		t, body := a2aFrameEnd, []byte(nil)
		if code != codes.OK {
			t, body = a2aFrameError, a2aErrorBody(code, detail)
		}
		ciphertext, encErr := ss.e2ee.seal(t, body)
		if encErr != nil {
			// Never the handler's words in the clear: the reason it could not be sealed (a revoked key).
			log.Printf("rpcclient: failed to seal the end of txn %s: %v", ss.txnID, encErr)
			detail = encErr.Error()
		} else {
			statusPayload = ciphertext
			detail = ""
		}
	}

	// The terminal a2a-status frame is the one frame that must not be
	// dropped: losing it makes the orchestrator record a finished task as
	// never-completed (the "0/N completed" lost-session-binding that breaks
	// auto verify/integrate). Unlike best-effort progress frames, retry it
	// across transient send failures (e.g. a stream reconnect mid-send) so a
	// brief flap doesn't lose the result. Persistent disconnects still fall
	// through to the rehydrate-on-reconnect path.
	send := func() error {
		return a.sendFrame(&pb.TunnelFrame{
			Payload:       statusPayload,
			MessageType:   "a2a-status",
			TransactionId: ss.txnID,
			Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
			Routing:       &pb.RoutingInfo{AgentId: a.agentID},
			Eom:           true,
			StatusCode:    int32(code),
			StatusDetail:  detail,
		})
	}
	switch sendErr := sendStatusTrailerWithRetry(a.ctx, send, statusTrailerSendAttempts, statusTrailerBackoff); {
	case sendErr == nil:
	case a.ctx.Err() != nil && a.Err() == nil:
		// Closed: Close does not drain (Drain does); the relay ends the call
		// for its caller as its target disconnected.
		log.Printf("rpcclient: closed before the end of txn %s was sent; Drain before Close delivers it", ss.txnID)
	default:
		log.Printf("rpcclient: failed to send a2a-status trailer for txn %s: %v", ss.txnID, sendErr)
	}
}

// statusTrailerSendAttempts bounds how many times handleCall retries the
// terminal a2a-status frame before giving up to the rehydrate-on-reconnect
// path. With statusTrailerBackoff this spans ~10s of stream flap.
const statusTrailerSendAttempts = 6

// statusTrailerBackoff returns the delay before retry attempt N+1 of the
// terminal status frame: 250ms, 500ms, 1s, 2s, then capped at 3s — long
// enough to let the reconnect loop re-establish the stream between attempts.
func statusTrailerBackoff(attempt int) time.Duration {
	d := min(250*time.Millisecond*time.Duration(int64(1)<<(attempt-1)), 3*time.Second)
	return d
}

// sendStatusTrailerWithRetry delivers the terminal status frame, retrying on
// transient send failures so a completed task's status reaches the
// orchestrator across a brief stream reconnect. Returns nil once delivered,
// or the last error after exhausting attempts or when ctx is done (agent
// shutdown). send is a.sendFrame in production; backoff/ctx are injectable so
// the retry loop is unit-testable without a live stream.
func sendStatusTrailerWithRetry(ctx context.Context, send func() error, attempts int, backoff func(attempt int) time.Duration) error {
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = send(); err == nil {
			return nil
		}
		if ctx != nil && ctx.Err() != nil {
			return err
		}
		if attempt < attempts {
			timer := time.NewTimer(backoff(attempt))
			select {
			case <-timer.C:
			case <-ctxDone(ctx):
				timer.Stop()
				return err
			}
		}
	}
	return err
}

// ctxDone returns ctx.Done() or a nil channel when ctx is nil (a nil channel
// blocks forever in select, so a nil ctx simply never short-circuits).
func ctxDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

func parseTarget(addr string) (string, int) {
	host := "localhost"
	port := 9090
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) >= 1 && parts[0] != "" {
		host = parts[0]
	}
	if len(parts) == 2 {
		if p, err := strconv.Atoi(parts[1]); err == nil {
			port = p
		}
	}
	return host, port
}
