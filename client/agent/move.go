// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nfltr/relay/client/rpcclient"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
)

// Moving off a leaving relay replica, make-before-break (pb.Move): the relay
// sends MOVE_RECONNECT on the ConnectHTTP stream; the agent opens a new
// connection (another replica answers it) and serves both; once the new one
// is up it sends MOVE_CONNECTED on the old stream; the relay routes nothing
// new to the old stream and answers MOVE_DONE; the agent closes the old
// stream once the requests it received there are answered, and the old
// connection once its TCP sessions have ended. No request in flight is lost,
// where letting the agent go (and the agent redialling) fails the requests
// the leaving replica had routed to it. An agent advertises it with
// agentwire.MoveKey; a relay that predates it never sends MOVE_RECONNECT.

// errMoved ends a connection the agent moved off.
var errMoved = errors.New("moved to another relay connection")

// moveTCPQuiet is how long the old connection's TCP tunnel must have no
// session before the connection closes, and moveTCPBound how long the agent
// waits for that at most (a session longer than that is cut).
const (
	moveTCPQuiet = 500 * time.Millisecond
	moveTCPBound = 30 * time.Second
)

// A move's new connection is tried again while a replica refuses it: the
// relay's load balancer can hand it to the replica moving the agent, or to
// another one above the fleet's mean, and those refuse new agents. The
// relay waits 10 s for MOVE_CONNECTED before it gives up on the move;
// moveRetryFor is the agent's default (agent.moveRetryFor).
const (
	moveRetryEvery = 200 * time.Millisecond
	moveRetryFor   = 8 * time.Second
)

// move is one connection's part in a move.
type move struct {
	reconnectOnce sync.Once
	reconnect     chan struct{} // closed on MOVE_RECONNECT
	connected     chan struct{} // closed once the new connection is up
	tcp           *tcpStreamGrowth
}

func newMove() *move {
	return &move{reconnect: make(chan struct{}), connected: make(chan struct{}), tcp: &tcpStreamGrowth{}}
}

func (m *move) askReconnect() { m.reconnectOnce.Do(func() { close(m.reconnect) }) }

// waitsForTCPSessions reports a connection end after which the connection
// stays open until its TCP sessions ended (waitIdle): the agent moved off it,
// or another process with the same agent ID and key took over (a rolling
// update's new pod), which the relay sends every new session.
func waitsForTCPSessions(err error) bool {
	return errors.Is(err, errMoved) || rpcclient.IsSessionReplaced(err)
}

// relayLetGo reports a ConnectHTTP end by which the relay let the
// connection go without a move: a leaving replica that gave up moving the
// agent ends the stream Canceled, a graceful stop (GOAWAY) ends it too. Its
// TCP sessions are not over: the agent connects again at once and closes
// the connection once they ended, as after a move.
func relayLetGo(err error) bool { return err == nil || isGracefulStopError(err) }

// waitIdle returns once the connection's TCP tunnel has had no session for
// moveTCPQuiet, or after moveTCPBound: a connection the agent moved off, or
// one another process took over (rpcclient.IsSessionReplaced: the relay
// sends that process the new sessions), closes once the sessions it
// carries ended.
func (g *tcpStreamGrowth) waitIdle(ctx context.Context) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	start, quietSince := time.Now(), time.Now()
	for time.Since(start) < moveTCPBound {
		if g.active.Load() > 0 {
			quietSince = time.Now()
		} else if time.Since(quietSince) >= moveTCPQuiet {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// moveConnect opens a move's new connection: one the relay accepted (its
// headers carry the Welcome; a refused stream ends without), tried every
// moveRetryEvery for up to moveRetryFor. moveRetryFor also bounds each
// attempt (its dial, the stream's accept): the relay gives up on the move
// 10 s after MOVE_RECONNECT, so a connection still stalled past it serves
// no move. release ends the new stream's context; call it once its
// connection is closed.
func (a *agent) moveConnect(ctx context.Context) (conn *grpc.ClientConn, client pb.DispatcherClient, stream pb.Dispatcher_ConnectHTTPClient, streamCtx context.Context, release func(), err error) {
	until := time.Now().Add(a.moveRetryFor)
	for {
		actx, cancel := context.WithCancel(ctx)
		late := time.AfterFunc(time.Until(until), cancel)
		conn, client, stream, streamCtx, err = a.connectOnce(actx, time.Now(), a.cfg.Retries)
		if err == nil {
			md, herr := stream.Header()
			if herr == nil && agentwire.HasWelcome(md) && late.Stop() {
				return conn, client, stream, streamCtx, cancel, nil
			}
			err = fmt.Errorf("the relay refused the new stream: %v", herr)
			_ = conn.Close()
		}
		late.Stop()
		cancel()
		if ctx.Err() != nil || time.Now().After(until) {
			return nil, nil, nil, nil, nil, err
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, nil, nil, err
		case <-time.After(moveRetryEvery):
		}
	}
}

// drainContexts are a connection cycle's contexts with a drain (Config.Drain
// > 0): the TCP tunnel's (ctx, streamCtx) and the cycle's own outlive a stop
// (ctx ending), so the open TCP sessions run while the ConnectHTTP stream,
// on streamCtx, ends at once; end cancels them once the cycle is over.
// Without a drain they are ctx and streamCtx.
func drainContexts(ctx, streamCtx context.Context, drain time.Duration) (tcpCtx, tcpStreamCtx, cycleCtx context.Context, end func()) {
	if drain <= 0 {
		return ctx, streamCtx, ctx, func() {}
	}
	tcpCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	tcpStreamCtx, cancelStream := context.WithCancel(context.WithoutCancel(streamCtx))
	return tcpCtx, tcpStreamCtx, tcpCtx, func() { cancel(); cancelStream() }
}
