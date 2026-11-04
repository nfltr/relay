# TLA+ models of the relay SDK's state machines

Checked with TLC (`make spec`, `make spec-mutants`; both in `make ci`,
about 10 s together; `make spec-traces` checks recorded runs). Java and `tla2tools.jar` come from
`scripts/fetch-tla.sh` (pinned, cached, never committed). The plan this
belongs to is nfltr's `docs/decisions/formal-specs-tla-2026-11-02.md`
(item 10).

## SignalConn.tla: a call's signaling over the relay and the direct path

`client/p2p` `SignalConn` (`sigconn.go`) carries a call's signaling frames
(SDP, ICE candidates, chat, hangup) over the relay stream from the first
frame and over the direct TCP channel once `AddDirectPath`'s `Connect`
finds one. The writer numbers each frame and writes it on every open path;
the reader delivers each number once, in order.

Modelled: one direction (the other is the same machine); `N` frames; the
relay path open from the start, the direct path joining once at any time
(on both sides: a stream buffers what is written before its reader
starts), never once the reader ended; each path a FIFO with two ends, the
writer's and the reader's, either of which may close alone (`MaxBreak`
one-sided drops), the other side learning it through the transport.
Abstracted: the E2E sealing of each path (`E2E.sealPath`, per path, below
the frames), unsequenced frames (seq 0), `maxAhead` (the model's `N` is
below it).

| action | Go |
|---|---|
| `Write` | `SignalConn.WriteFrame` |
| `Join` | `SignalConn.AddPath` (from `AddDirectPath`) on both sides; refused by a reader that ended (`ended`) |
| `Recv(p)` | `readPath` and `accept`: deliver, hold ahead, drop a copy |
| `WDrop(p)` | the writer's end closes alone: a write error, its own reader of the path (the other direction) ended or saw a tampered frame: `dropPath`, the path's `Close` |
| `RDrop(p)` | the reader's end closes alone: a tampered frame (`errE2ETampered`), a malformed mux message, the transport broke: `dropPath` |
| `REnd(p)` | the reader reads the writer's close after what it carried: the initiator's `CloseSend`, the responder's empty message (`muxSignalPath.Close`), a FIN |
| `WLearn(p)` | the writer's end learns the reader's close: the relay demux reads the stream's end and fails the credit window; the direct path's write fails |
| `Stall(p)` | a path takes no write and delivers nothing, unbroken (no relay credit, a half-open connection) |
| `TimeOut(p)` | a frame write past its bound (`tcpWriteTimeout`, `sigWriteTimeout`): the writer closes the path |

Invariants: `NoSilentLoss` (while some path is open at both ends, every
frame sent and not delivered is held ahead or on a path the reader reads;
with none, the reader's remaining paths end after what they carry and its
reads end with `io.EOF`), `EndedFinal` (an ended reader has no path
again), `ReadBound`, `PathOrdered`. Properties: `AllDelivered` (while the
reader can read a path, every frame is delivered), `DropReachesWriter`
and `DropReachesReader` (a side's drop of a path reaches the other side);
weak fairness on `Write`, `Recv`, `TimeOut`, `REnd` and `WLearn`.
`SignalConn.cfg` (3 frames, 2 drops, 1 stall): 2,024 distinct states,
depth 14, every action taken (`-coverage 1`), about 4 s at low load.

### Environment assumptions

| assumption | source |
|---|---|
| A relay stream and a direct TCP connection are each FIFO; nothing reorders within a path | gRPC streams are ordered (grpc.io "Core concepts: streaming"); TCP (RFC 9293) |
| The initiator's `CloseSend` reaches the responder's `Recv` as `io.EOF` after every message sent before it; a responder's empty message reaches the initiator after every message before it | rpcclient `clientStream.CloseSend`, `serverStream.Send`; `TestRelayMuxResponderCloseEndsInitiator` |
| A TCP close reaches the peer as EOF after the bytes before it; a reset as an error | RFC 9293 |
| A path may stall unbroken (no relay credit, a half-open TCP connection) and the stalled side may never learn; each write is bounded (`sigWriteTimeout`, `tcpWriteTimeout`) | relay credit (`RelayMux`, signaling protocol 4); TCP keepalive covers only reads |
| The app drains `ReadFrame` (`accept` blocks on `in` under `rmu`): weak fairness on `Recv` | `sigconn.go` `accept` |
| Clock only in the write bounds; no clock in the model | `sigWriteTimeout`, `tcpWriteTimeout` |

### Code map (SignalConn.tla)

| actions | code |
|---|---|
| `Write`, `Join`, `Recv`, `WDrop`, `RDrop` | client/p2p/sigconn.go |
| `REnd`, `WLearn`, `Stall`, `TimeOut` | client/p2p/relaymux.go |
| `RDrop` (tamper) | client/p2p/e2e.go |
| trace recorder | client/p2p/trace_on.go |

### Findings (lane WGP2P, 2026-11-02)

- **P1 (medium, fixed)**: a path that joined carried only the frames
  written after it. A frame written before the direct path joined and still
  in flight on the relay when the relay broke was lost; every later frame
  came over the direct path and waited behind it in `ahead`, and the call's
  signaling stopped silently (no error: the direct path kept the reader
  open) until `maxAhead` frames piled up. `NoSilentLoss`, 4 states; the
  same run without the invariant breaks `AllDelivered`. Fix: `AddPath`
  first writes the frames sent so far (the last `maxAhead`), then joins
  the path; its reader starts before that replay, since the peer replays
  to us at the same moment (two replays into each other's unread pipes
  would wait for each other). Test: `TestSignalConnJoiningPathCarriesEarlierFrames`
  (it timed out before the fix). With the replay every path carries every
  frame in order, so `ahead` holds a frame only past the replay's
  `maxAhead` bound; it stays for that case, where a gap ends the reader
  (`TestSignalConnGapIsBounded`) instead of stalling it.

- **M1 (medium, fixed, lane WGFIX2, review r2)**: `WriteFrame` writes the
  paths one after another under its lock, relay first, and the relay
  path's write waited for credit with no bound. A relay that stopped
  granting credit (peer reader blocked, relay overloaded, half-open
  stream) blocked every later frame on the direct path too, and `AddPath`,
  `dropPath` and `Close` behind the lock, while both paths looked live.
  Mutant `M1:unbounded-relay`: `AllDelivered`. Fix: the relay signal
  write waits for credit at most `sigWriteTimeout` (as the direct path's
  `tcpWriteTimeout`) and fails, which closes the path. Test:
  `TestSignalConnStalledRelayDoesNotBlockDirect`.

- **L6 (low, lane WGFIX2, review r2)**: invariants `ReadBound` (the
  reader is never past the writer; `ahead` within `next+1..sent`) and
  `PathOrdered` (each path carries strictly increasing numbers); mutant
  `reorder` (a frame put before earlier ones on the direct path):
  `PathOrdered`. Witnesses `W_PathOrdered`, `W_ReadBound`, `W_Stall`.
- **L4, L5 (low, fixed, lane WGFIX2)**: a frame no path took stays out of
  the replay window and its number is reused (`WriteFrame` returned an
  error for a frame a later `AddPath` replayed:
  `TestSignalConnFailedWriteIsNotReplayed`); a frame too large for the
  relay window is refused before it is numbered (it closed the relay path
  and so the data fallback: `TestSignalConnOversizeFrameKeepsPaths`). The
  model's `Write`, disabled with no live path, is the fixed behaviour.
- **M2 (medium, fixed, lane W5-RELAY, review r2)**: the model dropped a
  path on both sides at once; in code one side could drop it alone. The
  responder's `RelayMux.Close` sent nothing (it cannot half-close its
  stream), so after a responder-side drop (a tampered or malformed frame,
  a failed write) the initiator kept writing into a path nobody read,
  until its credit ran out (since M1: one `sigWriteTimeout`). The model
  now has per-side path ends (`wOpen`, `rOpen`) and the propagation steps
  `REnd`, `WLearn`; mutant `M2:one-sided` (`WLearn` of the relay never
  taken): `DropReachesWriter`. Fix: the responder's close sends an empty
  message, which ends the initiator's demux as its stream's end does (and
  an older initiator's: an empty message always ended the demux). Test:
  `TestRelayMuxResponderCloseEndsInitiator` (it timed out before the fix).
- **L1 (low, fixed in the model)**: `Join` was enabled after every path
  died and replayed everything; the code's `ended` is sticky and `AddPath`
  refuses. The model's `ended` is sticky, `Join` needs `~ended`;
  invariant `EndedFinal`, mutant `L1:revive`, witness `W_EndedFinal`;
  `MaxBreak = 2`, so both paths die in `make spec`.
- **L2 (low, decided: test-guarded)**: `AddPath` starts the path's reader
  before its replay, since the peer replays into us at the same moment.
  The model has one direction and an atomic `Join`, so it cannot see this
  order; modelling both directions with per-side reader starts would
  square the state space for one ordering. Guard:
  `TestSignalConnSwitchLosesNothing` fails with the reader started after
  the replay (checked 2026-11-03: "read 100 of 200: timed out").
- **L3 (low, fixed)**: the trace check read the first end of a path on
  either side as a `Break` that lost what the path carried, so a real run
  where the writer closed and the reader then read the frames before the
  close was rejected (the fixture enshrined it). With per-side ends a
  writer's drop is `WDrop` (its frames still readable) and the reader's
  `REnd` or `RDrop`; `spec/testdata/accept-recv-after-writer-drop.ndjson`
  is accepted, `reject-recv-after-reader-drop.ndjson` rejected.

Mutants (`make spec-mutants`): `P1:no-replay` (`NoSilentLoss`),
`P1:no-replay-stall` (`AllDelivered`), `one-path` (a frame written on one
path only: `NoSilentLoss`), `M1:unbounded-relay` (`AllDelivered`),
`reorder` (`PathOrdered`), `M2:one-sided` (`DropReachesWriter`),
`L1:revive` (`EndedFinal`). Witnesses, each violated: `W_NoSilentLoss`
(an undelivered frame while one path is open at both ends and the other
is not), `W_EndedFinal`, `W_ReadBound`, `W_PathOrdered`, `W_Stall`,
`W_OneSided` (a path open at one end only). `TypeOK` has none (a typing
check).

### Trace validation

`make spec-traces`: with `-tags relaytrace`, a test that calls `traceTest`
records its SignalConns' steps (`client/p2p/trace_on.go`: a write before
its frame goes on the paths, a path joining before its replay, a frame
read from a path, a path's reader ending), one NDJSON line each, in one
process-wide order. `TraceSignalConn.tla` checks each direction that wrote (writer W, reader R)
against `SignalConn.tla`: W's writes, W's direct path joining, R's reads,
and each side's end of a path closing (W's: `WDrop`, or `WLearn` once R
dropped it; R's: `REnd` after W's close and what it carried, else `RDrop`).
A W join once R ended is W's alone (R's `AddPath` refuses it). Traced
tests: `TestSignalConnSwitchLosesNothing` (both ways, about 970 lines
each), `TestSignalConnJoiningPathCarriesEarlierFrames`. Rejected fixtures
(`spec/testdata/reject-*.ndjson`), one per invariant the trace check
holds: a joining path without the replay (P1, `NoSilentLoss`), a read
before the write (`ReadBound`), a path's frames read out of order
(`PathOrdered`), a read from a path after the reader's own drop, a read
from a path that joined an ended reader (`EndedFinal`). Accepted fixture:
a read after the writer's drop (L3).
About 20 s (most of it the tagged test build), so not in `make ci`.

### Path selection: not a state machine to model further

The brief's other suspected silent failures were checked against the code
and need no spec:

- **Flapping**: nothing switches paths mid-session. `OpenDataPath` (a file
  transfer) chooses once: the sender takes the direct TCP channel, the
  WebRTC data channel or the relay (`choose`) and sends that choice
  (`FrameDataPath`); the receiver uses exactly that path or fails with an
  error (`follow`: "the sender chose ... but that connection is not
  here"). `Connect` with `AnnounceConn`/`AwaitConn` (`nfltr p2p send`)
  likewise keeps the announced connection or returns `ErrPeerRelay`.
- **Different paths on the two sides**: a file transfer cannot (the
  receiver follows or errors). `Connect` without `AwaitConn` (a peer that
  predates `SignalSelect`, and `AddDirectPath`) keeps the highest ConnID
  within 50 ms on each side, which two loaded peers can pick differently
  (documented on `Connect`). Each side then closes the other's choice, so
  both direct ends read EOF and are dropped; for `SignalConn` every frame
  also went on the relay, so nothing is lost: the call stays on the relay
  (a missed direct path, not a silent loss).
- **Data on a path the peer no longer reads**: when the receiver fails to
  find the chosen path it closes it (`settleTCP`, `closePC`), so the
  sender's writes fail (a reset, an SCTP abort) rather than vanish.

## CallCredit.tla: per-call credit for agent-to-agent calls

Lane CALLCREDIT (2026-11-04). This section is the design; it came before
the spec and the code.

### Problem

An agent's agent-to-agent calls (`client/rpcclient`: `NewStream`,
`Invoke`, the `Handle` handler) share the agent's one tunnel and its one
receive loop (`recvLoop` -> `handleMessage`). Each call has a buffer
(`clientStream.responseCh`, 256 frames; `serverStream.requestCh`, 16), and
nothing told the sender how much of it was free. A caller that stopped
reading filled its buffer; the loop then waited on it (`handoff.Send`) for
`handoff.Stall` (10 s) before it cut the call, and every other call on
the connection, both directions, waited too (lane FLAKEQW4: relay-core
`TestInternalAgentRouting_SaturatedTransactionDoesNotBlockHealthyTransaction`).
The relay in between keeps per-call pipes (relay-core
`dispatcher_agent_routing.go`) and was not the cause.

### Design

Per-call credit end to end, between the two rpcclient agents, as the TCP
data path's (`x-nfltr-tcp-credit`, relay-core `spec/AgentLink.tla` NoHOL),
with `github.com/nfltr/link`'s `Credit` counting frames instead of bytes:

- Windows, in frames: a caller buffers `ResponseWindow` (256) responses of
  a call, a handler `RequestWindow` (16) requests. Each side keeps two
  `link.Credit`s, one per role: calls it makes (its window the response
  window, the peer's the request window) and calls it serves (the other
  way round). The call's transaction id is the session id.
- A sender takes one credit per data frame before it queues it
  (`clientStream.sendMsg`, `resendEarly`; `serverStream.Send`). The
  frame that ends a direction (the caller's `CloseSend`, the handler's
  `a2a-status`, the relay's `error`) takes none: each buffer has one slot
  beyond its window for it. Control frames (E2EE handshake, 0-RTT first
  flight, which carries its request outside the buffer, cancel) take none.
- The receive loop charges each data frame (`Credit.Received`) and puts it
  in its call's buffer without waiting: credit guarantees room. A frame
  past the window is the peer breaking the rules: that call is refused
  (`ResourceExhausted`), never the connection, which carries other peers'
  calls.
- The app's `Recv` acknowledges what it took (`Credit.Consumed`), which
  sends a window update once a quarter window was read: a frame of type
  `a2a-window` (`rpcclient.WindowMessageType`) with the call's transaction
  id and the count as an unsigned varint payload. A caller's update is
  routed like its requests (source and target ids), a handler's like its
  responses. A received update is `Credit.Grant`; one past the peer's
  window refuses that call.
- The relay carries window updates like any frame of the call, with one
  change (relay-core): a caller's updates travel the request direction,
  which its `CloseSend` ended, so the relay forwards them after the
  request's EOM as well: from the caller's receive loop into a per-call
  channel of `a2aWindowCap` updates (never waiting: a full one refuses the
  call), forwarded by the call's route until its responses end (local
  route, remote route, and `RelayTunnel` between replicas, which forwards
  an agent-to-agent call's frames until its stream ends).

### Invariants (each a property of CallCredit.tla)

- `NoHOL`: the receive loop never waits on one call: the frame at the head
  of the connection always fits its call's buffer (or its call is gone).
- `BufferBound`: a call's buffer holds at most its window (plus the end
  frame); a connection's at most its calls times that. The relay's pipe
  per call stays at its cap (16): it only waits on the connection it sends
  to, never on a call, since the receiver never waits.
- `Ordered`: each call's frames arrive in order, once each.
- `Conservation`: credit + frames on the way + buffered + read and not yet
  acknowledged + updates on the way = the window, per live call.
- `GrantBound`: a call has at most `W / T` updates on the way (each is at
  least a quarter window and together they never pass the window): 4. So
  the relay's channel of `a2aWindowCap` (4) is never full for a peer that
  keeps to the rules.
- `HealthyDone` (liveness): every call whose reader reads gets all its
  frames, whatever a stuck call does.

Who ends what: the caller's context (cancel, deadline) and the call's end
forget the call's credit on the caller (`Credit.Forget`: a `Send` waiting
for credit returns); the handler's context (the call's cancel, a refusal,
the agent) forgets it on the handler side; `Agent.Close` closes both
credits. A peer that stops reading holds only its own call: that call's
sender waits in `Acquire` until credit or the call's end.

Failure model: a connection is a FIFO each way that ends whole (gRPC
stream); a frame is never lost while it lives, so no update is lost; when
it ends every call on it ends (`closePendingClientStreams`, the handler
contexts). The relay refusing a call (a target connection that took
nothing of its requests for `handoff.Stall`, relay-core) ends that call.

Out of scope: a slow connection (not a stalled call) still paces every
call on it, as TCP and gRPC flow control do; the relay's per-call pipes
then wait on that connection (its `TxnRegistry` stall bound).

Wire change, a hard cut (no users yet): a peer before this version sends
no window updates, so a new sender to it stops after its window; a relay
before it drops a caller's updates after the request EOM, so a call with
more responses than the window stops. relay-server and nfltr take both
modules together.

### Model

One direction of the frames of several calls (`Calls`, `Stuck` the ones
whose reader never reads): the sender's connection to the relay (`in`), a
relay pipe per call (`pipe`, cap `P`), the receiver's connection (`out`),
both FIFOs of cap `Q`; the receiver's per-call buffer (`buf`), the reads
(`got`), acknowledgements (`cons`), and the updates back (`gin` to the
relay, `gout` to the sender). The other direction is the same machine
(requests: their updates travel the response direction, which has no
early end). Abstracted: frame sizes (frames are counted; a frame's bytes
are bounded by the gRPC message limit), E2EE (it changes payloads, not
frames), the agents' send queues (one FIFO with the connection: every
frame of a connection goes through its one `sendLoop`).

| action | Go |
|---|---|
| `Send(c)` | `clientStream.sendMsg` / `serverStream.Send`: `Credit.Acquire`, `Agent.sendFrame` |
| `RelayIn` | relay-core: the sender's stream receive loop; `TxnRegistry` fanout (responses), `dispatchAgentToAgent` (requests) |
| `RelayOut(c)` | relay-core: the call's route sending on the receiver's stream (`routeAgentToAgentLocal`, `routeAgentToAgentRemote`, `RelayTunnel`) |
| `Deliver` | `Agent.recvLoop` -> `handleMessage` -> `pushResponse` / `pushRequest` (`Credit.Received`) |
| `Read(c)` | `clientStream.Recv` / `serverStream.Recv`: `Credit.Consumed` -> `sendWindow` |
| `Eom(c)` | `clientStream.CloseSend` |
| `RelayGrant` | relay-core: `dispatchAgentToAgent` -> `a2aSession.windows` -> the route (caller's updates); the response path (handler's) |
| `SenderGrant` | `handleMessage` `WindowMessageType`: `Credit.Grant` |
| `Cancel(c)` | the call's context, cancel or deadline: `Credit.Forget` on both sides |

Mutants (`make spec-mutants`): `CC:no-credit` (the code before: `NoHOL`),
`CC:no-credit-live` (the same, `HealthyDone`), `CC:no-return` (reads
grant nothing: `HealthyDone`), `CC:shared-buffer` (one buffer per
connection: `NoHOL`), `CC:drop-after-eom` (the relay before: `HealthyDone`).
Witnesses, each violated: `W_StuckFullHealthyDone` (a healthy call done
while the stuck one's buffer is full), `W_RelayPipeFull` (the relay's pipe
smaller than the window fills), `W_LateGrant` (an update forwarded after
the request EOM), `W_SenderWaits`, `W_CancelDrop` (a frame of an ended
call dropped at the head). `CallCredit.cfg` (2 calls, window 2, 3 frames,
pipes of 1, FIFOs of 2): 9,932 distinct states, depth 33, every action
taken (`-coverage 1`), about 1 s. `CallCreditLarge.cfg` (window 4, 5
frames, pipes of 2; `LARGE=1 make spec`, not in `make ci`): 296,864
distinct states, depth 55, about 12 s.

### Environment assumptions

| assumption | source |
|---|---|
| A gRPC stream is FIFO each way and ends whole; nothing is lost while it lives | grpc.io "Core concepts: streaming" |
| Every frame of one agent goes through its one `sendLoop`, in queue order | `a2a.go` `sendLoop` |
| The relay keeps a call's frames in order (one route goroutine per direction) | relay-core `dispatcher_agent_routing.go` |
| A reader that reads keeps reading (weak fairness on `Read` outside `Stuck`) | the app |

### Code map (CallCredit.tla)

| actions | code |
|---|---|
| `Send`, `Read`, `Eom`, `Cancel` | client/rpcclient/client_stream.go, client/rpcclient/server_stream.go |
| `Deliver`, `SenderGrant` | client/rpcclient/a2a.go, client/rpcclient/call_credit.go |
