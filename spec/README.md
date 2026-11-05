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
for credit returns); on the handler side `serverStream.end` forgets it
where the call ends (its handler returned, the call's cancel, a refusal, a
failed E2EE ack; lane CALLCREDIT2, no context callback per call);
`Agent.Close` closes both credits. A peer that stops reading holds only its own call: that call's
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
early end); `CallCreditBoth.tla` checks both at once on the connections
they share. Abstracted: frame sizes (frames are counted; a frame's bytes
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
| `Cancel(c)` | a stuck call's `End(c)` |
| `End(c)` | the call's context, cancel or deadline: `Credit.Forget` on both sides (the caller's `removePendingClientStreamOnContextDone`; the handler's `serverStream.end`) |

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

### Code map (CallCredit.tla, CallCreditBoth.tla, CallCreditSenders.tla)

| actions | code |
|---|---|
| `Send`, `Read`, `Eom`, `Cancel`, `End`, `CloseSend` | client/rpcclient/client_stream.go, client/rpcclient/server_stream.go |
| `Deliver`, `SenderGrant` | client/rpcclient/a2a.go, client/rpcclient/call_credit.go |
| trace recorder | client/rpcclient/trace_callcredit_on.go |

### CallCreditBoth.tla: both directions at once

Lane CALLCREDIT2 (2026-11-05). `CallCredit.tla` checks one direction on
connections of its own and took the other as the same machine. Both
directions of a call share connections: the caller's connection to the
relay carries its requests, its request EOM and its window updates for
responses; the handler's its responses and its window updates for
requests; the relay's connection to each agent what the other sent. So an
agent's receive loop serves one direction's frames and the other
direction's window updates from one FIFO, and a `Recv` that sends a window
update waits for room on its connection behind that agent's own frames
(`Agent.sendFrame` returns once its frame is written).
`CallCreditBoth.tla` has both directions credited at once (`WReq`,
`WResp`) on those four FIFOs (`up[a]`, `down[a]`), the relay's pipe and
window channel per call and direction (`pipe`, `gch`), the request EOM as
a frame on the caller's connection (`CloseSend`, after its requests), and
the same invariants per direction (`NoHOL` now: the head of each agent's
connection is a window update or fits its call's buffer) and
`HealthyReqDone`, `HealthyRespDone`.

| action | Go |
|---|---|
| `Send(d, c)` | as `CallCredit`'s `Send`, per direction |
| `CloseSend(c)` | `clientStream.CloseSend`: the request EOM, after the call's requests |
| `RelayIn(a)` | relay-core: agent `a`'s stream receive loop: data to the call's pipe, a window update to its window channel, the EOM ends the requests |
| `RelayOut(d, c)`, `RelayGrant(d, c)` | relay-core: the call's routes |
| `Deliver(a)` | agent `a`'s `recvLoop`: `pushRequest` / `pushResponse`, `handleWindow` |
| `Read(d, c)` | `Recv`: `Credit.Consumed`, its window update written before `Recv` returns |
| `Cancel(c)` | a call with a stuck reader ends: `Credit.Forget` on both sides |

`CallCreditBoth.cfg` (2 calls, one stuck both ways; windows of 1, 2
frames each way, pipes of 1, FIFOs of 2): 38,350 distinct states, depth
44, about 18 s; `CallCreditBothLarge.cfg` (`LARGE=1`: windows that differ,
2 frames for requests and 1 for responses): 672,092 distinct states,
depth 50, about 6 min at load 9 (windows of 2 both ways passed 1.1 M
states at depth 25 in 15 min and was stopped).
Mutants: `CCB:no-credit-req`, `CCB:no-credit-resp` (one direction
uncredited: `NoHOL`), `CCB:no-credit-req-holds-resp` and
`CCB:no-credit-resp-holds-req` (the same with `NoHOL` off: the healthy
call's *other* direction stops, its window updates behind the waiting
loop: `HealthyRespDone`, `HealthyReqDone`), `CCB:drop-after-eom`
(`HealthyDone`). Witnesses, each violated: `W_BothFullHealthyDone`,
`W_GrantBehindData` (a window update behind data on one connection),
`W_ReadWaits` (a `Recv` whose window update waits for room), `W_LateGrant`.

### CallCredit traces

`make spec-traces` here checks the recorder's fixtures; the traces come
from relay-core's two-agent tests (relay-core `make spec-traces`, which
runs `scripts/spec.sh cctraces` from the relay version it requires): with
`-tags relaytrace` and `RELAYTRACE=<dir>`, `client/rpcclient`
(`trace_callcredit_on.go`; without the tag empty functions the compiler
drops) writes every agent's steps of the process to
`callcredit-<pid>.ndjson`: `Send` (after `Credit.Acquire`), `Deliver`
(the receive loop, before `Credit.Received`), `Read` (before
`Credit.Consumed`), `Eom` (`CloseSend`), `Grant` (`handleWindow`, its
count) and `Cancel` (the caller left), each with its call's transaction
id and direction (from the agent's role in the call, which
`traceCCOpen` records). Each line is written before the step's effect
can be seen by the other side, under one lock, so the file's order is one
the run took. `TraceCallCredit.tla` checks each call and direction alone
against `CallCredit.tla` with that call (`W` the direction's window): the
relay's steps are TLC's, taken only when the next logged step needs them.
One call at a time because frames and window updates of different calls
on one connection are ordered by goroutines the recorder does not see.
Rejected fixtures: `reject-callcredit-send-past-window.ndjson` (a
handler's 257th response with no window update: the code before lane
CALLCREDIT), `reject-callcredit-early-grant.ndjson` (a window update for
4 requests after 3 reads). `scripts/spec.sh traces` also checks that
every step `TraceCallCredit.tla` takes is one `traceCC` records.

### CallCreditSenders.tla: several senders on one call

Lane FLAKECC (2026-11-05), lane CREDITMU. `CallCredit.tla`'s `Send(c)` is
enabled whenever the call has credit: it assumes a sender waiting for
credit takes it once credit is there. That holds for one sender per call.
A handler may `Send` from several goroutines (`serverStream.Send`: a
remote-exec handler's stdout and stderr), each waiting in
`link.Credit.Acquire`. Before link v0.12.3 `Credit` woke its waiters
through one token of capacity one, which `Grant` filled and one waiter
emptied. Of two waiters a grant woke one; it took a credit and sent on,
and once it had nothing more to send the other waited with credit there
and no token; no grant came, since the receiver grants only for frames it
read (`TestConcurrentServerStreamSend` on the Linux runner, relay
582038b7: 427 of 500 frames, every sender waiting). Lane FLAKECC worked
around it with a lock per call (`serverStream.creditMu`); lane CREDITMU
deleted it.

Design: the guarantee link v0.12.3 gives (link's `spec/CreditWaiters.tla`,
lane LINKWAKE): a grant wakes every waiter, each checking again under
`Credit`'s lock. So a call's senders `Acquire` with no lock of their own.
A `clientStream` has one sender (its `Send` is not safe for concurrent
use: `sentFirst`), and `resendEarly` runs before anything else of the
call is sent.

Invariants: `Conservation` (credit, frames on the wire, read and not yet
granted, and grants on the way make up the window), `NoStrandedWaiter` (no
sender waits while the call has credit unless it is woken); liveness
`AllSent` (every sender sends all its frames).
Mutants: `CCS:one-slot` (link before v0.12.3 with no lock:
`NoStrandedWaiter`), `CCS:one-slot-live` (the same: `AllSent`).
Witnesses, each violated: `W_BothWant` (one sender waits while the other
wants credit), `W_GrantToWaiter`, `W_WakeAll` (one grant wakes both
senders). `CallCreditSenders.cfg` (2 senders, window 8 so grants come two
frames at a time, 5 frames each): 1,600 distinct states, depth 36, every
action taken.

| action | Go |
|---|---|
| `Start(s)` | `serverStream.Send`: `Credit.Acquire` |
| `Try(s)` | `link.Credit.acquire`'s check; `Agent.sendFrame` |
| `Wake(s)` | `link.Credit.acquire`'s `<-wake` (a closed channel) |
| `Read` | `clientStream.Recv`: `Credit.Consumed` |
| `Grant` | `handleWindow`: `Credit.Grant` (wakes every waiter) |

| assumption | source |
|---|---|
| A grant or refund wakes every waiter of the session, each checks again under `Credit`'s lock | link v0.12.3 `credit.go` `wakeAll`; link `spec/CreditWaiters.tla` |

## CallLifecycle.tla: which frame starts a call, and what an ended call leaves

Lane CONFORM6-RELAY (2026-11-05). `CallCredit.tla`'s `End` drops a call's
later frames; the code did not (finding CL1 below). The target's receive
loop (`Agent.handleMessage`) keeps one entry per call it serves
(`Agent.incoming`), deleted when the call's handler returns. A frame of a
transaction with no entry was taken as a new call, so a request frame that
arrived after the handler returned (the caller sent it before it saw the
call's status) ran the handler a second time with the call's later
requests. Keeping the ended call's id would drop it, but then every ended
call leaves an entry: the transaction ids are the callers' random UUIDs
(`NewStream`: `uuid.New()`), not numbers that grow per connection, so "at
or below the highest ended id" is no rule here, and the relay drops the
caller's last frame of a call whose route ended (relay-core
`dispatchAgentToAgent`'s `a2aEnded`), so the target never learns when to
forget it.

Design: the caller says which frames continue a call. Every request data
frame after the call's start (its first frame, or an E2EE call's
handshake init) carries `TunnelFrame.continuation` (proto field 9).
Rule at the target: **a frame of a transaction it serves goes to that
call; a frame of any other transaction starts a call only if it is a data
frame without `continuation`; every other frame is dropped**. The target
keeps nothing per ended or refused call: 0 entries, at any rate of calls.
A caller older than this field marks nothing; its late frames still start
a call (mutant `CL:old-caller`), as before; an old target ignores the
field. No other wire change.

The refusal of a call at its first frame (`refuseCall` from the new-call
branch, which kept its entry: finding CL2) is gone: a fresh call's credit
(`link.Credit.Open`: nothing held, window `RequestWindow` >= 1) and buffer
(`RequestWindow+1`) always take its first frame
(`TestFirstFrameFitsAFreshCall`).

Invariants: `AtMostOneCall` (a transaction runs at most one handler
call), `NoEndedEntry` (`incoming` holds only calls whose handler runs: the
memory bound); liveness `AllServed` (a call whose first frame was sent
gets its handler call or its refusal). Mutants, each caught:
`CL:late-new-call` (the code before: `AtMostOneCall`), `CL:old-caller`
(`AtMostOneCall`), `CL:tombstone` (an ended call keeps its entry:
`NoEndedEntry`), `CL:refused-first-kept` (the code before for a refused
first frame: `NoEndedEntry`), `CL:drop-unknown` (every frame of an
unknown transaction dropped: `AllServed`). Witnesses, each violated:
`W_LateFrame`, `W_LateData` (a data frame of a call whose handler
returned reaches the target), `W_BothRun`. `CallLifecycle.cfg` (2 calls,
2 data frames each, request ends and cancels; a `Send` that took its
credit before its caller left may follow the cancel): 45,421 distinct
states, depth 19, every action taken (`-coverage 1`), about 3 s.

| action | Go |
|---|---|
| `Send(t)`, `CloseSend(t)`, `Cancel(t)` | `clientStream.sendMsg` (sets `continuation`), `resendEarly`, `CloseSend`, `sendCancel` |
| `Serve` | `Agent.handleRequest`: a frame of a served call (`pushRequest`); `handleMessage`'s cancel of a served call |
| `Start` | `Agent.handleRequest`'s new-call branch; `handleE2EEInit`, `handleE2EEInit0RTT` |
| `Drop` | `Agent.handleRequest`: an empty EOM or a `continuation` of an unknown transaction; a cancel of one |
| `Refuse` | no handler; `refusesPlaintext`; a bad or unanswered E2EE init |
| `Return(t)` | `Agent.endServed` (from `handleCall`) |

| assumption | source |
|---|---|
| A call's frames reach its target in the order its caller sent them | the gRPC streams (grpc.io "Core concepts: streaming"); relay-core `dispatcher_agent_routing.go` (one route per call) |
| The receive loop takes one frame at a time (`recvLoop` -> `handleMessage`) | `a2a.go` `recvLoop` |
| A caller marks every request data frame after its call's start | `client_stream.go` `sendMsg`, `resendEarly` (this lane); older callers do not (`CL:old-caller`) |

### CallLifecycle traces

With `-tags relaytrace` and `RELAYTRACE=<dir>`, `client/rpcclient`
(`trace_callcredit_on.go` `traceCL`) writes every agent's target-side
steps of the process to `calllifecycle-<pid>.ndjson`: `Serve`, `Start`,
`Drop`, `Refuse` (the receive loop took a request frame: its kind and
`continuation`) and `Return`. The receive loop's decision and its line,
and `endServed`'s delete and its line, are taken under one lock
(`clLock`), so the file's order is the order the entries changed.
`TraceCallLifecycle.tla` checks each transaction of each agent (`a`, its
address) alone; the caller's steps are TLC's, taken only when the next
logged step needs them. A transaction no frame of which is marked is
checked with an old caller (`Mutant = "old-caller"`): tests that play the
caller by hand send unmarked frames; `AtMostOneCall` still holds for them.
`make spec-traces` runs `client/rpcclient`'s tests (`CL_TRACE_TESTS`,
default all) with the recorder and checks every transaction: 72
transactions accepted, 0 rejected; every action taken (`Start` 53,
`Return` 53, `Serve` 78, `Drop` 47, `Refuse` 13). Rejected fixtures:
`reject-calllifecycle-late-new-call.ndjson` (a second `Start` from a
continuation after `Return`: the code before),
`reject-calllifecycle-tombstone.ndjson` (a frame served after `Return`).

### Findings (lane CONFORM6-RELAY, 2026-11-05)

| id | severity | finding | status |
|---|---|---|---|
| CL1 | medium | a request frame that reached the target after its call's handler returned started a second handler call for the transaction (code diverged from `CallCredit.tla`'s `End`) | fixed: `continuation` mark and the rule above; `TestLateRequestFrameStartsNoCall`, `TestEndedAndRefusedCallsLeaveNoEntry` (red before: 2 handler calls for one call; 20 entries left by late frames) |
| CL2 | low | a call refused at its first frame kept its entry (one per refusal) | unreachable (a fresh call always takes its first frame); the refusal deleted; `TestFirstFrameFitsAFreshCall` |

### Code map (CallLifecycle.tla)

| actions | code |
|---|---|
| `Serve`, `Start`, `Drop`, `Refuse`, `Return` | client/rpcclient/a2a.go, client/rpcclient/a2a_e2ee_agent.go |
| `Send`, `CloseSend`, `Cancel` | client/rpcclient/client_stream.go |
| the mark | proto/pb/service.proto |
| trace recorder | client/rpcclient/trace_callcredit_on.go |
