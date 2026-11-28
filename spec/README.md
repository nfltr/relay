# TLA+ models of the relay SDK's state machines

Checked with TLC (`make spec`, `make spec-mutants`; both in `make ci`,
about six minutes together on a cache miss, each configuration and mutant
side by side, `scripts/pool.sh`; `make spec-traces` checks recorded runs). Java and `tla2tools.jar` come from
`scripts/fetch-tla.sh` (pinned, cached, never committed). The plan this
belongs to is nfltr's `docs/decisions/formal-specs-tla-2026-11-02.md`
(item 10).

The organisation issuer's models (`org/`) are in their own directories:
`spec/enrol/` (certificates' lifecycle) and `spec/orgmove/` (moving the
issuer), `make spec-enrol-ci spec-orgmove-ci` (both in `make ci`).
Time-limited, approved access to a service is `spec/grant/`, `make
spec-grant-ci` (in `make ci`), its traces in `make spec-traces`. The
issuer's half of one set of groups (the root's move orders) is
`spec/onegroup/`, `make spec-onegroup-ci` (in `make ci`), its traces in
`make spec-traces`.

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
  (`clientStream.sendMsg`; `serverStream.Send`). The
  frame that ends a direction (the caller's `CloseSend`, the handler's
  `a2a-status`, the relay's `error`) takes none: each buffer has one slot
  beyond its window for it. Control frames (E2EE handshake, cancel) take
  none.
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
| trace checks | spec/TraceCallCredit.tla, spec/TraceCallCreditBoth.tla, spec/TraceCallCreditSenders.tla |

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
4 requests after 3 reads). Accepted fixture:
`accept-callcredit-full-window.ndjson` (a full response window, 256
frames, in flight at once; lane TRACEFIX2: `Of` was a recursive function,
which TLC evaluates one Java frame chain per element, and a long call's
trace overflowed the Linux JVM's 1 MiB thread stack, relay-core nightly
2026-11-05; `Of` is now `SelectSeq`, no recursion). `scripts/spec.sh
traces` also checks that every step `TraceCallCredit.tla` takes is one
`traceCC` records.

Both directions and several senders (lane TRACEGAPS, 2026-11-21):
`make spec-cctraces` (`scripts/spec.sh ccruns`, about 25 s on the runner; nightly,
`spec-traces` runs it) runs client/rpcclient's tests `CCTESTS` (two agents
over an in-order bridge: `TestFullRoundTrip`, `TestCallCreditBothWaysGrant`
(requests past `RequestWindow`, responses past `ResponseWindow`),
`TestCallCreditCallerLeavesStuckHandler` (the caller leaves a call whose
handler never reads), `TestCallCreditSendersWaitForTheCaller` (two
goroutines serve one call past its window while the caller reads nothing);
one agent: `TestConcurrentServerStreamSend`), each in its own process with
`-tags relaytrace`. Every call of each trace is checked per direction
(`TraceCallCredit.tla`), both ways (`TraceCallCreditBoth.tla`: a call with
a caller agent in the run; `NReq` is the trace's count of requests, a call
the caller left is one of `Ends` with its unread directions stuck, the
relay pipe `P = 1`, which takes nothing from a relay whose connections
`Q` hold the whole trace) and, when two or more goroutines logged a
`Start` for its responses, per sender (`TraceCallCreditSenders.tla`:
`Senders` and `M` from the trace, written into the config by the script,
since a definition substituted for a constant is evaluated on every use).
The recorder logs `Start` (`serverStream.Send` before `Credit.Acquire`;
a step of no other machine) and each line's goroutine (`s`). Not logged,
taken by TLC when the next logged step needs them: the relay's steps, a
receive loop dropping a frame of an ended call (`Deliver` of a gone call:
never needed by these runs), the caller's Reads in a run with no caller
agent. `Try` without credit and `Wake` are link.Credit's: rpcclient cannot
log them in an order the model may take (a Send is logged after its
`Acquire` returns, so the model's credit may be above the real one at a
real check that found none), so no trace takes them (`-coverage 1`); link's
own `spec/TraceCreditWaiters.tla` traces record them under `Credit`'s
lock. Rejected fixtures: `reject-callcreditboth-req-past-window.ndjson`
(`CCB:no-credit-req`: a 17th request with 16 unread),
`reject-callcreditboth-resp-past-window.ndjson` (`CCB:no-credit-resp`: a
257th response), `reject-callcreditboth-early-grant.ndjson` (a window
update for 4 requests after 3 reads: `GrantBound`, `Conservation`),
`reject-callcreditsenders-past-window.ndjson` (two goroutines, 257
responses with no window update: `Conservation`, the code before lane
CALLCREDIT), `reject-callcreditsenders-send-unstarted.ndjson` (a Send by
a goroutine that logged no Start: a step of no sender); each is required
rejected by its own machine. `CCB:drop-after-eom` and `CCS:one-slot` break
liveness only (a sender that never sends again): no finite trace shows
them, the mutants stay the model's (`make spec-mutants`).

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
memory bound), `CancelKnown` (a cancel reaches its target only for a call
it started or refused: a caller sends one only once a frame of its call
went, `clientStream.reached`); liveness `AllServed` (a call whose first frame was sent
gets its handler call or its refusal). Mutants, each caught:
`CL:late-new-call` (the code before: `AtMostOneCall`), `CL:old-caller`
(`AtMostOneCall`), `CL:tombstone` (an ended call keeps its entry:
`NoEndedEntry`), `CL:refused-first-kept` (the code before for a refused
first frame: `NoEndedEntry`), `CL:drop-unknown` (every frame of an
unknown transaction dropped: `AllServed`, with `CancelKnown` off: its dropped first frame leaves the cancel unknown too), `CL:cancel-unreached` (a
caller that leaves before any frame went cancels all the same: the code
before lane A2AFINAL, finding CL4: `CancelKnown`). Witnesses, each violated:
`W_LateFrame`, `W_LateData` (a data frame of a call whose handler
returned reaches the target), `W_BothRun`. `CallLifecycle.cfg` (2 calls,
2 data frames each, request ends and cancels; a `Send` that took its
credit before its caller left may follow the cancel): 45,421 distinct
states, depth 19, every action taken (`-coverage 1`), about 3 s.

| action | Go |
|---|---|
| `Send(t)`, `CloseSend(t)`, `Cancel(t)` | `clientStream.sendMsg` (sets `continuation`), `CloseSend`, `sendCancel` |
| `Serve` | `Agent.handleRequest`: a frame of a served call (`pushRequest`); `handleMessage`'s cancel of a served call |
| `Start` | `Agent.handleRequest`'s new-call branch; `handleE2EEInit` |
| `Drop` | `Agent.handleRequest`: an empty EOM or a `continuation` of an unknown transaction; a cancel of one |
| `Refuse` | no handler; `refusesPlaintext`; a bad or unanswered E2EE init; a wire v1 E2EE init |
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
caller by hand send unmarked frames; `AtMostOneCall` holds for them only
while no handler returns before its caller's last frame (an old caller's
later frame starts a second call: mutant `CL:old-caller`), so a test whose
handler returns early marks its continuations as a caller does
(`TestStuckHandlerDoesNotHoldTheReceiveLoop`, finding CL3).
`make spec-traces` runs `client/rpcclient`'s tests (`CL_TRACE_TESTS`,
default all) with the recorder and checks every transaction: 72
transactions accepted, 0 rejected; every action taken (`Start` 53,
`Return` 53, `Serve` 78, `Drop` 47, `Refuse` 13). Rejected fixtures:
`reject-calllifecycle-late-new-call.ndjson` (a second `Start` from a
continuation after `Return`: the code before),
`reject-calllifecycle-tombstone.ndjson` (a frame served after `Return`),
`reject-calllifecycle-cancel-unreached.ndjson` (a cancel dropped for a
call no frame of which reached: finding CL4),
`reject-calllifecycle-old-caller-second-call.ndjson` (an old caller's
unmarked frame after `Return` starts a second call; it ends at that
`Start`, so it was accepted while the checker listed `TraceNotDone` first:
every trace checker of `scripts/spec.sh` now lists it last, so a trace whose
last step breaks an invariant is rejected). `make spec-cltraces`
(in `make ci`, about 10 s) is the per-push slice: the stuck-handler test's
traces, three runs (`CL_TRACE_TESTS`, `CL_TRACE_COUNT`).

### Findings (lane CONFORM6-RELAY, 2026-11-05)

| id | severity | finding | status |
|---|---|---|---|
| CL1 | medium | a request frame that reached the target after its call's handler returned started a second handler call for the transaction (code diverged from `CallCredit.tla`'s `End`) | fixed: `continuation` mark and the rule above; `TestLateRequestFrameStartsNoCall`, `TestEndedAndRefusedCallsLeaveNoEntry` (red before: 2 handler calls for one call; 20 entries left by late frames) |
| CL2 | low | a call refused at its first frame kept its entry (one per refusal) | unreachable (a fresh call always takes its first frame); the refusal deleted; `TestFirstFrameFitsAFreshCall` |
| CL3 | low | `make spec-traces` rejected `TestStuckHandlerDoesNotHoldTheReceiveLoop`'s `stuck` trace in about 2 of 3 runs (`AtMostOneCall`): the test played an old caller (no `continuation` marks) and its refused handler returned before the caller's last frame, so a later frame started a real second handler call (2-3 per run in the raw trace). Callers of this module mark continuations, so no product path; the test was outside the spec's caller (lane CALLDUP, 2026-11-06) | fixed: the test marks continuations and asserts one handler call (red before: `ran 2 handler calls, want 1` in 2 of 10 runs); `make spec-cltraces` in `make ci`; reject fixture `reject-calllifecycle-old-caller-second-call.ndjson` |
| CL4 | low | nightly `make spec-traces` on 11ff714 rejected 3 transactions, each a lone `Drop`: a cancel of a call its target never heard of (`TestA2AE2EEKeyringRevokeRefusesOnlyThatMachine`, `TestA2AE2EERevokeEndsSession`: the caller refused the call at a revoked key and still sent its cancel; the spec's `Cancel` needs `sent > 0`, so the code was wrong), and a continuation with no first frame (`TestA2AE2EEWithoutPairingKeyIsOpenToAnActiveRelay`, an active relay that took the first frame: outside the model's network, T1; that test went with unkeyed E2EE, eaf1900). Harmless at the target (dropped), but a first frame after such a cancel would start a handler whose caller left (lane CALLTRACES, 2026-11-08) | fixed in lane A2AFINAL (1b8edfa: `clientStream.reached`, a cancel only once a frame went); guarded by `TestClientStream_CancelOnlyForACallThatReachedItsTarget` (red without the guard: `sent 1 cancels, want 0`), invariant `CancelKnown`, mutant `CL:cancel-unreached`, reject fixture `reject-calllifecycle-cancel-unreached.ndjson` |

### Code map (CallLifecycle.tla)

| actions | code |
|---|---|
| `Serve`, `Start`, `Drop`, `Refuse`, `Return` | client/rpcclient/a2a.go, client/rpcclient/a2a_e2ee_agent.go |
| `Send`, `CloseSend`, `Cancel` | client/rpcclient/client_stream.go |
| `Retry` (an E2EE resume answered unknown; `Retries`, `CallLifecycleRetry.cfg`, mutant `CL:retry-runs-again`) | client/rpcclient/client_stream.go (`rehandshake`), client/rpcclient/a2a_e2ee_session.go (`retry`) |
| the mark | proto/pb/service.proto |
| trace recorder | client/rpcclient/trace_callcredit_on.go |

## A2ASession.tla: E2EE sessions reused across agent-to-agent calls

Wire v2 (`client/rpcclient/a2a_e2ee*.go`) handshakes once per call: one
more round trip before the first request frame. A keyed handshake now also
makes a session at both ends; a later call between the same root holder
and machine resumes it in the request's first frame
(`a2a-e2ee-v2-resume`: session id, call number, tag), sends its request
frames at once and derives its own keys `HKDF(S, txn, number, direction)`.
The message exchange (secrecy, agreement, binding to the pair and the
call, revoke) is `spec/proverif/a2a_machine.pv` "Sessions"; this model
holds what ProVerif does not: the callee's replay window, the callee's
restart, expiry, revoke, and the one retry after an unknown. One caller,
one callee; the relay may drop, delay, duplicate and reorder every resume
(`net` is a set) and forge the callee's answer (resumed and unknown are
not sealed: a callee that lost the session has no key to seal with).

The callee answers a resume it does not take `unknown`; the caller then
handshakes once on the same call (a retry) and sends its request frames
again. The retry's message 1 names the resume it retries (session id,
call number, when it was taken; sealed under the pairing key). Without
that, an unknown the relay forged in place of `resumed`, or a resume the
relay held back and delivered after the retry, ran one request twice
(TLC found both; finding S1 below). The callee refuses a retry whose call
number its session took, takes the number when it answers one (so the
held resume is refused), refuses another pair's session and one older
than `a2aRetryBound` (5 min, either clock).

The replay record (lane A2AL1, limit L1 closed; nfltr
`docs/decisions/a2a-at-most-once-restart-2026-11-09.md`): every call number
the callee takes, by a resume or by answering a retry, it first appends to
a file and syncs (`rec`, `client/rpcclient/a2a_e2ee_replay.go`), before the
call starts (`Deliver`, then `Finish`: a restart between them loses the
call, not its record); a restart keeps the record (`Restart`), which lets a
number go only once no retry naming it is within the bound (`Forget`). A
retry of a session the callee no longer keeps (lost to a restart, expired,
evicted) is answered by the record: refused when the number is in it, else
taken. A callee with no record offers no session: every call handshakes.

| invariant | holds because |
|---|---|
| `AtMostOnce` | a call is served at most once, a callee restart between serving it and its retry included (the record; `lost`: the calls served before a restart whose callers still wait) |
| `NoKeyReuse` | a session's call number is used once, so no call key (and no nonce under it) is used twice |
| `RevokeEnds` | nothing is served after the revoke: both ends drop the machine's sessions (`takeCall`, `resume` check the keyring) |
| `OnceRetry` | an unknown makes one retry; an unknown after that fails the call |

| mutant (`make spec-mutants`) | caught by |
|---|---|
| `AS:counter-reset` (call number restarts per call) | `NoKeyReuse` |
| `AS:no-window` | `AtMostOnce` |
| `AS:restart-keeps-sessions` (sessions persisted, windows not) | `AtMostOnce` |
| `AS:survive-revoke` | `RevokeEnds` |
| `AS:retry-loop` (retry again on a second unknown) | `OnceRetry` |
| `AS:no-retry-check` (S1: the callee answers a retry without its call number) | `AtMostOnce` |
| `AS:retry-no-take` (S1: answering a retry leaves the number untaken) | `AtMostOnce` |
| `AS:no-retry-bound` (the record may have let the number go) | `AtMostOnce` |
| `AS:record-in-memory` (L1: a restart loses the record; the code before lane A2AL1) | `AtMostOnce` |
| `AS:record-after-serve` (the call served before its record is synced) | `AtMostOnce` |
| `AS:short-retention` (the record lets a number go a retry within the bound may name) | `AtMostOnce` |

Witnesses `W_Resumed`, `W_Rehandshake`, `W_Failed`, `W_ForgedRefused`,
`W_Lost`, `W_RestartRefused` are violated (a resumed call confirmed, one
served after its retry, one failed, a forged unknown on a served call
refused, a call served before a restart still waiting, and its retry
refused after the restart). `A2ASession.cfg` (`make spec`, every mutant
caught): two calls, three sessions, a window of 1: 255360 states, depth
22, about 17 s, every action taken (`COVERAGE=1`); with three calls the
record's states pass 8 million (not run).
`CallLifecycle.tla` has the retry too (`Retry`, `Retries`;
`CallLifecycleRetry.cfg`, mutant `CL:retry-runs-again`), so the traces of
the session tests are its behaviours.

### Findings (lane A2ASESS, 2026-11-07)

| id | severity | finding | status |
|---|---|---|---|
| S1 | high (design, before landing) | a retry after an unknown ran the request twice when the unknown was the relay's: in place of `resumed` (the callee had run the call), or with the resume held back and delivered after the retry | fixed before landing: the retry names its resume, the callee refuses it or takes its number (`a2aSessions.retry`); `TestA2AE2EELateResumeAfterRetryRefused`, `TestA2AE2EERetryChecks`, `TestA2AE2EEForgedUnknownEndsCall` |
| L1 | low (limit) | a callee that restarts after serving a resumed call, with the relay forging its unknown within `a2aRetryBound`, runs that call again: nothing of the session survives a restart | fixed (lane A2AL1): the callee's replay record, synced before the call starts and kept across a restart, answers the retry of a session it lost (`a2a_e2ee_replay.go`; mutants `AS:record-in-memory`, `AS:record-after-serve`, `AS:short-retention`; `TestA2AE2EERestartAfterServeRefusesForgedRetry`, fixture `reject-a2asession-restart-retry.ndjson`). Lane A2AFINAL had kept it as a limit: refusing every retry after a restart fails each caller's first call after it, which the record avoids |
| S2 | high | found by the A2ASession traces (lane A2AFINAL): a rotation while a resumed call waits for its resumed. The callee served the call and dropped the old key's session (`RecheckA2AE2EE`); a relay's forged unknown made the caller retry under the new key, and the callee, keeping no session, answered the retry: the call ran twice. Trace (`reject-a2asession-rotation-retry.ndjson`): `Handshake t1 s1`, `Resume t2 s1 c1`, `Deliver t2 s1 c1`, `DropIn s1`, `Retry t2 s2 (s1, c1)`: the model drops a session only past the retry bound of its waiting calls (`ExpireCallee`), so the retry is refused (`RetryOK`) | fixed: the caller ends a call whose key no longer holds instead of retrying it (`a2aE2EEState.restart`, as `RecheckA2AE2EE` ends it); a callee still on the old key keeps the session and refuses the taken number, one on the new key refuses the old key id; `TestA2AE2EERotationDoesNotRetryAServedCall` |
| T1 | low | `make spec-traces`: the CallLifecycle traces of tests whose relay drops a call's first frame (`TestA2AE2EERefusesDroppedFrame`, and here `TestA2AE2EELateResumeAfterRetryRefused`) are rejected: the model's network loses nothing (2 such transactions on main before this lane) | closed (lane A2AFINAL): those tests are out of the traces (`CL_TRACE_SKIP`, `scripts/spec.sh` `clrun`): a relay that loses frames is outside CallLifecycle.tla's network; what they check is `a2a_machine.pv`'s (16-18). A `Lose` step for every trace would accept a frame the code lost |

### A2ASession traces

`make spec-astraces` (in `make ci`) runs the A2A E2EE session
tests of the retry, the restart, the forged unknown, the warm, the revoke
and the rotations (`AS_TRACE_TESTS`; `make spec-traces` runs every
`TestA2AE2EE` but `TestA2AE2EEv2Vectors`, whose session no handshake made)
with `-tags relaytrace`, each in its own process (the tests name their
agents alike), and checks each caller and callee pair of each trace against
`TraceA2ASession.tla`: the run must be a behaviour of A2ASession.tla with
that pair's calls and sessions alone (W = `a2aReplayWindow`). The callee
logs `Handshake`, `Warm` and `Retry` (a retry answered: `Unknown`'s
handshake, naming the resume it retries, which must be the call's) when it
keeps the new session, before its ack goes out; `Deliver` when `resume`
takes a call number; `DropIn` when it drops a session (`resume`,
`dropRevoked`); `Restart` (the tests' `restartSessions`) when it loses them
all. The caller logs `Resume` under the sessions' lock (its session and
call number must be the model's `cs`), `Confirm`, `Fail` (a retry refused)
and `DropOut` (`takeCall`, `dropRevoked`). Sessions are numbered per pair
in the order the trace first names them, the order the model makes them.
TLC fills in only what no end logs, and only when the next logged step
needs it: the retry bound passing (`Late`) and the caller losing a session
the model gave it (`ExpireCaller`: an ack the caller never took). Not
logged: the relay's steps, an unknown the caller drops as out of place
(after its retry or its resumed: the model's call is done), eviction past
`a2aSessionMax`. A revoke shows as the drops it makes (`DropIn`,
`DropOut`): the keyring does not say revoke from rotation, so `RevokeEnds`
stays the model's alone. Fixtures `spec/testdata/reject-a2asession-*` must
be rejected: a call number used twice, a resume taken after the retry that
took its number (S1), S2's run below, and L1's (a retry answered after
the restart that followed its served resume). The callee logs `Deliver`
once the record is synced; TLC fills in `Finish` (the call starting) when
the next logged step needs it. The per-push slice: 9 tests, 10 pairs
(`TestA2AE2EERestartAfterServeRefusesForgedRetry` added; out of the
CallLifecycle traces, `CL_TRACE_SKIP`: its relay drops the restarted
callee's answers).

### Environment assumptions

| assumption | source |
|---|---|
| The relay may drop, delay, duplicate, reorder and replay any frame and forge resumed and unknown; it cannot forge a sealed frame or a retry (tags, AEAD, the pairing key) | `spec/proverif/a2a_machine.pv` queries 13-18 |
| A restarted callee has no sessions (they live in memory only) but its replay record (a directory that survives the restart) | `a2aSessions` in `Agent`, `WithA2AE2EEReplayDir` |
| A record the callee synced survives its restart and a power loss (`File.Sync`, `F_FULLFSYNC` on macOS) | `a2aReplayRecord.write` |
| A keyring answers `Valid`/`For` for a revoked machine with a refusal from the revoke on | nfltr `internal/application/a2akeys` |
| The two ends' clocks differ by less than `a2aRetryBound` (else a retry is refused: the call fails, it never runs twice) | `a2aSessions.retry` |
| The callee does not evict a session within `a2aRetryBound` of its last call (it holds `a2aSessionMax` = 1024 per agent) | `evictA2ASession` |

### Code map (A2ASession.tla)

| actions | code |
|---|---|
| `Handshake`, `Resume`, `ExpireCaller` | client/rpcclient/a2a.go (`NewStream`), client/rpcclient/a2a_e2ee_session.go (`takeCall`) |
| `Deliver`, `Finish`, `ExpireCallee`, `Restart` | client/rpcclient/a2a_e2ee_agent.go (`handleE2EEResume`, `startE2EECall`), client/rpcclient/a2a_e2ee_session.go (`resume`, `takeCallNumber`) |
| `rec`, `Forget` (the replay record) | client/rpcclient/a2a_e2ee_replay.go (`write`, `has`, `file`: slots) |
| `Confirm`, `Unknown` (the retry) | client/rpcclient/client_stream.go (`resumeAnswered`, `rehandshake`), client/rpcclient/a2a_e2ee_agent.go (`handleE2EEInit`), client/rpcclient/a2a_e2ee_session.go (`retry`) |
| `Revoke` | client/rpcclient/a2a_e2ee_session.go (`takeCall`, `resume`: the keyring check; `dropRevoked`: both maps at once, run by `RecheckA2AE2EE` in a2a_e2ee_agent.go, which also ends the calls in flight under the revoked key through the existing cancel and `Return`, so CallLifecycle.tla needs no new action) |
| trace recorder | client/rpcclient/trace_a2asession_on.go (`traceAS`; trace_a2asession_off.go without the tag), called from a2a_e2ee_session.go (`takeCall`, `resume`, `dropRevoked`), a2a_e2ee_agent.go (`answerE2EEInit`) and client_stream.go (`resumeAnswered`, `rehandshake`); spec/TraceA2ASession.tla; scripts/spec.sh `astraces` |

## UDPFlow.tla: raw UDP tunnels, the flow lifecycle (design, no code yet)

Lane UDPTUN (2026-11-08). The design is nfltr's
`docs/decisions/udp-tunnels-2026-11-08.md`: an agent's `udp` service, a
client's `connect:` mapping with `listen: "udp:..."`, one link session
per flow (a source address at the client's listener), each datagram
length-framed inside the session's bytes, one connected UDP socket per
flow at the agent. This model is that design's state machine, checked
before any code: the client's one socket reader and flow table, each
flow's sender queue and session, the agent's flow table, idle expiry at
both ends (the client's, and the agent's backstop), the open's refusal
when the agent's table is full, and the death of the link connection
(relay restart, client gone, agent gone).

Invariants: `NoDeliverAfterClose` (no datagram is handed on, to the
target or the application, by a side after it closed the flow it came
on), `TableBounded` (each side's flow table holds at most `MaxFlows`),
`MemoryBound` (per flow at most `Q` queued at each sender and `W` in
flight each way), `NoHOL` (the client's reader never waits on one flow
while another source's datagrams wait); properties `ClosedFinal` (a
closed flow stays closed: link never reuses a session id) and
`AllFlowsEnd` (every flow ends at both sides; every step but a cut is
weakly fair). Mutants, each caught: `UDP:deliver-after-close`
(`NoDeliverAfterClose`), `UDP:no-client-cap`, `UDP:no-agent-cap`
(`TableBounded`), `UDP:grow-queue` (a full queue takes the datagram:
`MemoryBound`), `UDP:block-on-full` (the reader waits on a full flow:
`NoHOL`), `UDP:no-idle` (no timer at either end) and
`UDP:agent-only-close` (the agent ends a flow only on the client's close:
no backstop, the reset ignored; caught after a client death), both
`AllFlowsEnd` on `UDPFlowLive.cfg`. Witnesses, each violated:
`W_Refused`, `W_DropFull`, `W_LateReply` (a reply in flight to a flow the
client closed), `W_LateDatagram` (a datagram in flight to a flow the agent
closed), `W_Expired`, `W_Reply`, `W_CutRecovered` (a flow opened after a
cut carries a datagram).

| action | design (no Go yet) |
|---|---|
| `AppSend(s)` | the application's datagram to the listener |
| `Read(s)` | the client's one reader: onto the source's flow queue, a new flow and session, or a counted drop (`queue_full`, `flows_full`) |
| `PumpC(f)`, `PumpA(f)` | a flow's sender: its queue onto the session, on link credit |
| `RecvC(f)` | the client reads the session: the open's answer, a reply to the flow's source, the agent's close |
| `RecvA(f)` | the agent reads the session: the open (a flow and its socket, or a refusal past `max_flows`), a datagram to the target (its reply queued), the client's close |
| `ExpireC(f)`, `ExpireA(f)` | `udp_idle` (and the open timeout) at the client, `idle_backstop` at the agent |
| `NoticeC(f)`, `NoticeA(f)` | a side reads its session's error after the connection died |
| `Cut(who)` | the link connection dies: `relay` (restart, drain deadline), `client`, `agent` (the process) |

| assumption | source |
|---|---|
| A session is ordered and credited; data for a session its receiver closed is dropped; ids are never reused on a connection | github.com/nfltr/link `WIRE.md` sections 5 and 7 |
| A connection's death ends every session on it at both ends, each learning it on its own time | link liveness (`WIRE.md` section 8); relay-core `spec/AgentLink.tla` (`AgentLinkBreak.cfg`): a stream's end resets its sessions |
| A UDP write never waits (a full socket buffer is a drop) | the design's zero-wait writes; abstracted: a delivery always completes |

`UDPFlow.cfg` (two sources, two session ids, one flow each side, queue
and credit 1, one cut): invariants and `ClosedFinal`, 24,023 distinct
states, depth 28, about 2 s. `UDPFlowLive.cfg` (one source, two ids):
`AllFlowsEnd` too, 2,670 states, about 4 s. `UDPFlowLarge.cfg`
(`LARGE=1`: two sources, three ids, `AllFlowsEnd`): 153,539 states,
depth 33, about 5 min. Every action taken in each (`-coverage 1`); the
14 UDP mutants and witnesses about 20 s. Code map: none yet; the lane
that builds `client/udpflow` adds it with a trace recorder.

Status: design only, no code, so no trace recorder (lane TRACEGAPS,
2026-11-21): the code built is `client/dgram`, one association per
listener (`DatagramAssoc.tla`, which refines this model and is traced);
a per-flow session (`client/udpflow`) is not built.

## BrowserPeer.tla: an nf1 address in a browser, its paths' lifecycle

Lane BROWSERPEER (2026-11-16). The design is nfltr's
`docs/decisions/browser-peer-2026-11-16.md`; its keys are
`proverif/browser_peer.pv`. One visitor tab, one address, `N` streams (app
streams or the page's HTTP requests), the agent's side. The control
session is an `nf1` session over the relay's WebSocket; once admitted, the
agent may create one RTCPeerConnection for it (the SDP inside the control
session). Each stream is its own `nf1` session, opened on a data channel
when the connection is up and the agent's cap `MaxDC` leaves room, else on
a WebSocket through the relay; a stream never changes path: when its path
breaks it fails to the app, and only a new stream takes the other path. The
agent reaps the connection and its channels when the control session ends
or the connection fails.

Invariants: `AtMostOnce` (a request reaches the service at most once: no
replay on the other path), `PCOnlyAdmitted` (the agent holds a connection
only for an admitted control session), `DCOnPC` (no data channel without
its connection), `DCBounded` (at most `MaxDC` at once); properties
`Reaped` (the connection ends once its control session has; the agent's
`Reap` is weakly fair) and `StreamsEnd` (every opened stream ends, done or
failed to the app). Mutants, each caught: `BP:retry-other-path`
(`AtMostOnce`), `BP:pc-before-admit` (`PCOnlyAdmitted`), `BP:no-dc-cap`
(`DCBounded`), `BP:pc-outlives-ctl` (`Reaped`), `BP:dc-without-pc`
(`DCOnPC`), `BP:no-break` (`StreamsEnd`). A data-channel stream whose own
`nf1` handshake fails is refused (`Refuse`, lane BP3: the agent's proof
check on each channel). Witnesses, each violated:
`W_DoneDC`, `W_DoneWSAfterFail` (a stream done over the relay after the
connection failed), `W_Failed`, `W_ReapedAfterCtl`.

| action | design |
|---|---|
| `CtlOpen`, `CtlAdmit` | the page's control session over the WebSocket: the `nf1` handshake, the agent's `Admit` |
| `CtlEnd` | the tab closes, the relay cuts the WebSocket, the agent drops the session |
| `Offer` | the agent answers the page's SDP inside the admitted control session and creates its connection (pion) |
| `PCUp`, `PCFail` | ICE and DTLS complete, or fail (or a NAT drops the binding) |
| `Reap` | the agent closes the connection and its data channels |
| `OpenDC(s)`, `OpenWS(s)` | the page opens a stream: a data channel under the cap, else a WebSocket |
| `Deliver(s)`, `Complete(s)` | the stream's `nf1` handshake and request reach the service; its answer reaches the page |
| `Break(s)` | a data channel's connection is gone: the stream fails to the app |
| `Refuse(s)` | a data channel's own `nf1` handshake fails (its proof, its TLS): the stream fails to the app |

| assumption | source |
|---|---|
| A WebSocket and a data channel are each an ordered, reliable byte stream until they end; an end reaches both sides | RFC 6455; RFC 8831 (data channels, reliable and ordered as the page opens them) |
| ICE and DTLS end in connected or failed; a consent-freshness failure is a failure | RFC 8445; RFC 7675 |
| A request carried on a broken path may or may not have reached the service | the abstraction of `Deliver` before `Break` |

`BrowserPeer.cfg` (three streams, `MaxDC` 2, one connection failure):
invariants and both properties, 4,902 distinct states, depth 17, about
10 s; every action taken (`-coverage 1`); the 6 mutants and 4 witnesses
about 20 s.

### Code map (BrowserPeer.tla)

Lane BP3 (2026-11-16) built the agent's side, `client/p2p`
`browserpeer.go` (`BrowserDirect`), served from `client/agent`
`direct_nf1.go` for a session whose answer said `nf1.HintBrowser` and whose
first byte is the visitor's mark. Lane BP4 (2026-11-16) built the page's
side (`OpenWS`, its choice of path, `AtMostOnce`), the extension's
`browser/src/nf1.ts` (`NF1Client`, `Direct`) over the wasm client
`client/nf1/internal/extension`; it records no trace (a page's steps are
the agent's actions' other ends, which BP3's recorder logs), and
`make browser-e2e` drives it against BP3's agent in Chromium. One `mu` per
control session orders the agent's steps; a step's trace line is written
under it.

| actions | code |
|---|---|
| `CtlOpen`, `CtlAdmit`, `CtlEnd`, `Offer` (`run`, `answer`, `end`); `PCUp`, `PCFail`, `Reap` (`onState`, `upLocked`, `reapLocked`); `OpenDC`, `Deliver`, `Complete`, `Break`, `Refuse` (`onDataChannel`, `stream`) | client/p2p/browserpeer.go |
| the control session's dispatch (the mark after a `HintBrowser` answer) | client/agent/direct_nf1.go |
| `HintBrowser` in the signed record | client/nf1/nf1.go |
| `OpenWS`, the path choice, a stream lost never re-sent (`AtMostOnce`: `NF1Client.open`, `Direct.stream`; a failed stream ends to the page) | browser/src/nf1.ts |

### BrowserPeer traces

`make spec-bptraces` (in `make ci`; `scripts/spec.sh bptraces`) runs
client/p2p's browser tests with `-tags relaytrace` (recorder
`client/p2p/browserpeer_trace_on.go`, one file per control session) and
checks each trace with `TraceBrowserPeer.tla`: every line one action of
`BrowserPeer` with the run's `MaxDC` (its `Serve` line), the trace's
streams, connection failures bounded by its length. A connection the
visitor closed is a failure to the agent (`PCFail`). It fails on a
`TraceBrowserPeer.tla` event that `browserpeer.go` never records. The
fixtures `testdata/reject-browserpeer-*` are rejected: a stream delivered
twice (`AtMostOnce`), an offer before admission (`PCOnlyAdmitted`), a
channel past the cap (`DCBounded`), a channel after the reap (`DCOnPC`),
a stream completed on a failed connection (`no-break`). The nightly
`make spec-traces` runs every `TestBrowserDirect` and the bindings rows
(which take `Refuse`).

## DatagramAssoc.tla: datagram sessions between identities

Lane NF1UDP (2026-11-14). The design is nfltr's
`docs/decisions/nf1-udp-2026-11-14.md`: UDP between identities (an `nf1`
address, an organisation machine) over one **association** per client
listener and service: one end-to-end session (the same rendezvous, pinned
TLS and admission as a stream session) whose stream carries control and
datagrams, many flows inside it (a source address at the listener is a
flow with an id the client picks, increasing and never reused; one
connected socket per flow at the agent), and, once the association's
stream is attached to the direct QUIC connection, datagrams as QUIC
DATAGRAM frames tagged with the association and the flow. It refines
`UDPFlow.tla` (one session per flow) and adds the second, lossy path,
moves between the paths, revocation and the amplification bound.

Invariants: `NoDeliverAfterClose`; `NoCrossFlow` (no datagram reaches a
flow other than its own: another source's, another association's);
`NoDeliverAfterRevoke` (nothing reaches the target once the association's
right was revoked, on either path); `TableBounded` (each side's cap per
association, set independently); `MemoryBound`; `NoHOL` (the listener's
reader never waits on one flow); `NoReflection` (a source the listener
does not admit is never written to); `AmpBound` (to each source at most
`R` times what it sent plus `B`); `NoLostOnMove` (lane DGRAMBIND: no
frame reaches a running end under its association's tag before that end
bound there: each end sends direct only once the other is bound);
properties `ClosedFinal` (ids never reused) and `AllFlowsEnd` (every flow
ends at both sides; the environment's steps, `BindA`, `PathLoss`,
`Revoke`, `Cut`, are not fair).

Mutants, each caught: `DA:deliver-after-close` (`NoDeliverAfterClose`),
`DA:reuse-id` (`ClosedFinal`; checked as `NoCrossFlow` on
`DatagramAssocTwo.cfg` with the property taken out), `DA:tag-unchecked` (a frame's flow id
looked up in the current association whatever its tag: `NoCrossFlow`, on
`DatagramAssocMove.cfg`), `DA:direct-ignores-assoc` (the direct path
does not check that the association is up, so a revocation reaches only
the stream until the cleanup: `NoDeliverAfterRevoke`), `DA:no-client-cap`,
`DA:no-agent-cap` (`TableBounded`, on `DatagramAssocTwo.cfg`),
`DA:grow-queue` (`MemoryBound`), `DA:block-on-credit` (the reader waits
for stream credit: `NoHOL`), `DA:no-source-check` (`NoReflection`),
`DA:no-amp-cap` and `DA:per-flow-budget` (the budget kept per flow, so
a source's new flow starts a new one: `AmpBound`), `DA:no-idle`
(`AllFlowsEnd`, on `DatagramAssocLive.cfg`), `DA:client-binds-first`
(the agent's token sent before its attach, so the client binds and sends
direct before the agent took the stream: `NoLostOnMove`; relay 0424e437
under load, 4 of 300 `echo of "direct-0"`), `DA:agent-sends-unheard` (the
agent replies direct as soon as it attached, before the client checked
its token: `NoLostOnMove`). Witnesses, each violated:
`W_Direct`, `W_Moved` (a flow that went direct carries on relayed),
`W_StaleTag` (an older association's frame reaches a newer one, and is
dropped), `W_Revoked`, `W_Refused` (an open after the revocation),
`W_AmpDrop`, `W_Reply`, `W_FlowRefused`, `W_RefusedWithRoom` (lane
NF1UDPBOUND: an open refused while the association has room: the
service's bound on all its associations' flows together, or an
unreachable target), `W_EarlyReply` (lane UDP3: a
direct reply opened a flow whose accept is still on the stream),
`W_HalfBound` (the agent bound, the client not yet), `W_Heard` (the agent
took a client's frame direct and replies direct).

| action | design (no Go yet) |
|---|---|
| `AppSend(s)` | the application's datagram to the listener, or a spoofed one |
| `AssocOpen` | the association's open (`nf1` rendezvous, TLS, proof; or the organisation open); refused after a revocation |
| `Read(s)` | the listener's one reader: a drop for a source it does not admit, onto the source's flow (direct, or the stream on credit), a new flow (its open carries the datagram), or a counted drop |
| `RecvC`, `RecvDgC(m)` | the client reads the stream (an open's answer, a reply, a close) or a frame; a reply is written within the source's budget; a frame for a flow still opening is its accept (it overtook the A on the stream) |
| `RecvA`, `RecvDgA(m)` | the agent reads the stream (an open: a flow and its socket, or a refusal: past its cap, or at any time for what lies outside the association, the service's bound across associations or an unreachable target; a datagram; a close) or a frame (only under a tag bound here, while the association is up) |
| `ReplyA(k)` | the target's reply: direct when bound, else the stream on credit, else dropped |
| `ExpireC(k)`, `ExpireA(k)` | the flow's idle timer, the agent's backstop |
| `NoticeC`, `NoticeA`, `CleanupA` | a side reads its association's end; the agent marks it down, then closes its flows and drops its binding |
| `BindA`, `BindC`, `PathLoss` | the agent attaches the client's direct stream (the client's token), then sends its own token; the client binds once it checked that token; the direct connection's death |
| `Cut(who)` | the association ends: `session` (the stream reset, the direct connection kept), `client`, `agent` (the process) |
| `Revoke` | the agent applies a revocation (address replaced, certificate revoked) |

| assumption | source |
|---|---|
| The stream is ordered and credited and survives path moves | github.com/nfltr/link `spec/Link.tla`, `spec/DirectPath.tla` |
| An association binds to a direct connection only on both ends' tokens | `spec/proverif/cap_address.pv` queries 17-18, `spec/proverif/e2ee_tcp.pv` 21-26 |
| A frame reaches an association only under a tag bound on its connection | `spec/proverif/cap_address.pv` query 22, `spec/proverif/e2ee_tcp.pv` 39 |
| An association is of its service's kind: a relay cannot join a stream client to a datagram service or the reverse | `spec/proverif/cap_address.pv` query 25 (`u1` in the record), `spec/proverif/e2ee_tcp.pv` 42 (the ALPN's kind) |
| A QUIC frame is authenticated; a replayed packet is discarded | RFC 9000 section 12.3 (quic-go) |
| A UDP write never waits | the design's zero-wait writes and per-association sender |

`DatagramAssoc.cfg` (one admitted source sending two datagrams, one
spoofed, two ids, two associations, the target answering twice per
datagram, one association end, one path death): 106,926 distinct states
(lane NF1UDPBOUND, with the refusal with room; 87,810 before).
`DatagramAssocMove.cfg` (one source, three datagrams): 162,106 states.
`DatagramAssocTwo.cfg` (two admitted sources, one association, the
client's cap above the agent's): 14,945 states.
`DatagramAssocLive.cfg` (`AllFlowsEnd`): 20,443 states (lane DGRAMBIND,
with the two binds; fewer than one bind's: the agent's replies wait for
a client's frame to go direct). `-coverage 1`
takes every action in each (but `PathLoss` in `DatagramAssocTwo.cfg`,
which has none).

### Code map (DatagramAssoc.tla)

Lane UDP2 (2026-11-14) built the relayed association, `client/dgram`;
lane UDP3 the direct path. `Revoke` is the agent's end of the
association (the session's reset: the direct path's per-frame check, then
`Server.Close` with the session's end), `Cut` the stream's end. The code's
tag is finer than the model's: the model's is the association's epoch,
the code's the attach stream's QUIC stream id (each re-attach a new one),
so the code drops every frame the model drops and a few more (an older
attach's of the same association): loss only. Each end binds on its own
(lane DGRAMBIND): the agent at its attach (`BindA`: `Attach`, then the
agent's token, the first bytes on the stream: `pathStream.first`), the
client once it checked that token (`BindC`: `tokenCheck`, then
`sessionDatagrams.ready`); the client sends direct only then and the agent
only once it took a client's frame on that stream (`aheard`:
`sessionDatagrams.ready` at the agent), so no frame goes to an end not yet
bound (`NoLostOnMove`; the agent's token before its attach lost the
client's first direct datagram, relay 0424e437). Spill (a datagram too large
for a packet goes on the stream) is a choice between the two carriers the
model has, no state of its own: `Read`'s and `ReplyA`'s `spill` (lane
DGRAMTRACE; before, the model sent every datagram of a bound flow direct,
which the traces of the move test refuted at its 4000-byte datagram).

| actions | code |
|---|---|
| `AssocOpen`, `Read` (admission, budget) | client/dgram/forward.go |
| `Read` (flow table, queue), `RecvC`, `ExpireC`, `NoticeC` | client/dgram/client.go |
| `RecvA`, `ReplyA`, `ExpireA`, `Revoke`, `CleanupA` | client/dgram/server.go |
| `RecvDgC`, `RecvDgA` (the association's half), the direct branch of `Read` and `ReplyA`, spill | client/dgram/direct.go |
| `RecvDgA` and `RecvDgC` (the tag and the session's state per frame), the direct send gate (`aheard`, `cbnd`) | client/agent/direct_datagram.go |
| `BindA` (attach, then the token) | client/agent/direct_server.go `acceptDirect` |
| `BindC` (the agent's token checked) | client/agent/direct_client.go `tokenCheck` |
| the stream, its one sender, `Cut` | client/dgram/assoc.go |
| framing | client/dgram/frame.go |
| trace recorder | client/dgram/trace_on.go (the association's steps; `traceSend`: a datagram's carrier as it is sent), client/agent/trace_dgram_on.go (`BindA`, `BindC`), client/agent/direct_datagram.go (`lost`: `PathLoss`), client/internal/dgtrace/ (the one file) |

### DatagramAssoc traces

`make spec-dgtraces` (in `make ci`; `make spec-traces` runs it too): the
traced test of `client/dgram` (`TestDatagramAssocTrace`: a listener with
two admitted sources and one refused, the target's replies, a third flow
past the agent's cap refused, idle closes), three runs each in its own
process with `-tags relaytrace`, each trace checked by
`TraceDatagramAssoc.tla` against `DatagramAssoc` with one association:
every line a step of the model, a datagram's delivery or drop the
model's, under `TypeOK`, `NoDeliverAfterClose`, `NoCrossFlow`,
`TableBounded`, `NoHOL` and `NoReflection`. The application's sends are
TLC's; recording stops at the association's end. Three hand-made traces
must be rejected (`spec/testdata/reject-datagramassoc-*`): a datagram
delivered after the agent closed its flow, a flow accepted past the
agent's cap, an open from a source not admitted. The byte budget
(`AmpBound` in bytes) is the Go test's (`TestDatagramAssocAmpBound`): the
model counts datagrams.

The direct path's steps (lane DGRAMTRACE) come from `client/agent`'s tests
that move an association direct (`DG_DIRECT_TESTS`, default
`TestDatagramDirectMovesAndFallsBack`: relayed, direct both ways, a spill,
the direct connection's death and relayed again;
`TestDatagramDirectOnlyOnceTheAgentAttached`: the attach held), three
runs each: the agent's attach (`BindA`, after `Attach`, before its token),
the client's check of that token (`BindC`), each side taking a frame off
the direct connection (`RecvDgA`, `RecvDgC`, delivered or dropped as the
model does), the carrier each datagram and reply took (`op`/`out`:
`direct`, the stream, `spill`; on the stream while bound only spilled or
after a `PathLoss`), and an end finding its bound path gone (`PathLoss`,
from the carrier's refusal `dgtrace.ErrLost`: the first end's is the
model's, the other's changes nothing), under `NoLostOnMove` too. A
datagram that may go direct is recorded by the association's sender as
it sends it, the trace's lock held across the send, so its receiver's
line comes after it. Two more hand-made traces must be rejected, the two
orders DGRAMBIND fixed: the client binds before the agent attached
(`reject-datagramassoc-client-binds-first`), the agent replies direct
before it took a client's frame (`reject-datagramassoc-agent-sends-unheard`);
each is accepted with its two steps in the right order. Ceiling: the
recorder orders one flow's steps; a traced run with a direct path and
several flows in flight at once may record an open-flow datagram (logged
at its send) after another flow's open (logged as it is queued) that the
stream carries after it, a false rejection, so `DG_DIRECT_TESTS` run one
flow at a time.

The association's end (lane TRACEGAPS, 2026-11-21): each side's end is
logged under its lock before anything of it is seen (`assoc.endWith`):
its own (`Cut`: the client's `Close` or idle end, `who` client; the
agent's `Serve` stopped, `who` agent), the agent's revocation (`Revoke`:
`Server.Close`, `CloseWith`), or the stream's end it read (`NoticeC`,
`NoticeA`), then the agent's `CleanupA` once its flows closed (not at its
own stop, whose flows end with it); recording stops once both sides
ended. `TestDatagramAssocTrace` ends with the client's `Cut`, `NoticeA`,
`CleanupA`; `TestDatagramAssocTraceRevoke` with `Revoke`, `CleanupA`, the
tail's close and `NoticeC`. A revocation's tail (`CloseWith`'s reason, a
close per open flow on the stream after what the sender wrote) is below
the model, whose `Revoke` resets the stream at once: the client's
`RecvC` of a tail close (`out` `tail`) changes nothing and is taken only
after a `Revoke` with the stream empty; a direct frame a side drops once
it ended changes nothing either. Ceiling: a frame in flight at an end is
delivered by the code (the stream is FIFO) and dropped by the model, so a
traced run ends quiet; the end tests run that way. Two more hand-made
traces must be rejected: a datagram delivered to the target after the
revocation (`reject-datagramassoc-deliver-after-revoke`), a tail close
with no revocation (`reject-datagramassoc-tail-without-revoke`).
`NoDeliverAfterRevoke` is checked on every trace. Not traced:
the session's `Cut` (the stream reset with both processes running: no
side's step logs it), and `client/agent`'s `dgUnit` tests (`TestDatagramRevokeOnDirect`, `TestDatagramModelBindings`,
`TestDatagramAgentDirectOnceItHeardTheClient`), whose client frames are
raw ones under any tag, no association's; their Go mutants
`direct-ignores-assoc`, `tag-unchecked` and `agent-sends-unheard`
(`client/agent/testdata/direct_dgram_mutants.txt`) cover them.

## DirectPunch.tla: one punch, with peer-reflexive candidates

Design: nfltr `docs/decisions/nat-symmetric-lan-2026-11-16.md` (lane
NATSYM). The client of a pair dials the agent's offered candidates at
once (`quiclink.Punch`) and, while it punches, reads the agent's probes:
a probe carrying the control exchange's tag (an exporter of that
exchange's TLS) from an address it does not dial is a peer-reflexive
candidate (ICE, RFC 8445 7.2.5.3.1, 7.3.1.3), dialled too. That opens a
public client toward an agent behind an endpoint-dependent (symmetric)
NAT. Owner 2026-11-16 ("direct is always preferred and relay is when
direct not possible"; nfltr `docs/decisions/direct-paths-2026-11-11.md`
"Direct by default"): the punch tries every candidate and stays relayed
only when none works; among the paths that work a LAN one wins: a
connection to a private or link-local address replaces a non-LAN winner,
and the LAN dials outlive a non-LAN win by `lanGrace` (100 ms), in which
a LAN probe is still learned (ICE's host-before-reflexive type preference,
RFC 8445 5.1.2.2); the rest by measured handshake RTT (the first up among
those dialled together). `make spec` checks `DirectPunch.cfg` (two offered
candidates, one the peer's and one someone else's on this LAN; two probe
sources, one a LAN address that answers before the bound (`Reach`); one
off-path untagged sender; three dials at most; a bound of two ticks).

| invariant / property | statement | mutant (`scripts/spec.sh mutants`) |
|---|---|---|
| `OnlyTagged` | a dialled address is offered or a tagged probe's source | `no-tag` |
| `DialBound` | at most MaxCands dials per punch | `no-cap` |
| `OnlyPeer` | the kept connection passed the certificate check | `no-cert-check` |
| `OneConnection` | once the punch returned, its only connection is the kept one | `return-early` |
| `DirectIfWorks` | a punch that returned relayed dialled no working candidate and closed no connection | `give-up-at-bound` |
| `PreferLan` | a punch that returned on a non-LAN connection dialled no working LAN candidate | `first-wins` |
| `NoWait` | every offered candidate is dialled from the punch's start, whatever the address check (trickle) | `wait-qad` |
| `Ends` (liveness) | every punch returns | `no-bound`, `keep-loser` |

Trickle (lane TRICKLE, 2026-11-18; nfltr
`docs/decisions/direct-paths-2026-11-11.md` "Trickle"; ICE trickle, RFC
8838): neither end waits for its relay's address check (QAD, up to 3 s
when the relay's UDP port is silent) or its port mapping (up to 500 ms)
before its first candidates line: the host candidates go at once, and a
reflexive or mapped candidate follows on the control session as one more
`{"candidates":[...]}` line when it arrives. The client reads the agent's
later lines as learned candidates (`AgentTrickle`, then `Learn`: the
control session's TLS authenticates them as a probe's tag does); the
agent probes the client's later ones. `QADEnd` is the agent's check
ending (answered or timed out, not fair: it may never); the bug before
it is mutant `wait-qad` (the offered candidates dialled only once the
check ended: a silent port held each anonymous session's first byte for
about 3 s).

`PreferLan` holds only for a LAN path whose handshake ends within the
grace (`Reach`): a LAN path that connects after the grace, or after the
punch returned, is not switched to; the session stays on the non-LAN
direct path (moving a live session to a later path is not modelled and
not built). On a loaded machine a loopback handshake can outlast 100 ms,
so `TestDirectPunchPrefersLAN` orders its peers by events (the LAN peer
reads only after the non-LAN handshake ended) and sets the grace past its
bound (lane R15FIX, 2026-11-17).

A port-mapped address (NAT-PMP, `client/agent/direct_portmap.go`; nfltr
`docs/decisions/portmap-2026-11-16.md`) is one more of `Offered`: the
mapping's lease is renewed before an offer names it, so the punch is
unchanged and the model with it.

Witnesses (each violated): `W_PrflxWon`, `W_OfferedWon`, `W_Relayed`,
`W_RogueRefused`, `W_LoserClosed`, `W_LanReplaced` (a LAN connection
replaced a non-LAN winner), `W_NonLanWon`, `W_TrickledWon` (the trickled
reflexive candidate won), `W_LanBeforeQAD` (a LAN path won while the
address check still ran). TLC 2026-11-18 (`-coverage 1`): 6,264 distinct
states, depth 18, every action taken.

| action | Go |
|---|---|
| `AgentProbe` | `directServer.control`: `DirectEndpoint.probe` with `probeTag` |
| `QADEnd`, `AgentTrickle` | `DirectEndpoint.gather` (the slow sources), `sendLate` at the agent; `DirectSession.punch`'s `readLate` feeding the learned channel |
| `SpoofProbe`, `Learn` | `DirectEndpoint.readProbes` (the tag's waiter), `DirectEndpoint.punch` (the learned case) |
| `DialUp`, `DialFail` | `quiclink.Punch` per dial, `punchTLS`'s certificate check |
| `Win`, `CloseLoser`, `Settle`, `Return`, `Tick` | `DirectEndpoint.punch` (first wins, a LAN one replaces a non-LAN winner, the others closed, the LAN grace, returns once no dial runs), `dialPair`'s 5 s bound |

### Environment assumptions

| assumption | source |
|---|---|
| A UDP datagram may be lost, and a NAT may drop every packet toward an address (no fairness on `AgentProbe` and `DialUp`) | RFC 4787 (filtering behaviour) |
| quic-go hands a datagram whose first byte has its two high bits clear to `ReadNonQUICPacket`, never to a connection | quic-go `Transport.handleNonQUICPacket` |
| Only the two ends of a control exchange can compute its exporter | RFC 8446 section 7.5 |
| Who answers at an address is the certificate check | `spec/proverif/e2ee_tcp.pv`, BIND:direct.cert |
| A dial that ends before the bound with no winner was refused (`Rogue`): the certificate check, or the network refusing the send at once (EADDRNOTAVAIL, ICMP unreachable); a silent address fails only at the bound or once a connection won | POSIX `sendmsg` errors; RFC 1122 section 4.1.3.3 (ICMP errors to UDP) |
| A working path's handshake ends before the punch's bound, a working LAN one within `lanGrace` (`Reach`; Tick and Settle wait on it) | the 5 s bound and 100 ms grace against LAN/WAN RTTs; a slower path is out of `Reach` and the punch may return without it |

### Code map (DirectPunch.tla)

| actions | code |
|---|---|
| `AgentProbe`, `Learn`, `Win`, `CloseLoser`, `Return` | client/agent/direct_prflx.go |
| `AgentProbe` (when) | client/agent/direct_server.go |
| `Learn` (listen), `Tick` (bound) | client/agent/direct_client.go |
| `Offered` (the mapped candidate) | client/agent/direct_portmap.go |
| `QADEnd`, `AgentTrickle`, `NoWait` (gather, sendLate, readLate) | client/agent/direct.go |

| trace recorder | client/agent/trace_punch_on.go |

### DirectPunch traces

`make spec-ptraces` (in make ci, about 30 s): client/agent's punch tests
(`TestDirectSymmetricAgentGoesDirectPeerReflexively`, `TestDirectPunchPrefersLAN`,
`TestDirectMappedAgentGoesDirect`, `TestDirectSessionMovesAndFallsBack`, `TestDirectModelBindings`,
`TestDirectAgentRebindDirectAgain`) built `-tags relaytrace`, each in its
own process; every punch writes `directpunch-<pid>-<n>.ndjson` (Init with
the offered candidates, Learn with what the punch did, DialUp then Win or
CloseLoser, DialFail, Return with the kept address), checked by
`spec/TraceDirectPunch.tla` (constants from the trace: the addresses that
came up are the peer's, the LAN ones as the code classified them, no
`Reach`; TLC adds the agent's probes and the clock). Six
traces on the Mac 2026-11-16, every step kind taken (Learn dialled and
ignored, Win, CloseLoser, DialFail). Rejected fixtures, one per invariant
the trace can break: `reject-directpunch-untagged` (OnlyTagged),
`-over-cap` (DialBound), `-second-connection` (OneConnection),
`-learn-after-win`, `-lan-closed` (a LAN connection closed under a
non-LAN winner), `-fail-before-bound` (a dial that failed before the bound
with no winner, not refused). A `DialFail` line carries `refused`: the dial
ended on its own, before its context and not by a timeout; those
addresses are the trace's `Rogue` (`TraceRogue`), every other failure is
the bound's or a win's. Before (lane PUNCHTRACE, 2026-11-26) the trace had
no `Rogue`, and a Mac with a bridge interface at 192.168.194.0 (its offer
names it; `sendmsg` there fails at once with EADDRNOTAVAIL) had every
punch trace that dialled it rejected: the code was right, the trace's
mapping assumed no early failure. The Go mutants `prflx-*` in
`client/agent/testdata/org_mutants.txt` plant the code's bugs.

## PunchRound.tla: a punch round's timing and retries

Design: nfltr `docs/decisions/direct-punch-timing-2026-11-21.md` (lane
HOLEPUNCH). The layer above `DirectPunch.tla`: one pair's round of
attempts, each a fresh control exchange over the relay. The client times
its request until the agent's offer (the relay's round trip, rtt), sends
its candidates (the sync) and dials them rtt/2 later; the agent probes the
client's candidates as soon as it reads them, about rtt/2 after the sync.
So the agent's first probe has left its NAT when the client's first QUIC
Initial reaches it, and the first Initial passes instead of a retransmit
one PTO (about 300 ms) later. An attempt that no candidate answered is
retried with a new exchange and a new rtt, at most three attempts per
round; a refused certificate, a withheld exchange or an offer's refusal
ends the round relayed at once. Prior art: a coordinated simultaneous open
timed from a round trip measured over the relayed channel, with up to
three attempts (the decision doc's prior-art section). The attempt's dials
are `DirectPunch.tla`; here only its end and its first Initial. `make
spec` checks `PunchRound.cfg` (a pair a punch passes) and
`PunchRoundSym.cfg` (one no punch passes): relay one-way delays 1 or 3
ticks each per attempt, a direct one-way delay of 1, the Initial
retransmitted every 2, an attempt's bound 4, an exchange's 7.

A session that ends while its round runs (a short transfer toward a pair
no punch passes) starts no further attempt and reports no path for the
attempt its end cut, from its Close on (a client's clean end closes
`Done` only a detach bound later; `TestDirectPunchRoundStopsWhenTheSessionEnds`,
Go mutants `round-past-end`, `round-done-only`; found in the NAT lab: 64 MiB sessions that ended
at 11 s reported `relayed/withheld` after three attempts). Not modelled:
stopping early only shortens a behaviour, and every invariant holds on
its prefixes.

| invariant / property | statement | mutant (`scripts/spec.sh mutants`) |
|---|---|---|
| `RetryBound` | at most MaxAttempts (3) attempts per round | `unbounded` |
| `RetryOnlyNoAnswer` | a retry follows only an attempt no candidate answered | `retry-refused` |
| `InitialAfterProbe` | the client's first Initial reaches the agent's NAT once the agent's first probe left it | `dial-before-sync`, `stale-rtt` (the first attempt's rtt reused), `asymmetry` (Delays {1, 5}: the assumption broken) |
| `FirstInitialWins` | a won attempt won on its first Initial | (follows from the above) |
| `NeverHeld`, `DirectOnlyWon` | the session runs relayed until the round moves it, never held by it | `block-during-punch` |
| `Ends` (liveness) | every round ends, direct or relayed, whatever the peer does (it may vanish mid-exchange or mid-punch) | `no-fallback`, `wait-vanished` (no exchange bound) |

Witnesses (each violated): `W_DirectFirst`, `W_DirectRetry` (direct after
a lost attempt), `W_VanishedRelayed`, `W_Refused`, and in
`PunchRoundSym.cfg` `W_RelayedAfterRetries`. TLC 2026-11-21 (`-coverage
1`): `PunchRound.cfg` 5,282 distinct states, depth 56, every action taken;
`PunchRoundSym.cfg` 5,698, depth 54, every action but `Win` (no punch
passes there).

### Environment assumptions

| assumption | source |
|---|---|
| The relay's one-way delays differ by at most twice the direct one-way delay (`Delays` against `Dd`); they may change between attempts | measured round trips are symmetric on average (RFC 6349 section 3.2, RTT as the basis of timing); mutant `asymmetry` shows what breaks past it: a retransmit, not a failure |
| The agent answers a request and probes on reading the sync at once | `directServer.control`: gather's host candidates are immediate, the slow ones trickle |
| A NAT lets a punch through (cone) or never (symmetric); the network may drop every packet of an attempt | RFC 4787 (mapping and filtering behaviour) |
| A QUIC client retransmits its Initial each PTO until its handshake bound | RFC 9002 section 6.2 |
| The control session ends at its bound (15 s) when the peer is gone | `directControlBound`, `context.AfterFunc` closing it |

### Code map (PunchRound.tla)

| actions | code |
|---|---|
| `Start`, `NoAnswer`, `Refused` (the round, its retries) | client/agent/direct_client.go (`punchRound`) |
| `Sync`, `Dial`, `Withheld` (the exchange, rtt, the wait) | client/agent/direct_client.go (`punch`) |
| `Vanish` (the agent's side of an exchange) | client/agent/direct_server.go |

| trace recorder | client/agent/trace_round_on.go |

### PunchRound traces

`make spec-ptraces` checks them with the DirectPunch ones, from the same
test runs: every round writes `punchround-<pid>-<n>.ndjson` (Start with the
attempt, Sync with the measured rtt, Dial with the wait and the time since
the sync, then Win, NoAnswer, Refused or Withheld), checked by
`spec/TracePunchRound.tla` (TLC chooses the delays, the clock, the losses
and a vanishing; each Dial's wait must be at least half its rtt and the
time since the sync at least the wait). Rejected fixtures, one per
invariant a trace can break: `reject-punchround-unbounded` (RetryBound),
`-retry-refused` (RetryOnlyNoAnswer), `-dial-early` (InitialAfterProbe).

## PortMap.tla: a direct endpoint's port mapping in three protocols

Design: nfltr `docs/decisions/hardnat-2026-11-25.md` (lane HARDNAT). At
each offer the endpoint asks its gateway to map its UDP port: PCP (RFC
6887) first, NAT-PMP (RFC 6886) when PCP gets a version-0 answer or none,
UPnP-IGD (`AddPortMapping`) last; the first that maps wins the round and
its address is one more candidate (`DirectPunch.tla`'s `Offered` or
`Trickled`, so the punch's model is unchanged). A round renews the held
mapping with its own protocol first and, if that fails, asks in that
order; a PCP refusal (the gateway speaks PCP and said no) skips NAT-PMP.
It renews only the mapping it holds; `Close` deletes it.

Checked: `NoPermanent` (no mapping without a lease: a 725
OnlyPermanentLeasesSupported gets none), `OneLive` (the only live mapping
is the held one, or one whose delete was lost), `NoMapAfterClose`,
`DeletedOnClose`; `Ends` (every round ends), `NoLeak` (a mapping nobody
renews ends). `make spec` checks `PortMap.cfg` (two rounds, one gateway
change, every combination of protocols spoken and permanent-only).
Mutants (`make spec-mutants`): `map-after-close` (the NAT-PMP code before
HARDNAT: an ask after `Close` mapped and nothing deleted it), `ask-all`,
`accept-permanent`, `no-delete`. Witnesses (each violated): `W_Held`,
`W_FellBackToUPnP`, `W_Switched` (a round mapped with another protocol and
the old one's delete was lost), `W_ClosedInFlight`, `W_PermRefused`,
`W_Stale` (the gateway lost the held mapping before the next round). TLC
2026-11-25 (`-coverage 1`): 6,369 distinct states, depth 15, every action
taken.

### Environment assumptions

| assumption | source |
|---|---|
| A gateway ends a lease nobody renews (fairness on `Expire`) | RFC 6886 section 3.3, RFC 6887 section 15, UPnP IGD `NewLeaseDuration` |
| A request or a delete may be lost; an ask ends at its bound (fairness on `Mapped`, `NotMapped`) | RFC 6886 section 3.1, RFC 6887 section 8.1.1 (UDP); the asks' own bounds in direct_portmap.go |
| A NAT-PMP-only server answers a PCP request with version 0 (Unsupported Version) or not at all | RFC 6887 appendix A, RFC 6886 section 3.5 |
| An IGD v1 that grants only permanent leases refuses a leased one with 725 | UPnP IGD WANIPConnection:1 error codes |
| A restarted gateway loses its table (`GatewayChange`) | RFC 6887 section 8.5 (epoch) |

### Code map (PortMap.tla)

| actions | code |
|---|---|
| `Round`, `Mapped`, `NotMapped`, `Close` | client/agent/direct_portmap.go |
| `Mapped`, `NotMapped` (PCP) | client/agent/direct_pcp.go |
| `Mapped`, `NotMapped` (UPnP-IGD) | client/agent/direct_upnp.go |

| trace recorder | client/agent/trace_portmap_on.go |

### PortMap traces

`make spec-ptraces` (in make ci, with the DirectPunch traces): client/agent's
port mapping tests (`TestDirectPortMapLease`, `TestDirectPortMapPCP`,
`TestDirectPortMapSwitchDeletesOld`, `TestDirectPortMapUPnP`,
`TestDirectPortMapUPnPPermanentOnly`, `TestPortMapNoMapAfterClose`) run
with `-tags relaytrace`; each endpoint's steps (Round with the protocol
asked first, Mapped, NotMapped, Close; whether a delete went with it and
the lease asked) are checked against `spec/TracePortMap.tla`. TLC picks
the gateway (what it speaks, its leases, its changes). Rejected fixtures
(`spec/testdata/reject-portmap-*`): a round after the close
(NoMapAfterClose), a second mapping in one round (OneLive), a mapping
asked with lease 0 (NoPermanent), a close and a protocol switch with no
delete (DeletedOnClose, OneLive).

## Birthday.tla: birthday probing for an easy/hard pair (design; code next)

Design: nfltr `docs/decisions/hardnat-2026-11-25.md` "birthday probing"
(lane HARDNAT; the code is the next lane, which adds the trace recorder).
A pair where exactly one side's NAT maps per destination (endpoint
dependent, RFC 4787; known from two QAD observers, RFC 5780 4.3) and an
attempt ended `no_answer`: the hard side opens K auxiliary sockets, each
probing the easy side's reflexive address (its NAT picks each one's
port); the easy side sends at most N tagged probes, at most Rate per
tick, to the hard side's offered address at guessed ports. A guess that
is one of those ports passes the hard NAT; that socket answers tagged,
the easy side learns the address (as `DirectPunch.tla`'s `Learn`) and
dials it; the connection runs on that socket. Prior art: Tailscale "How
NAT traversal works" (256 sockets, 1024 probes, ~98 %).

Checked: `SprayOnlyEasyHard`, `SprayBound`, `SprayOnlyPeer`,
`OneConnection`, `AuxClosed` (at the return only the won socket is open),
`DirectIfHit` (relayed only when no guess was answered); `Ends`,
`HitGoesDirect`. `make spec` checks `Birthday.cfg` (three ports, two
sockets, three guesses, two per tick, two ticks; every guess may be
lost). Mutants: `no-cap`, `no-pace`, `any-target`, `keep-aux`,
`return-early`, `keep-all`, `no-dial`, `spray-hard-hard`, `spray-first`.
Witnesses (each violated): `W_Hit`, `W_Miss` (every guess spent, none
hit), `W_LostHit` (a guess at a right port lost), `W_OthersClosed`.

### Environment assumptions

| assumption | source |
|---|---|
| An endpoint-dependent NAT gives each socket's flow toward one address its own port, which the far side cannot know; that flow's port passes only packets from that address | RFC 4787 sections 4.1 and 5 |
| An endpoint-independent NAT keeps one external address for a socket toward every destination | RFC 4787 section 4.1 |
| A probe may be lost (no fairness on `Spray`'s delivery) | UDP |
| Only the two ends of a control exchange can compute its probe tag | RFC 8446 section 7.5 |

### Code map (Birthday.tla)

The code is the next lane; its files join this table with it.

## AgentStop.tla: an agent's stop, its drain and its grace

Lane STOPSPEC, after lanes SENDCUT (a killed receiver's direct session held
a `--once` nfltr-send for a 5 s drain and three 5 s graces) and SENDBEST (a
second `Listener.Close` returned while the first was still resetting). The
state lives in the SDK: `directServer.stop` and `directSession.reset`
(client/agent/direct_server.go), the target's reset reaching its direct
session (`setDirect`, `QueueConn.cut`), the agent's stop sequence
(connect.go: waitIdle, the primary's and the cycle's end's stops, endTCP),
`ServiceTable.Close` and nfnet's `Listener.Close`.

Model: sessions relayed or direct (`Direct`); a target writes, closes
cleanly or resets; a peer delivers, ends at the clean close, answers an
ABORT, resets, or vanishes (killed) and then answers nothing: the relay
cuts a relayed one, only the agent's grace or the detach bound a direct
one. The stop is a signal or `Listener.Close` (its accepted Conns reset,
the agent stopped, the table's stop; a second Close waits for the first).
The agent: relayed sessions until they end or `Drain` passes, then the
primary's `directServer.stop`, then the cycle's end's (at once when there
is no drain: both together), then the relayed sessions left are reset. A
`directServer.stop` call: the first drains (until each direct session
ended or was reset, or the drain passed), each resets the sessions left
(one ABORT per session) and waits until each ended or `Grace` passed since
its first reset. Time is a tick; the agent's own steps are urgent, the
peers' and targets' are not; the clock starts at the stop. `make spec`
checks `AgentStop.cfg` (one direct and one relayed session, two Closes,
Drain 1, Grace 2, one byte each; about 0.8 M states),
`AgentStopNoDrain.cfg` (Drain 0) and `AgentStopLate.cfg` (lane STOPGAP:
one session of `Late`, which registers at any time the agent's link still
carries new sessions, the stop's included, and may move to its direct
path; one Close; about 25 k states). Each call resets and waits for the
sessions registered at its reset (`snap`, the code's `left`); the link's
end resets a late session not moved; one registered once a drain ended is
refused (reset at once, not tabled). `AgentStopClose.cfg` (lane
DIRECTCLOSE, PIPEMATRIX defect 1: `AgentStop.cfg` with one Close; about
1.3 M states) also models the target's Close to its return
(`CloseWaits`): it waits until the peer took every byte (its end among
them: TLS close_notify) and returns clean then, or returns an error once
the session failed or ended first (`CloseReturn`); the other configs
leave it out (`CloseWaits = FALSE`: no states added). The model's
relayed sessions always waited too, while the code's returned at once
(lane RELAYCLOSE closed the gap: for a relayed session `dlv = wrote`
means the far end took every byte and the END, the relay passing its
ENDACK on, link `spec/RelayedClose.tla`; relay-core
`TestRelayedCloseThenExitDeliversTheTail` read a cut tail before, and
pipe `TestRelayedEndDropAfterLastByte` exited 0 with the client short).

| invariant / property | statement | mutant (`scripts/spec.sh mutants`) |
|---|---|---|
| `NoSilentLoss` | a peer sees a clean end only after every committed byte and the target's clean close | `reset-as-close` |
| `NoEarlyReset` | the stop resets a session its target did not only once the drain passed | `no-drain` |
| `ResetEndsInGrace` | a session its target reset ends or is cut within one grace of that reset | `no-target-cut` (SENDCUT) |
| `StopInTime` | the stop ends (the process exits) within the drain and one grace | `grace-per-stop` (SENDCUT, 867a20e) |
| `ExitAfterEnd` | the process exits only once every session ended or its grace passed since its ABORT | `second-close-returns` (SENDBEST, f09ea5f), `no-grace` |
| `NoDrainOnReset` (action) | no time passes in a drain once every direct session ended or its target reset it | `no-target-cut`, `drain-waits-reset` (SENDCUT, 04e84d8) |
| `CloseTruth` (`AgentStopClose.cfg`) | a target's Close returns clean only once its peer took every byte and the END: a program that exits 0 then lost nothing to the stop's later reset | `close-returns-early` (DIRECTCLOSE: an accepted QueueConn's Close returned at once; nfltr-pipe listen exited 0, the stop's 5 s drain then reset the tail: the dialler read a short stream and exited 6) |
| `ExitAfterEnd`, `StopInTime` (`AgentStopLate.cfg`) | a session registered once a drain ended does not outlive the exit nor stretch the stop | `late-unreset` (STOPGAP: it moves direct after the last call's `left`, exit; with a session there at the stop, `late-unreset-grace`: a later call waits a fresh grace) |

Witnesses (each violated: the model reaches it): `W_GoneCut` (exit after a
killed direct peer's grace), `W_FullBound` (the stop takes the whole
bound), `W_StopReset`, `W_Eof` (every byte and the clean end after the
stop began), `W_ResetCut`, `W_DrainWaits`, `W_SecondClose`; on
`AgentStopLate.cfg` `W_LateMoved` (a late session moved direct and reset
before the exit) and `W_LateRefused` (one refused, then the exit); on
`AgentStopClose.cfg` `W_CloseClean` and `W_CloseErr` (a Close returns
clean; one returns an error). `Propagate`
is the `no-target-cut` mutant's step only (never taken in the design);
every other action is taken (`COVERAGE=1`; `Register` and `Move` on
`AgentStopLate.cfg`). `NoEarlyReset` does not cover a session registered
after the stop began (`newer`): the stop takes no new work, so it gets no
drain of its own. The model's drain waits for every registered session;
the code's for those registered at its start (a later one is reset at
the drain's end): an over-approximation that only lengthens the drain.

Prior art: the drain is a graceful shutdown's (Go `http.Server.Shutdown`:
stop taking new work, let the open work end within a bound, then close);
the grace after an ABORT is a closing endpoint lingering so its last
control frame is delivered (RFC 9000 10.2, the closing and draining
periods; TCP's `SO_LINGER`); a second close waiting for the first is
`sync.Once` semantics for a close that blocks.

### Environment assumptions

| assumption | source |
|---|---|
| The relay resets a relayed session's peer when the agent resets it or the agent's link ends, and cuts a relayed session whose peer's connection ended (`RelayCut`, no bound assumed); a relayed session's END is acknowledged (the relayed `CloseReturn`) only once the far end took it: the relay's joint passes the far end's ENDACK on (link FeatureEndAck, a hop's `Config.Hop`); once the relay read the tail and END it delivers them whatever the agent does next (a FIN then a failure reads io.EOF; lane RELAYCLOSE) | relay-core `core/session` (spec relay-core `spec/`), `link` GOAWAY/reset semantics (link `WIRE.md`), link `spec/RelayedClose.tla` (`TailDelivered`) |
| A pathswitch ABORT reaches a live peer, which answers it; a killed peer answers nothing, and the session ends at its detach bound (`DetachEnd`) | link `pathswitch`, link `spec/DirectPath.tla` (`RLeftAnswer`, `SLeftAnswer`) |
| The link's end resets a pathswitch session still on its relayed path at the peer, which ends it (`CycleEnd`'s `LinkEnds`); a session moves to a direct path only while not aborted (an aborted Conn takes no path) | relay-core `core/session`; link `pathswitch` (Abort ends the Conn) |
| A peer may be arbitrarily slow (no fairness on peer steps): a slow peer is a vanished one until it answers | QUIC/TCP give no delivery-time bound |
| Closing a QUIC connection at once drops the ABORTs queued on it (the reason for the grace) | RFC 9000 10.2 |
| A direct session's `WaitAcked` is true only once the peer holds every byte, and the peer's Read keeps what it took through a later reset (`CloseReturn`'s clean case is `dlv = wrote`); an ABORT or the session's end fails it, silence within `Linger`. The acked end waits for the END too (`Written()+1`), which pathswitch acknowledges only once the peer's program read it (lane ENDACK, `TestAckedEndWaitsForTheEnd`): stronger than `dlv = wrote`, which still holds | link `pathswitch` (`spec/DirectPath.tla` `TakenRead`, `CloseBounded`, `EndTruth`; `Conn.WaitAcked`) |
| Timers fire at their deadline (Drain, Grace are ticks); the scheduler runs the agent's own steps before time passes | Go `time.Timer`; tests measure the bound (`TestDirectStopsWaitOneGrace`) |

### Code map (AgentStop.tla)

| actions | code |
|---|---|
| `CallDrainEnd`, `CallReset`, `CallWaitEnd`, `Cut`, `Abort`, `Register`, `Move` (acceptDirect's Attach) | client/agent/direct_server.go |
| `TargetReset` (a direct session's), `Propagate` | client/agent/datagram_target.go |
| `TargetReset` (the cut at either end's Reset) | client/agent/queue.go |
| `CloseWrite`, `CloseReturn` (Accept's conn's Close waits for `joinTarget`'s report: a direct path's WaitAcked; relayed, Join's CloseWriteSync onto the agent-link session or TLS on it, which returns at the far end's ENDACK (link FeatureEndAck), `QueueConn.EndDelivered`; lane RELAYCLOSE) | client/agent/queue_close.go, client/agent/queue.go |
| `Signal`, `PrimaryStart`, `CycleStart`, `CycleEnd` | client/agent/connect.go |
| `PrimaryStart` (waitIdle), `Drain` | client/agent/move.go |
| `CloserAwait` (the table's stop) | client/agent/services.go |
| `Close`, `CloserReset`, `CloserAgent`, `CloserTable`, `CloserWait`, `Exit` | client/nfnet/listen.go |

| trace recorder | client/agent/trace_stop_on.go |

### AgentStop traces

`make spec-traces` (nightly): client/agent's stop tests
(`TestDirectStopsWaitOneGrace`, `TestDirectTargetResetResetsTheSession`,
`TestDirectStopRefusesLateSessions`, `TestDirectStopDrainsThenResets`,
`TestStopResetsDirectSessionsBeforeClose`)
in one process built `-tags relaytrace`, and the fixtures; `make
spec-stoptraces` (in make ci, about 15 s) the first three (SENDCUT's, STOPGAP's); every directServer writes
`agentstop-<pid>-<n>.ndjson` (Register, TargetReset, Abort, Done, Cut,
StopBegin with whether it drains, DrainEnd with by over or deadline,
StopReset, StopEnd), checked by `spec/TraceAgentStop.tla` (a Register is AgentStop's, every
session `Late`, with whether the code refused it, which must be the
model's: refused once a drain ended, read under the recorder's lock; a StopEnd needs the Cut of every session its StopReset took,
logged under the table's lock with the snapshot): which call is
which is TLC's choice, Drain 0 (the calls may overlap), and the clock is
free (no urgency), so a trace checks the steps' order (a drain ends over
only when every session ended or was reset; a reset only after the drain;
a call drains only before any drain ended; a call ends only after every
session's cut; an ABORT only after a reset) and the timing properties
stay the tests'. Thirteen traces on the Mac 2026-11-19 (ten from the
no-drain agent, its two calls overlapping), all accepted. Rejected
fixtures, one per check: `reject-agentstop-end-before-cut`,
`-reset-before-drain`, `-second-drain`, `-over-live`, `-abort-unasked`,
`-late-tabled` (a session registered after a drain ended, not refused:
`late-unreset`), `-unknown-step` (a logged step that maps to no action).

### Findings (lane STOPSPEC, 2026-11-19)

No new bug: the design holds every invariant, and the three past bugs
(SENDCUT's target reset and drain, SENDCUT's grace per call, SENDBEST's
second Close) are mutants it catches. Open (not modelled): a session
registered after a stop call's snapshot of the sessions (`left`) is not
reset by that call; a new session starts relayed and rides the agent's
link, so the relay resets it at the exit, unless it moved to a direct
path in that window. The model's sessions all exist at the stop.

### Findings (lane STOPGAP, 2026-11-19)

The open item above is a bug, now fixed. `AgentStopLate.cfg` with the
code as it was (`late-unreset`) violates `ExitAfterEnd`: a session
registers after the last call took `left` (the cycle's end's, under a
signal: a framed session whose TLS handshake ended in that window),
moves to its direct path before the link ends, and the process exits with no ABORT sent: the peer waits
out the detach bound (30 s), UDPFIX's symptom. Beside a session there at
the stop it also violates `StopInTime`: a later call takes it and waits
a fresh grace past the drain and one grace. Fix: `registerSession`
refuses a session once a drain ended (`stopped`, read under the table's
lock; `stop` takes `left` under it): reset at once, not tabled
(`TestDirectStopRefusesLateSessions`, failing first).

## TLSEnd.tla: a session's end under end-to-end TLS

`client/tlsend` runs TLS on a link session (nf1 and organisation
sessions, relayed). A peer X ends its stream with the close_notify, then
the transport's FIN (`Conn.CloseWriteSync`), and waits for the far end's
ENDACK (link FeatureEndAck). The reader Y's reads end at the close_notify:
crypto/tls reads nothing past it. Y's whole close (`Conn.Close`) then
raced the FIN still in flight, and since link ENDACKTRUTH a whole close
before the end was acknowledged ends X's wait with a reset: nfltr-pipe's
relayed ends exited 6 after a clean two-sided end (lane PIPERESET, pipe
`TestSecondDialIsReset/relayed`). Design: `Close` after the peer's
close_notify first reads the transport to its end (the FIN, which Y's
Mux acknowledges before any close), within `EndBound` (5 s, crypto/tls's
own close_notify bound) when X ended only its TLS stream and keeps the
transport (a plain crypto/tls peer's `CloseWrite`).

The end read (lane ENDACK, link `spec/README.md` "The end read by the
far program"): link now acknowledges an end once the far program read it
(EOF), not at receipt, so a clean `CloseWriteSync` says Y's program took
the stream. Y's program reads only to the close_notify, so Y's `Read`, at
the close_notify's EOF on a transport that acknowledges ends, starts
reading the transport to its FIN in the background (`YTake`, within
`EndBound`; `Close` waits for it): link's FIN is read, so acknowledged,
once Y's program read the close_notify. Without it each end's
`CloseWriteSync` waited for the other's Close (mutant `stop-at-notify`:
both wait for the ack, every clean relayed nf1 session stalled the 30 s
idle bound, PIPERACE's prototype). In the background, a peer that sends
its FIN only after Y's Close (nfnet `TestNF1CloseTakesThePeersEnd`'s
server) costs Y's Read nothing. Y's program failing after the close_notify
(`YFail`, before its take) resets X's wait: never a clean end Y's program
did not take (`AckTruth`).

`TLSEnd.cfg` (`make spec`, 104 states, every action taken with
`COVERAGE=1`); X may keep the transport (`keep`); Y may half close first
(`yw`).

| invariant / property | statement | mutant (`scripts/spec.sh mutants`) |
|---|---|---|
| `NoFalseReset` | nothing fails here: X's end, every byte taken, is never read as a reset | `close-at-notify` (the code before: Close at the close_notify) |
| `XEnds` | X's wait for the ENDACK ends clean | `close-at-notify` |
| `YCloses` | Y's Close returns, also when X keeps the transport | `unbounded` (the FIN awaited with no bound), `stop-at-notify` |
| `AckTruth` | X's end reads clean only once Y took the FIN behind the close_notify (its program read the close_notify) | `ack-on-receipt` (link before lane ENDACK: the FIN acknowledged on Y's Mux's receipt) |
| `YWEnds` | Y's own half close (`CloseWriteSync`) ends | `stop-at-notify` (Y's Read stops at the close_notify: both ends wait for the other's ack) |

Witnesses (violated): `W_Clean` (X's end acknowledged), `W_Bound` (Y
closed by the bound, X keeping the transport), `W_BothClean` (both half
closes clean), `W_FailAfterArrival` (Y's program fails after the
close_notify arrived: X reads a reset). Go mutants:
`client/nfnet/testdata/mutants.txt` `close-before-fin`
(`TestNF1CloseTakesThePeersEnd`), `closewrite-tls-only`
(`TestNF1CloseWriteEndsTheSession`).

### Environment assumptions

| assumption | source |
|---|---|
| A link session is one ordered stream each way; the close_notify record and the FIN written after it arrive in that order | link `WIRE.md` (session frames in order) |
| A far end acknowledges a FIN once its reader took it (Read's EOF), or at a close after every byte read; never at receipt (lane ENDACK; v0.14.0 and earlier at receipt) | link `endack.go` (`readEnd`, `ackAtClose`), link `spec/RelayedClose.tla`, `spec/EndAckLeg.tla` |
| A whole close that reaches the peer before its end's ENDACK ends the peer's `CloseWriteSync` with `ErrReset` | link ENDACKTRUTH (`closeAckErr`), link `spec/RelayedClose.tla` `CClose` |
| The FIN behind a close_notify arrives within `EndBound`: `CloseWrite` writes it right after the close_notify on the same stream; later, Close closes anyway. A direct path's conn (no `CloseWriteSync`) is not waited for: its own Close takes the peer's end in the background | crypto/tls bounds its close_notify write by 5 s (`Conn.closeNotify`); client/agent `psConn.Close` |

### Code map (TLSEnd.tla)

| actions | code |
|---|---|
| `XNotify`, `XFin` (the FIN right behind the close_notify) | client/tlsend/tlsend.go (`CloseWrite`, `CloseWriteSyncReceived`), client/nf1/early.go (an early session's `CloseWrite`, `CloseWriteSyncReceived`, `Reset`: its link session's) |
| `YRecv` (the close_notify's EOF: `notified`), `YTake` (`Conn.takeEnd`, started by `Read`), `YClose`, `YClosed` | client/tlsend/tlsend.go (`Read`, `takeEnd`, `Close`, `rawEnd.readToEnd`) |
| trace recorder | client/tlsend/trace_on.go (`-tags relaytrace`), checked by `TraceTLSEnd.tla` (below) |
| a wrapper over the session passes its end on (`CloseWrite`, `CloseWriteSyncReceived`, `Reset`; no `CloseWriteSync` on a direct path's conn) | client/agent/direct_nf1.go (`detachTap`), client/agent/direct.go (`peekConn`, `pathStream`, `psConn`), client/nf1/early.go |

### TLSEnd traces (lane ENDTRACE)

`client/tlsend` built `-tags relaytrace` with `RELAYTRACE=<dir>` writes
one file per session (named by the TLS exported keying material, the
same at both ends) and direction (the first close_notify's: its sender
is X): X's `Notify` (`XNotify`), `Fin` (`XFin`) and `End` (its
`CloseWriteSync` returned: n 1 nil, `XRecv` to clean; 0, to reset), Y's
`EOF` (its take of the FIN behind the close_notify ended: `YTake`, lane ENDACK), `Close` (`YClose`; n 1: it takes the
transport's end first, the only Close of a Y on a transport that
acknowledges ends, so n 0 is `close-at-notify`'s) and `Closed`
(`YClosed`). TLC adds Y's Mux reading the close_notify and the FIN
(`YRecv`: the ENDACK X's `End` takes may come before Y's app reads the
close_notify, 1 trace in about 60 on the box) and X's reads while it
waits for nothing; `keep` is its choice. A direction whose X is no
tlsend Conn (a plain crypto/tls peer: nfnet's `TestNF1CloseTakesThePeersEnd`
server) or whose Y's transport acknowledges no end (a direct path) is
not recorded: Y's first step drops its file, and X's later steps (its
`End`) record nothing (`TestTraceEndAfterOutOfScopeY`; they wrote to the
closed file and panicked, lane TLSENDTRACE). `TraceTLSEnd.tla` accepts a trace once every line is taken
and Y's Close returned, `NoFalseReset` checked on every state.
`make spec-tetraces` (in `make ci`, and in `spec-traces`): every event the
module maps is one tlsend records, the fixtures, then
`TestEndOverALinkSession` (sync, closewrite, crossing) recorded and each
direction checked. Fixtures (`spec/testdata/`): `accept-tlsend-sync`,
`accept-tlsend-crossing` (recorded), `reject-tlsend-ack-on-receipt`
(was `accept-tlsend-end-before-eof`: `End` before `EOF`, an ENDACK
before Y took the FIN, lane ENDACK), `accept-tlsend-keep` (X keeps its
transport: Y's Close by the bound); `reject-tlsend-close-at-notify`
(recorded with the mutant put back: `Close` n 0),
`reject-tlsend-close-before-fin` (a whole close reached X before the
ENDACK: its reset, the order nfltr-pipe saw), `reject-tlsend-unbounded`
(X keeps its transport and Y's Close never returns),
`reject-tlsend-unknown-step`.

Close's direct-path exemption (lane ENDTRACE): `syncsEnd` keeps Close
from taking the end of a conn that acknowledges none (a direct path's
`psConn`, whose own Close takes the peer's end); waiting `EndBound` there
failed nfltr-pipe's direct dials. Guards `TestCloseOnADirectPathTakesNoEnd`
(Go mutant `direct-takes-end`, `client/tlsend/testdata/mutants.txt`) and
`TestSessionWrappersPassTheEndOn` (`psConn` has no `CloseWriteSync`).

## AuditLog.tla: a machine's session audit log, its lost closes and its rotation

The serving agent appends each organisation session's `open` and `close`
lines to the machine's audit log (`client/orgaudit` `Log`, `sessions.jsonl`,
written by `org/orgmachine` and `client/orgid`'s Identity; nfltr
`docs/decisions/service-access-2026-11-25.md` "SA5"). Lane SA5GAPS closes
two of its gaps. (c) A killed process left an `open` with no `close`: each
process now holds an owner file (`sessions.owners/<id>`, its lock
`<id>.lock` held for the process's life) listing the sessions it opened,
written before the open line and pruned after the close line; a later
process of the machine (its keeper's round) whose try-lock of an owner
lock succeeds writes, under the log's lock, a `lost` close for each listed
session whose open is in the file and whose close is not, then deletes the
owner file. The log is the truth, the owner file only says whose sessions
they were. (a) The file is rotated: a prefix of lines the issuer
acknowledged is dropped, never the last line (the next line chains to it,
the log goes on) and never an open whose close is not written.
Lane ONEREVOKE: a client the machine refused (its certificate the
organisation issued, refused by the rules, a grant or the CRL) is one
`refused` line under the log's lock (`Refuse`, `Log.Refused`): no session,
so no owner file lists it, nothing closes it, recovery and rotation pass
it, and the issuer's `Silent` counts no refusal open (`ReadAudit`,
`TestAuditRefusalReachesTheIssuer`). At most one a minute per client name
and service (`RefusedEvery`; the rest counted in the next line's
`repeats`).

`AuditLog.cfg` (`make spec`: 3 processes, 2 sessions, 2 rotations, no
refusal, every action but `Refuse` taken with `COVERAGE=1`),
`AuditLogLive.cfg` (one process never killed), `AuditLogRefused.cfg` (2
processes, 2 sessions, 1 rotation, 1 refusal: 34,925 states, 9 s; with a
refusal in `AuditLog.cfg` 1.6M states, 8 times its 194k).

| invariant / property | statement | mutant (`scripts/spec.sh mutants`) |
|---|---|---|
| `AtMostOneClose` | a session has at most one close | `recover-no-log-check` (every listed session closed) |
| `CloseHasOpen` | every close follows its open | `recover-no-log-check` |
| `LiveOpenNotClosed` | a session its live process serves is not recorded closed | `recover-live` (an owner closed without its lock taken) |
| `NothingLost` | rotation drops only lines the issuer holds | `rotate-unacked` |
| `OneLog` | rotation never starts a new log | `rotate-all` (the last line dropped too) |
| `OpenIsAdmitted` | every open line is an admitted session's | `refused-as-open` (AuditLogRefused: a refusal written as a session's open) |
| `EveryOpenCloses` (AuditLogLive) | every open is closed, a killed process's too | `no-recovery` (the code before), `open-before-intent`, `rotate-drops-open` |

Witnesses (violated): `W_LostClose`, `W_CloseThenKilled` (killed between
its close line and its owner file's prune: recovery writes none),
`W_IntentOnly` (killed between the owner file and the open line: nothing
to close), `W_Rotated`, `W_Refused` (AuditLogRefused).

### Environment assumptions

| assumption | source |
|---|---|
| `flock(2)` (`LockFileEx` on Windows) is released when its process ends, also when killed; a lock held by a live process cannot be taken by another (a Log kept reachable: its lock file is closed by the GC with it) | flock(2), LockFileEx docs; `client/orgaudit/files*.go` |
| A line appended and fsynced under the log's lock is in the file after a crash; a torn last line is cut by the next append | `client/orgaudit` `Append` (`lastLine`, `Truncate`) |
| A rename over a file is atomic | rename(2); `client/orgaudit` `writeFile` |
| The issuer's answer acknowledges a prefix of the log (`sessions.sent`) | `org/orgenrol/auditship.go` |

### Code map (AuditLog.tla)

| actions | code |
|---|---|
| `Intent`, `OpenLine`, `CloseLine`, `Forget`, `Start` | client/orgaudit/log.go (`Log.Audit`, `Append`, the owner file), its writers org/orgmachine/audit.go and client/orgid/identity.go (`Audit`) |
| `Refuse` | client/orgaudit/log.go (`Log.Refused`), client/orgid/identity.go and org/orgmachine/audit.go (`AuditRefused`), client/agent/org.go (`orgServerConfig`) |
| `Recover`, `RecoverDone` | client/orgaudit/log.go (`Log.CloseLost`), org/orgenrol/auditship.go (the keeper's round) |
| `Ship`, `Rotate` | org/orgenrol/auditship.go (`shipAudit`, `shipOnce`, `unshipped`), client/orgaudit/log.go (`Rotate`) |
| (traces) | client/orgaudit/trace_on.go, trace_off.go |

## MoveAudit.tla: the session audit across an organisation move

A machine moves its cursor (`sessions.sent`) past the lines an issuer's
answer acknowledges, so those lines exist only at the issuer. They are
issuer state: `nfltr org move send` carries `sessions.jsonl`,
`sessions-heads.json`, `sessions.sink` and `config.json` in the bundle
(`org/orgissuer/bundle.go`), and the issuer takes no audit post after its
fence (the post stays unanswered; the new machine answers it: `decide`'s
`orgissuer.Store.Open` refuses a fenced log with ErrMoved, which held
before; `TestAuditNotTakenAfterTheFence` guards it). Before lane SA5GAPS
the bundle carried none of the files: the new issuer refused every
machine's next lines as a gap (`TestAuditFollowsTheMove`). `spec/orgmove/OrgMove.tla` owns the move; here only what the audit
needs of it.

`MoveAudit.cfg` (`make spec`: 3 hosts, 3 lines, every action taken).

| invariant | statement | mutant |
|---|---|---|
| `AckedHeld` | every line the machine was answered for is held by the serving issuer | `bundle-no-sessions` (the code before), `take-after-fence` |
| `NoGap` | a move makes no serving issuer report a gap | `bundle-no-sessions` |

Witnesses: `W_TakenAfterMove`, `W_AckedBeforeMove`.

### Environment assumptions

| assumption | source |
|---|---|
| The fence and the bundle are written under the issuer directory's lock, which the intake (`decide`) takes too | `orgissuer.Send`, `orgenrol` `service.with` |
| A request the issuer does not answer is read again (by the new issuer after the move) | `orgenrol` `Run` (ErrMoved: unanswered and unacknowledged), `spec/orgmove/OrgMove.tla` |

### Code map (MoveAudit.tla)

| actions | code |
|---|---|
| `Take` | org/orgenrol/audit.go (`takeAudit`), org/orgenrol/issuer.go (`decide`) |
| `Fence`, `Send`, `Import` | org/orgissuer/bundle.go (`bundleMember`, `tombstoneFiles`) |
| (traces) | org/internal/audittrace/on.go, org/orgenrol/audit.go (`take`), client/orgaudit/trace_on.go (`write`) |

### AuditLog and MoveAudit traces (lane SA5TRACE)

`scripts/spec.sh audittraces` (nightly in `make spec-traces`): the audit
tests of client/orgaudit (the kills between steps, the rotation, a
refused client) and
org/orgenrol (the path to the issuer, the move, the fence, an SDK-only
machine), each in its own process with `-tags audittrace`
(`AUDITTRACE=<dir>`; org: `-tags 'enroltrace audittrace'`). A machine
directory's log writes `auditlog-<hash>.ndjson`, each line under the
log's lock (so the file's order is the log's, across processes too),
checked against `TraceAuditLog.tla`: `intent`, `open`, `close`,
`refused`, `forget`, `lost`, `recovered`, `crash` (a test's kill: the owner lock released),
`ship` (Rotate's acknowledged offset, as the seq of its line) and
`rotate`; a process's start is TLC's. Each test process's
`<pid>.moveaudit` (the machine's `write` lines, the issuer's `take` with
its held seq before and after and whether the checker found a gap,
`fence`, `send`, `import`) is checked against `TraceMoveAudit.tla` (the
directories as hosts in the order the trace names them; whether an
answer arrived is TLC's). Not traced: tests that plant what the recorder
never saw (a crafted log, an edited line, a planted owner file).

For the traces the code takes the spec's atomicity: the owner file's
listing and the open line, and the close line and the prune, are each one
hold of the log's lock (`Log.line`), and a recovery deletes the owner file
under it (`closeOwner`). `Ship(n)` and `Take(h, n, answered)` acknowledge
the lines the keeper read, not every line written.

Fixtures (`spec/testdata/`): `accept-auditlog-lost`,
`accept-auditlog-rotate`, `accept-auditlog-refused` (rotated past a
refusal), `accept-moveaudit-follows`;
`reject-auditlog-refused-as-open` (a refusal closed as a session),
`reject-auditlog-recover-live` (LiveOpenNotClosed),
`reject-auditlog-close-twice` (AtMostOneClose, recover-no-log-check),
`reject-auditlog-close-no-open` (CloseHasOpen),
`reject-auditlog-open-before-intent`, `reject-auditlog-rotate-unacked`
(NothingLost), `reject-auditlog-rotate-all` (OneLog),
`reject-auditlog-rotate-drops-open`, `reject-auditlog-unknown-step`;
`reject-moveaudit-bundle-no-sessions` (AckedHeld, the code before),
`reject-moveaudit-take-after-fence`, `reject-moveaudit-gap` (NoGap),
`reject-moveaudit-unknown-step`.
