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
starts); each path a FIFO that may break, losing what it carried, and then
dropped on both sides (`MaxBreak` breaks). Abstracted: the E2E sealing of
each path (`E2E.sealPath`, per path, below the frames), unsequenced frames
(seq 0), `maxAhead` (the model's `N` is below it).

| action | Go |
|---|---|
| `Write` | `SignalConn.WriteFrame` |
| `Join` | `SignalConn.AddPath` (from `AddDirectPath`) on both sides |
| `Recv(p)` | `readPath` and `accept`: deliver, hold ahead, drop a copy |
| `Break(p)` | a path's read or write fails: `dropPath` |

Invariant `NoSilentLoss`: every frame sent and not delivered is held ahead
or on a live path, or no path is left (reads end with `io.EOF`). Property
`AllDelivered`: while a path lives, every frame is delivered (weak
fairness on `Write` and `Recv`). `SignalConn.cfg` (3 frames, 1 break):
223 states, depth 11, every action taken (`-coverage 1`).

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

Mutants (`make spec-mutants`): `P1:no-replay` (`NoSilentLoss`),
`P1:no-replay-stall` (`AllDelivered`), `one-path` (a frame written on one
path only: `NoSilentLoss`).

### Trace validation

`make spec-traces`: with `-tags relaytrace`, a test that calls `traceTest`
records its SignalConns' steps (`client/p2p/trace_on.go`: a write before
its frame goes on the paths, a path joining before its replay, a frame
read from a path, a path's reader ending), one NDJSON line each, in one
process-wide order. `TraceSignalConn.tla` checks each direction that wrote
(writer W, reader R) against `SignalConn.tla`: W's writes, W's direct path
joining, R's reads, and the first end of a path on either side as its
`Break`. Traced tests: `TestSignalConnSwitchLosesNothing` (both ways, about
970 lines each), `TestSignalConnJoiningPathCarriesEarlierFrames`. Rejected
fixtures (`spec/testdata/reject-*.ndjson`): a joining path without the
replay (P1), a read before the write, a read from a path after its break.
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
