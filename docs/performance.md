# Performance

Optimizations that landed in this repository, newest first. Each entry says
what changed, why it was slow, the evidence and the guard test that keeps
the gain. Read an entry before undoing what it describes.

## A received body chunk is copied once (proto/wire/grpccodec)

**Was.** The codec decoded a message over 1 MiB (an HTTP body chunk:
`chunking.MaxPayload` plus its headers, the relay receiving a response
chunk on ConnectHTTP, the agent a request chunk) by copying grpc-go's
16 KiB frames into one process-wide flattening buffer (a fresh one when
another stream held it) and then `proto.Unmarshal`, which copies the
payload out again into an allocation of its own: two copies of every
relayed byte. The agent-side relay's CPU profile (lane RELAYSPEED2, 1 MiB
bodies, ccx23) had `consumeBytesNoZero` and `BufferSlice.CopyTo` at 1.8 s
of `memmove`, `mallocgcLarge` 0.75 s.

**Now.** `unmarshalAliasingPayload` copies the frames into a buffer the
message owns and decodes it as protobuf merges fields: the message from
its fields except the body, the body from its fields except the payload,
and the payload is the buffer's own bytes (capped). One copy, one
allocation, no shared buffer. The wire bytes are unchanged (decode only).
Smaller messages keep the pooled path: a whole-message buffer would round
a 64 KiB payload's allocation up a page.

**Evidence.** `BenchmarkUnmarshalBodyChunk`, base and after interleaved, 6
rounds each, Apple M5 at load 11 (`~/nfltr-evidence/profiles/2026-11-22-TUNNELCPU/benchstat-codec.txt`):

| chunk | before | after |
|---|---|---|
| response 1 MiB | 233 µs | 157 µs (-33 %, p=0.002) |
| response 1 MiB, parallel | 167 µs | 121 µs (-28 %, p=0.041) |
| request 1 MiB | 268 µs | 187 µs (-30 %, p=0.002) |
| request 1 MiB, parallel | 152 µs | 103 µs (-32 %, p=0.002) |
| response 64 KiB | 22.1 µs | 21.0 µs (~, unchanged path) |

B/op and allocs/op unchanged (20 per response chunk; 1.009 MiB, the
buffer's page rounding, against 1.001-1.020 MiB).

End to end, relay-core's `BenchmarkConnectHTTPResponseChunks` (an agent
streaming 1 MiB chunks on ConnectHTTP over loopback gRPC with the
production transport, both ends in one process, CPU profiles of base and
after): the codec's decode fell from 3.2 % to 1.1 % of the process's CPU
and `memmove` from 3.0 % to 0.8 %; process CPU per MiB 1.46 -> 1.45 ms
(within noise, p=0.70: on macOS the loopback syscalls are 60 % of it).

**Guards.** `TestUnmarshalAliasingPayloadParity` and
`FuzzUnmarshalAliasingPayload` (decodes exactly as `proto.Unmarshal`,
errors included; the payload is the buffer's bytes, capped),
`TestUnmarshalOwnsItsBytes` (a decoded message survives grpc-go reusing
its frames), `TestBodyPayloadFields` (the field numbers parsed by).

## Direct-path sessions keep the 16 MiB data window (client/agent)

**Was.** A session that may go direct wraps its streams in
`pathswitch.Conn`, whose window W (bytes a sender keeps until the peer
acknowledges them) defaulted to 1 MiB, and the direct QUIC node's stream
receive window was link's `DefaultWindow`, 1 MiB. The relay link gives a
session 16 MiB (`tcpDataWindow`). One transfer therefore moved at most
1 MiB per round trip on either path, whatever the path carried.

**Now.** Every `pathswitch.Config` (client, organisation server, nf1
servers) and both direct `quiclink` nodes take `Window: tcpDataWindow`.

**Evidence.** nfltr-send v0.1.2 built with and without the change, the
two alternated on the same machines (2026-11-18; nfltr-send's
`docs/scale.md`, raw results kept with the lane's evidence):

| path | RTT | before | after |
|---|---|---|---|
| 10 GiB, Falkenstein to Helsinki | 36 ms | 191 Mbit/s | 757 Mbit/s (single-stream TCP on the path: 748) |
| 1 GiB, Nuremberg to Ashburn, direct | 95 ms | 72 Mbit/s | 259 Mbit/s |
| 1 GiB, Nuremberg to Ashburn, relayed | 95 ms | 89 Mbit/s | 216 Mbit/s |

**Memory.** Nothing is allocated up front. A pathswitch end's send queue
grows as bytes are in flight, up to W, and keeps its peak capacity while
the session lives; its receive queue holds what arrived and was not read,
at most the sender's W. QUIC buffers only frames not yet read. So a
session costs memory only while it has bytes in flight or unread: at most
about 2 x 16 MiB per end (send queue plus unread bytes), the same bound per
session as the relay link's window. Over all sessions it is 16 MiB times
the sessions that are actually stalled (a quiclink connection admits 1024
sessions; the relay link admits `tcpDataMaxSessions`). The QUIC stream
window is fixed at W rather than auto-tuned (quiclink sets the initial and
the maximum to one `Window`); auto-tuning up to 16 MiB and a send queue
that gives back its peak capacity are link changes (quiclink, pathswitch).

**Guard.** `TestDirectPathWindowIsTheDataWindow` (client/agent): a session
to a target that stops reading takes at least 3/4 of `tcpDataWindow`
before its writes block (1.98 MB before the change). The comment on
`tcpDataWindow` points here.
