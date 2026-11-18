# Performance

Optimizations that landed in this repository, newest first. Each entry says
what changed, why it was slow, the evidence and the guard test that keeps
the gain. Read an entry before undoing what it describes.

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
