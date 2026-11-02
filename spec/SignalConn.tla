------------------------- MODULE SignalConn -------------------------
(* client/p2p SignalConn: one direction of a call's signaling frames over
   the relay stream and, once Connect finds one, the direct TCP channel
   (sigconn.go; spec/README.md maps each action to Go).

   The writer numbers each frame and writes it on every open path; the
   reader delivers each number once, in order, holding a frame that overtook
   an earlier one (ahead) and dropping copies. A path is a FIFO byte stream;
   it may break, losing what it carried, and is then dropped on both sides.
   The direct path joins at most once, at any time (AddDirectPath). Replay =
   TRUE: the fix: a joining path first carries every frame sent before.

   A path may also stall without breaking (the relay grants no credit: the
   peer's reader is blocked, the relay is overloaded, a half-open
   connection): it takes no write and delivers nothing. WriteFrame writes
   the paths one after another under one lock, so a write waits while any
   path it writes is stalled; each path's write is bounded (the direct
   path's tcpWriteTimeout, the relay path's sigWriteTimeout) and a write
   past the bound drops that path (TimeOut). Mutant "unbounded-relay": the
   relay path's write before lane WGFIX2 waited for credit with no bound,
   so a stalled relay stopped the direct path too (review r2 M1). *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    N,         \* frames written
    MaxBreak,  \* path breaks
    MaxStall,  \* path stalls
    Replay,
    Mutant     \* a bug put back (scripts/spec.sh mutants)

Paths == {"relay", "direct"}

VARIABLES sent, open, chan, dead, joined, next, ahead, breaks, stalled, stalls
vars == <<sent, open, chan, dead, joined, next, ahead, breaks, stalled, stalls>>

Live(p) == open[p] /\ ~dead[p]
Flowing(p) == Live(p) /\ ~stalled[p]
Range(s) == {s[i] : i \in 1..Len(s)}

TypeOK ==
    /\ sent \in 0..N /\ next \in 1..N+1 /\ ahead \subseteq 1..N
    /\ open \in [Paths -> BOOLEAN] /\ dead \in [Paths -> BOOLEAN]
    /\ chan \in [Paths -> Seq(1..N)] /\ joined \in BOOLEAN
    /\ stalled \in [Paths -> BOOLEAN]

Init ==
    /\ sent = 0
    /\ open = [p \in Paths |-> p = "relay"]
    /\ chan = [p \in Paths |-> <<>>]
    /\ dead = [p \in Paths |-> FALSE]
    /\ joined = FALSE
    /\ next = 1 /\ ahead = {}
    /\ breaks = 0
    /\ stalled = [p \in Paths |-> FALSE] /\ stalls = 0

\* WriteFrame: the next number on every open path; it waits while one of
\* them is stalled.
Write ==
    /\ sent < N /\ \E p \in Paths : Live(p)
    /\ \A p \in Paths : Live(p) => ~stalled[p]
    /\ sent' = sent + 1
    /\ LET on == IF Mutant = "one-path" THEN {CHOOSE p \in Paths : Live(p)} ELSE {p \in Paths : Live(p)}
       IN chan' = [p \in Paths |-> IF p \notin on THEN chan[p]
                                ELSE IF Mutant = "reorder" /\ p = "direct" THEN <<sent + 1>> \o chan[p]
                                ELSE Append(chan[p], sent + 1)]
    /\ UNCHANGED <<open, dead, joined, next, ahead, breaks, stalled, stalls>>

\* AddPath on both sides (the stream buffers what is written before the
\* reader starts); with Replay, the frames sent so far first.
Join ==
    /\ ~joined
    /\ joined' = TRUE
    /\ open' = [open EXCEPT !["direct"] = TRUE]
    /\ chan' = [chan EXCEPT !["direct"] = IF Replay THEN [i \in 1..sent |-> i] ELSE <<>>]
    /\ UNCHANGED <<sent, dead, next, ahead, breaks, stalled, stalls>>

\* readPath and accept: deliver the next number and what waits behind it,
\* keep an early one, drop a copy.
RECURSIVE Drain(_, _)
Drain(n, a) == IF n \in a THEN Drain(n + 1, a \ {n}) ELSE n
Recv(p) ==
    /\ Flowing(p) /\ chan[p] # <<>>
    /\ LET f == Head(chan[p]) IN
         IF f < next \/ f \in ahead THEN UNCHANGED <<next, ahead>>
         ELSE IF f > next THEN /\ ahead' = ahead \cup {f} /\ UNCHANGED next
         ELSE /\ next' = Drain(next + 1, ahead)
              /\ ahead' = {k \in ahead : k > Drain(next + 1, ahead)}
    /\ chan' = [chan EXCEPT ![p] = Tail(@)]
    /\ UNCHANGED <<sent, open, dead, joined, breaks, stalled, stalls>>

\* A path breaks (the relay restarts, the TCP connection resets): what it
\* carried is lost; both sides drop it (dropPath).
Break(p) ==
    /\ Live(p) /\ breaks < MaxBreak
    /\ dead' = [dead EXCEPT ![p] = TRUE]
    /\ chan' = [chan EXCEPT ![p] = <<>>]
    /\ breaks' = breaks + 1
    /\ UNCHANGED <<sent, open, joined, next, ahead, stalled, stalls>>

\* A path stops taking writes and delivering, without breaking.
Stall(p) ==
    /\ Flowing(p) /\ stalls < MaxStall
    /\ stalled' = [stalled EXCEPT ![p] = TRUE]
    /\ stalls' = stalls + 1
    /\ UNCHANGED <<sent, open, chan, dead, joined, next, ahead, breaks>>

\* A write waiting on a stalled path passes its bound: the writer closes
\* the path (its reader ends and drops it on both sides).
TimeOut(p) ==
    /\ Live(p) /\ stalled[p] /\ sent < N
    /\ ~(Mutant = "unbounded-relay" /\ p = "relay")
    /\ dead' = [dead EXCEPT ![p] = TRUE]
    /\ chan' = [chan EXCEPT ![p] = <<>>]
    /\ UNCHANGED <<sent, open, joined, next, ahead, breaks, stalled, stalls>>

Next == Write \/ Join \/ \E p \in Paths : Recv(p) \/ Break(p) \/ Stall(p) \/ TimeOut(p)
Spec == Init /\ [][Next]_vars /\ WF_vars(Write) /\ \A p \in Paths : WF_vars(Recv(p)) /\ WF_vars(TimeOut(p))

\* Every frame sent and not delivered is held ahead or on a live path, or
\* no path is left (the reader ends: EOF). Else the reader waits forever
\* for a frame no path carries, while a live path keeps it open.
NoSilentLoss ==
    (\E p \in Paths : Live(p)) =>
        \A k \in next..sent : k \in ahead \/ \E p \in Paths : Live(p) /\ k \in Range(chan[p])

\* While a path flows, every frame is delivered (a path that stalls once
\* every frame went out holds the reader open: the transport's own end).
AllDelivered == <>[](next = N + 1 \/ ~\E p \in Paths : Flowing(p))

\* The reader is never past the writer; what it holds ahead was sent and
\* is past next.
ReadBound == next <= sent + 1 /\ ahead \subseteq next + 1..sent

\* Each path carries strictly increasing numbers (WriteFrame's writes are
\* serialized under its lock, and AddPath's replay is in order).
PathOrdered == \A p \in Paths : \A i, j \in 1..Len(chan[p]) : i < j => chan[p][i] < chan[p][j]

\* Witnesses (make spec-mutants: each must be violated).
W_Stall == ~\E p \in Paths : stalled[p] /\ sent < N
W_PathOrdered == \A p \in Paths : Len(chan[p]) < 2
W_ReadBound == next = 1
=============================================================================
