------------------------- MODULE SignalConn -------------------------
(* client/p2p SignalConn: one direction of a call's signaling frames over
   the relay stream and, once Connect finds one, the direct TCP channel
   (sigconn.go; spec/README.md maps each action to Go).

   The writer numbers each frame and writes it on every open path; the
   reader delivers each number once, in order, holding a frame that overtook
   an earlier one (ahead) and dropping copies. A path is a FIFO byte stream
   with two ends: the writer's (wOpen) and the reader's (rOpen). Either side
   may drop its end alone (a write error, a tampered or malformed frame, a
   write past its bound); the other side learns it through the transport:
   the writer's close reaches the reader as EOF after what it carried
   (REnd), the reader's close reaches the writer as a failed write (WLearn).
   Mutant "one-sided": the responder's RelayMux.Close sent nothing, so the
   initiator never learned a responder-side drop of the relay path (review r2
   M2). The direct path joins at most once, at any time (AddDirectPath), and
   never once the reader ended (sticky: AddPath refuses; review r2 L1).
   Replay = TRUE: the fix: a joining path first carries every frame sent
   before.

   A path may also stall without breaking (the relay grants no credit: the
   peer's reader is blocked, the relay is overloaded, a half-open
   connection): it takes no write and delivers nothing. WriteFrame writes
   the paths one after another under one lock, so a write waits while any
   path it writes is stalled; each path's write is bounded (the direct
   path's tcpWriteTimeout, the relay path's sigWriteTimeout) and a write
   past the bound drops that path's writer end (TimeOut). Mutant
   "unbounded-relay": the relay path's write before lane WGFIX2 waited for
   credit with no bound, so a stalled relay stopped the direct path too
   (review r2 M1). *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    N,         \* frames written
    MaxBreak,  \* one-sided drops (WDrop, RDrop)
    MaxStall,  \* path stalls
    Replay,
    Mutant     \* a bug put back (scripts/spec.sh mutants)

Paths == {"relay", "direct"}

VARIABLES sent, wOpen, rOpen, chan, joined, ended, next, ahead, breaks, stalled, stalls
vars == <<sent, wOpen, rOpen, chan, joined, ended, next, ahead, breaks, stalled, stalls>>

\* A path open at both ends; one the reader may still read from.
Live(p) == wOpen[p] /\ rOpen[p]
Delivering(p) == rOpen[p] /\ ~stalled[p] /\ (wOpen[p] \/ chan[p] # <<>>)
Range(s) == {s[i] : i \in 1..Len(s)}

TypeOK ==
    /\ sent \in 0..N /\ next \in 1..N+1 /\ ahead \subseteq 1..N
    /\ wOpen \in [Paths -> BOOLEAN] /\ rOpen \in [Paths -> BOOLEAN]
    /\ chan \in [Paths -> Seq(1..N)] /\ joined \in BOOLEAN /\ ended \in BOOLEAN
    /\ stalled \in [Paths -> BOOLEAN]

Init ==
    /\ sent = 0
    /\ wOpen = [p \in Paths |-> p = "relay"]
    /\ rOpen = [p \in Paths |-> p = "relay"]
    /\ chan = [p \in Paths |-> <<>>]
    /\ joined = FALSE /\ ended = FALSE
    /\ next = 1 /\ ahead = {}
    /\ breaks = 0
    /\ stalled = [p \in Paths |-> FALSE] /\ stalls = 0

\* WriteFrame: the next number on every path open at the writer; it waits
\* while one of them is stalled. What goes on a path whose reader dropped
\* it is read by nobody.
Write ==
    /\ sent < N /\ \E p \in Paths : wOpen[p]
    /\ \A p \in Paths : wOpen[p] => ~stalled[p]
    /\ sent' = sent + 1
    /\ LET on == IF Mutant = "one-path" THEN {CHOOSE p \in Paths : wOpen[p]} ELSE {p \in Paths : wOpen[p]}
       IN chan' = [p \in Paths |-> IF p \notin on \/ ~rOpen[p] THEN chan[p]
                                ELSE IF Mutant = "reorder" /\ p = "direct" THEN <<sent + 1>> \o chan[p]
                                ELSE Append(chan[p], sent + 1)]
    /\ UNCHANGED <<wOpen, rOpen, joined, ended, next, ahead, breaks, stalled, stalls>>

\* AddPath on both sides (the stream buffers what is written before the
\* reader starts); with Replay, the frames sent so far first. A reader that
\* ended refuses it (its AddPath closes the path, which the writer's end
\* then reads as an end: as if it never joined). Mutant "revive": it does
\* not (review r2 L1: the spec revived a conn the code had ended).
Join ==
    /\ ~joined /\ (~ended \/ Mutant = "revive")
    /\ joined' = TRUE
    /\ wOpen' = [wOpen EXCEPT !["direct"] = TRUE]
    /\ rOpen' = [rOpen EXCEPT !["direct"] = TRUE]
    /\ chan' = [chan EXCEPT !["direct"] = IF Replay THEN [i \in 1..sent |-> i] ELSE <<>>]
    /\ UNCHANGED <<sent, ended, next, ahead, breaks, stalled, stalls>>

\* readPath and accept: deliver the next number and what waits behind it,
\* keep an early one, drop a copy.
RECURSIVE Drain(_, _)
Drain(n, a) == IF n \in a THEN Drain(n + 1, a \ {n}) ELSE n
Recv(p) ==
    /\ rOpen[p] /\ ~stalled[p] /\ chan[p] # <<>>
    /\ LET f == Head(chan[p]) IN
         IF f < next \/ f \in ahead THEN UNCHANGED <<next, ahead>>
         ELSE IF f > next THEN /\ ahead' = ahead \cup {f} /\ UNCHANGED next
         ELSE /\ next' = Drain(next + 1, ahead)
              /\ ahead' = {k \in ahead : k > Drain(next + 1, ahead)}
    /\ chan' = [chan EXCEPT ![p] = Tail(@)]
    /\ UNCHANGED <<sent, wOpen, rOpen, joined, ended, breaks, stalled, stalls>>

\* The reader's end closes; once it has no path left it has ended (its
\* reads return io.EOF, sticky).
CloseR(p) ==
    /\ rOpen' = [rOpen EXCEPT ![p] = FALSE]
    /\ chan' = [chan EXCEPT ![p] = <<>>]
    /\ ended' = (ended \/ ~\E q \in Paths \ {p} : rOpen[q])

\* The writer drops its end alone (a write error; its own reader of the
\* path, the other direction, saw a tampered frame or the path's end). The
\* close goes after what it wrote (CloseSend, a FIN, the responder's empty
\* message): the reader still reads it.
WDrop(p) ==
    /\ wOpen[p] /\ breaks < MaxBreak
    /\ wOpen' = [wOpen EXCEPT ![p] = FALSE]
    /\ breaks' = breaks + 1
    /\ UNCHANGED <<sent, rOpen, chan, joined, ended, next, ahead, stalled, stalls>>

\* The reader drops its end alone (a tampered or malformed frame, the
\* transport broke): what the path still carried is lost to it.
RDrop(p) ==
    /\ rOpen[p] /\ breaks < MaxBreak
    /\ CloseR(p)
    /\ breaks' = breaks + 1
    /\ UNCHANGED <<sent, wOpen, joined, next, ahead, stalled, stalls>>

\* The reader's end reads the writer's close after everything before it.
REnd(p) ==
    /\ rOpen[p] /\ ~wOpen[p] /\ chan[p] = <<>> /\ ~stalled[p]
    /\ CloseR(p)
    /\ UNCHANGED <<sent, wOpen, joined, next, ahead, breaks, stalled, stalls>>

\* The writer's end learns the reader's close: its writes on the path fail
\* and it drops it (relay: the demux reads the stream's end, the credit
\* window fails; direct: a reset).
WLearn(p) ==
    /\ wOpen[p] /\ ~rOpen[p]
    /\ ~(Mutant = "one-sided" /\ p = "relay")
    /\ wOpen' = [wOpen EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<sent, rOpen, chan, joined, ended, next, ahead, breaks, stalled, stalls>>

\* A path stops taking writes and delivering, without breaking.
Stall(p) ==
    /\ Live(p) /\ ~stalled[p] /\ stalls < MaxStall
    /\ stalled' = [stalled EXCEPT ![p] = TRUE]
    /\ stalls' = stalls + 1
    /\ UNCHANGED <<sent, wOpen, rOpen, chan, joined, ended, next, ahead, breaks>>

\* A write waiting on a stalled path passes its bound: the writer closes
\* its end of the path.
TimeOut(p) ==
    /\ wOpen[p] /\ stalled[p] /\ sent < N
    /\ ~(Mutant = "unbounded-relay" /\ p = "relay")
    /\ wOpen' = [wOpen EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<sent, rOpen, chan, joined, ended, next, ahead, breaks, stalled, stalls>>

Next == Write \/ Join \/ \E p \in Paths :
    Recv(p) \/ WDrop(p) \/ RDrop(p) \/ REnd(p) \/ WLearn(p) \/ Stall(p) \/ TimeOut(p)
Spec == Init /\ [][Next]_vars /\ WF_vars(Write) /\ \A p \in Paths :
    WF_vars(Recv(p)) /\ WF_vars(TimeOut(p)) /\ WF_vars(REnd(p)) /\ WF_vars(WLearn(p))

\* Every frame sent and not delivered is held ahead or on a path the
\* reader reads, while some path is open at both ends. Else the reader
\* waits forever for a frame no path carries, while a live path keeps it
\* open. With no path open at both ends, every path the reader still has
\* ends after what it carries (REnd), and then reads end with io.EOF.
NoSilentLoss ==
    (\E p \in Paths : Live(p)) =>
        \A k \in next..sent : k \in ahead \/ \E p \in Paths : rOpen[p] /\ k \in Range(chan[p])

\* Once the reader ended (io.EOF to the app) it has no path again.
EndedFinal == ended => \A p \in Paths : ~rOpen[p]

\* While the reader can still read a path, every frame is delivered (a path
\* that stalls once every frame went out holds the reader open: the
\* transport's own end).
AllDelivered == <>[](next = N + 1 \/ ~\E p \in Paths : Delivering(p))

\* A side's drop of a path reaches the other side (review r2 M2): the
\* writer stops writing on a path the reader no longer reads, and the
\* reader's end of an unstalled path the writer closed ends.
DropReachesWriter == \A p \in Paths : (wOpen[p] /\ ~rOpen[p]) ~> ~wOpen[p]
DropReachesReader == \A p \in Paths : (rOpen[p] /\ ~wOpen[p] /\ ~stalled[p]) ~> ~rOpen[p]

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
W_NoSilentLoss == ~((\E p \in Paths : Live(p)) /\ \E p \in Paths : ~Live(p) /\ rOpen[p] /\ next <= sent)
W_EndedFinal == ~ended
W_OneSided == \A p \in Paths : wOpen[p] = rOpen[p]
=============================================================================
