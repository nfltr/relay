------------------------- MODULE SignalConn -------------------------
(* client/p2p SignalConn: one direction of a call's signaling frames over
   the relay stream and, once Connect finds one, the direct TCP channel
   (sigconn.go; spec/README.md maps each action to Go).

   The writer numbers each frame and writes it on every open path; the
   reader delivers each number once, in order, holding a frame that overtook
   an earlier one (ahead) and dropping copies. A path is a FIFO byte stream;
   it may break, losing what it carried, and is then dropped on both sides.
   The direct path joins at most once, at any time (AddDirectPath). Replay =
   TRUE: the fix: a joining path first carries every frame sent before. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    N,         \* frames written
    MaxBreak,  \* path breaks
    Replay,
    Mutant     \* a bug put back (scripts/spec.sh mutants)

Paths == {"relay", "direct"}

VARIABLES sent, open, chan, dead, joined, next, ahead, breaks
vars == <<sent, open, chan, dead, joined, next, ahead, breaks>>

Live(p) == open[p] /\ ~dead[p]
Range(s) == {s[i] : i \in 1..Len(s)}

TypeOK ==
    /\ sent \in 0..N /\ next \in 1..N+1 /\ ahead \subseteq 1..N
    /\ open \in [Paths -> BOOLEAN] /\ dead \in [Paths -> BOOLEAN]
    /\ chan \in [Paths -> Seq(1..N)] /\ joined \in BOOLEAN

Init ==
    /\ sent = 0
    /\ open = [p \in Paths |-> p = "relay"]
    /\ chan = [p \in Paths |-> <<>>]
    /\ dead = [p \in Paths |-> FALSE]
    /\ joined = FALSE
    /\ next = 1 /\ ahead = {}
    /\ breaks = 0

\* WriteFrame: the next number on every open path.
Write ==
    /\ sent < N /\ \E p \in Paths : Live(p)
    /\ sent' = sent + 1
    /\ LET on == IF Mutant = "one-path" THEN {CHOOSE p \in Paths : Live(p)} ELSE {p \in Paths : Live(p)}
       IN chan' = [p \in Paths |-> IF p \in on THEN Append(chan[p], sent + 1) ELSE chan[p]]
    /\ UNCHANGED <<open, dead, joined, next, ahead, breaks>>

\* AddPath on both sides (the stream buffers what is written before the
\* reader starts); with Replay, the frames sent so far first.
Join ==
    /\ ~joined
    /\ joined' = TRUE
    /\ open' = [open EXCEPT !["direct"] = TRUE]
    /\ chan' = [chan EXCEPT !["direct"] = IF Replay THEN [i \in 1..sent |-> i] ELSE <<>>]
    /\ UNCHANGED <<sent, dead, next, ahead, breaks>>

\* readPath and accept: deliver the next number and what waits behind it,
\* keep an early one, drop a copy.
RECURSIVE Drain(_, _)
Drain(n, a) == IF n \in a THEN Drain(n + 1, a \ {n}) ELSE n
Recv(p) ==
    /\ Live(p) /\ chan[p] # <<>>
    /\ LET f == Head(chan[p]) IN
         IF f < next \/ f \in ahead THEN UNCHANGED <<next, ahead>>
         ELSE IF f > next THEN /\ ahead' = ahead \cup {f} /\ UNCHANGED next
         ELSE /\ next' = Drain(next + 1, ahead)
              /\ ahead' = {k \in ahead : k > Drain(next + 1, ahead)}
    /\ chan' = [chan EXCEPT ![p] = Tail(@)]
    /\ UNCHANGED <<sent, open, dead, joined, breaks>>

\* A path breaks (the relay restarts, the TCP connection resets): what it
\* carried is lost; both sides drop it (dropPath).
Break(p) ==
    /\ Live(p) /\ breaks < MaxBreak
    /\ dead' = [dead EXCEPT ![p] = TRUE]
    /\ chan' = [chan EXCEPT ![p] = <<>>]
    /\ breaks' = breaks + 1
    /\ UNCHANGED <<sent, open, joined, next, ahead>>

Next == Write \/ Join \/ \E p \in Paths : Recv(p) \/ Break(p)
Spec == Init /\ [][Next]_vars /\ WF_vars(Write) /\ \A p \in Paths : WF_vars(Recv(p))

\* Every frame sent and not delivered is held ahead or on a live path, or
\* no path is left (the reader ends: EOF). Else the reader waits forever
\* for a frame no path carries, while a live path keeps it open.
NoSilentLoss ==
    (\E p \in Paths : Live(p)) =>
        \A k \in next..sent : k \in ahead \/ \E p \in Paths : Live(p) /\ k \in Range(chan[p])

\* While a path lives, every frame is delivered.
AllDelivered == <>[](next = N + 1 \/ ~\E p \in Paths : Live(p))
=============================================================================
