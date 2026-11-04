----------------------- MODULE CallCreditBoth -----------------------
(* CallCredit.tla with both directions of each call credited at once, on
   the connections they share (spec/README.md "CallCreditBoth.tla"): the
   caller's connection to the relay carries its requests, its request EOM
   and its window updates for responses; the handler's carries its
   responses and its window updates for requests; the relay's connection to
   each agent carries what the other sent. So one agent's receive loop
   serves one direction's frames and the other direction's window updates
   from one FIFO, and an agent's Recv that sends a window update waits for
   room on its connection behind that agent's own data (Agent.sendFrame
   waits until the frame is written). CallCredit.tla checks one direction
   on connections of its own; this checks that the two directions do not
   hold each other: symmetry checked, not assumed.

   Mutants (scripts/spec.sh mutants): "no-credit-req", "no-credit-resp"
   (that direction uncredited, its receive loop waiting on a full buffer:
   the code before lane CALLCREDIT, one direction at a time);
   "drop-after-eom" (the relay drops the caller's window updates after its
   request EOM: the relay before lane CALLCREDIT). *)
EXTENDS Naturals, Sequences

CONSTANTS
    Calls,
    StuckReq,  \* calls whose handler never reads their requests
    StuckResp, \* calls whose caller never reads their responses
    WReq,    \* RequestWindow: a handler's buffer per call, in frames
    WResp,   \* ResponseWindow: a caller's
    N,       \* frames each call sends each way
    P,       \* the relay's pipe per call and direction
    Q,       \* a connection FIFO's capacity
    Mutant

Dirs == {"req", "resp"}
Agents == {"caller", "handler"}
Sender(d) == IF d = "req" THEN "caller" ELSE "handler"
Receiver(d) == IF d = "req" THEN "handler" ELSE "caller"
W(d) == IF d = "req" THEN WReq ELSE WResp
T(d) == IF W(d) \div 4 > 1 THEN W(d) \div 4 ELSE 1
Stuck == ({"req"} \X StuckReq) \cup ({"resp"} \X StuckResp)
Ends == {c \in Calls : \E d \in Dirs : <<d, c>> \in Stuck}  \* calls that end early

ASSUME StuckReq \cup StuckResp \subseteq Calls /\ WReq >= 1 /\ WResp >= 1 /\ N >= 1 /\ P >= 1 /\ Q >= 1

Uncredited(d) == Mutant = "no-credit-" \o d

VARIABLES cr, sent, pipe, gch, buf, got, cons, up, down, closed, eom, gone, late
vars == <<cr, sent, pipe, gch, buf, got, cons, up, down, closed, eom, gone, late>>

\* The entries of FIFO s of kind k, direction d and call c (data: 1 each;
\* a window update: its count when cnt).
OfK(s, k, d, c, cnt) == LET f[i \in 0..Len(s)] ==
        IF i = 0 THEN 0
        ELSE IF s[i].k = k /\ s[i].d = d /\ s[i].c = c
             THEN f[i-1] + (IF cnt THEN s[i].n ELSE 1) ELSE f[i-1]
    IN f[Len(s)]
DataOn(s, d, c) == OfK(s, "data", d, c, FALSE)
Sum(s) == LET f[i \in 0..Len(s)] == IF i = 0 THEN 0 ELSE f[i-1] + s[i] IN f[Len(s)]

Room(d, c) == Len(buf[d][c]) < W(d)

TypeOK ==
    /\ \A d \in Dirs, c \in Calls :
        cr[d][c] \in 0..W(d) /\ sent[d][c] \in 0..N /\ got[d][c] \in 0..N /\ cons[d][c] \in 0..W(d)
    /\ eom \in [Calls -> BOOLEAN] /\ closed \in [Calls -> BOOLEAN]
    /\ gone \in [Calls -> BOOLEAN] /\ late \in BOOLEAN

Init ==
    /\ cr = [d \in Dirs |-> [c \in Calls |-> W(d)]]
    /\ sent = [d \in Dirs |-> [c \in Calls |-> 0]]
    /\ got = [d \in Dirs |-> [c \in Calls |-> 0]]
    /\ cons = [d \in Dirs |-> [c \in Calls |-> 0]]
    /\ pipe = [d \in Dirs |-> [c \in Calls |-> <<>>]]
    /\ gch = [d \in Dirs |-> [c \in Calls |-> <<>>]]
    /\ buf = [d \in Dirs |-> [c \in Calls |-> <<>>]]
    /\ up = [a \in Agents |-> <<>>] /\ down = [a \in Agents |-> <<>>]
    /\ closed = [c \in Calls |-> FALSE] /\ eom = [c \in Calls |-> FALSE]
    /\ gone = [c \in Calls |-> FALSE] /\ late = FALSE

\* clientStream.sendMsg / serverStream.Send: Credit.Acquire, sendFrame.
Send(d, c) ==
    LET a == Sender(d) IN
    /\ ~gone[c] /\ sent[d][c] < N /\ Len(up[a]) < Q
    /\ d = "req" => ~closed[c]
    /\ Uncredited(d) \/ cr[d][c] > 0
    /\ cr' = IF Uncredited(d) THEN cr ELSE [cr EXCEPT ![d][c] = @ - 1]
    /\ sent' = [sent EXCEPT ![d][c] = @ + 1]
    /\ up' = [up EXCEPT ![a] = Append(@, [k |-> "data", d |-> d, c |-> c, n |-> sent[d][c] + 1])]
    /\ UNCHANGED <<pipe, gch, buf, got, cons, down, closed, eom, gone, late>>

\* clientStream.CloseSend, after the call's requests: the request EOM.
CloseSend(c) ==
    /\ ~closed[c] /\ sent["req"][c] = N /\ Len(up["caller"]) < Q
    /\ closed' = [closed EXCEPT ![c] = TRUE]
    /\ up' = [up EXCEPT !["caller"] = Append(@, [k |-> "eom", d |-> "req", c |-> c, n |-> 0])]
    /\ UNCHANGED <<cr, sent, pipe, gch, buf, got, cons, down, eom, gone, late>>

\* The relay's receive loop of agent a's stream: data to its call's pipe
\* (it waits while that pipe is full), a window update to its call's
\* window channel (never waits), the request EOM ends the call's requests.
RelayIn(a) ==
    /\ up[a] # <<>>
    /\ LET m == Head(up[a]) IN
       CASE m.k = "data" ->
              /\ Len(pipe[m.d][m.c]) < P
              /\ pipe' = [pipe EXCEPT ![m.d][m.c] = Append(@, m.n)]
              /\ UNCHANGED <<gch, eom, late>>
         [] m.k = "grant" ->
              IF Mutant = "drop-after-eom" /\ m.d = "resp" /\ eom[m.c]
              THEN UNCHANGED <<pipe, gch, eom, late>>
              ELSE /\ gch' = [gch EXCEPT ![m.d][m.c] = Append(@, m.n)]
                   /\ late' = (late \/ (m.d = "resp" /\ eom[m.c]))
                   /\ UNCHANGED <<pipe, eom>>
         [] m.k = "eom" ->
              /\ eom' = [eom EXCEPT ![m.c] = TRUE]
              /\ UNCHANGED <<pipe, gch, late>>
    /\ up' = [up EXCEPT ![a] = Tail(@)]
    /\ UNCHANGED <<cr, sent, buf, got, cons, down, closed, gone>>

\* The call's route: its data to the receiver, its window updates to the sender.
RelayOut(d, c) ==
    LET a == Receiver(d) IN
    /\ pipe[d][c] # <<>> /\ Len(down[a]) < Q
    /\ down' = [down EXCEPT ![a] = Append(@, [k |-> "data", d |-> d, c |-> c, n |-> Head(pipe[d][c])])]
    /\ pipe' = [pipe EXCEPT ![d][c] = Tail(@)]
    /\ UNCHANGED <<cr, sent, gch, buf, got, cons, up, closed, eom, gone, late>>

RelayGrant(d, c) ==
    LET a == Sender(d) IN
    /\ gch[d][c] # <<>> /\ Len(down[a]) < Q
    /\ down' = [down EXCEPT ![a] = Append(@, [k |-> "grant", d |-> d, c |-> c, n |-> Head(gch[d][c])])]
    /\ gch' = [gch EXCEPT ![d][c] = Tail(@)]
    /\ UNCHANGED <<cr, sent, pipe, buf, got, cons, up, closed, eom, gone, late>>

\* Agent a's recvLoop: a data frame into its call's buffer (pushRequest,
\* pushResponse), a window update into its call's credit (handleWindow).
\* Frames of a call that ended are dropped. Only an uncredited direction
\* can find no room: its loop then waits (handoff.Stall).
Deliver(a) ==
    /\ down[a] # <<>>
    /\ LET m == Head(down[a]) IN
       IF gone[m.c] THEN UNCHANGED <<cr, buf>>
       ELSE IF m.k = "data"
            THEN /\ Room(m.d, m.c)
                 /\ buf' = [buf EXCEPT ![m.d][m.c] = Append(@, m.n)]
                 /\ UNCHANGED cr
            ELSE /\ cr' = [cr EXCEPT ![m.d][m.c] = @ + m.n]
                 /\ UNCHANGED buf
    /\ down' = [down EXCEPT ![a] = Tail(@)]
    /\ UNCHANGED <<sent, pipe, gch, got, cons, up, closed, eom, gone, late>>

\* The app's Recv; Credit.Consumed's window update is sent on the reader's
\* connection before Recv returns (sendFrame waits for room).
Read(d, c) ==
    LET a == Receiver(d)
        grant == cons[d][c] + 1 >= T(d) /\ ~Uncredited(d)
    IN
    /\ <<d, c>> \notin Stuck /\ ~gone[c] /\ buf[d][c] # <<>>
    /\ grant => Len(up[a]) < Q
    /\ buf' = [buf EXCEPT ![d][c] = Tail(@)]
    /\ got' = [got EXCEPT ![d][c] = @ + 1]
    /\ IF grant
       THEN /\ up' = [up EXCEPT ![a] = Append(@, [k |-> "grant", d |-> d, c |-> c, n |-> cons[d][c] + 1])]
            /\ cons' = [cons EXCEPT ![d][c] = 0]
       ELSE /\ cons' = [cons EXCEPT ![d][c] = IF Uncredited(d) THEN 0 ELSE @ + 1]
            /\ UNCHANGED up
    /\ UNCHANGED <<cr, sent, pipe, gch, down, closed, eom, gone, late>>

\* A call with a stuck reader ends (the caller leaves, a cancel): both
\* sides forget its credit, both directions' buffers go.
Cancel(c) ==
    /\ c \in Ends /\ ~gone[c]
    /\ gone' = [gone EXCEPT ![c] = TRUE]
    /\ buf' = [d \in Dirs |-> [buf[d] EXCEPT ![c] = <<>>]]
    /\ UNCHANGED <<cr, sent, pipe, gch, got, cons, up, down, closed, eom, late>>

Next ==
    \/ \E d \in Dirs, c \in Calls : Send(d, c) \/ RelayOut(d, c) \/ RelayGrant(d, c) \/ Read(d, c)
    \/ \E c \in Calls : CloseSend(c) \/ Cancel(c)
    \/ \E a \in Agents : RelayIn(a) \/ Deliver(a)

Fairness ==
    /\ \A d \in Dirs, c \in Calls :
        WF_vars(Send(d, c)) /\ WF_vars(RelayOut(d, c)) /\ WF_vars(RelayGrant(d, c))
    /\ \A d \in Dirs, c \in Calls : <<d, c>> \notin Stuck => WF_vars(Read(d, c))
    /\ \A c \in Calls : WF_vars(CloseSend(c))
    /\ \A a \in Agents : WF_vars(RelayIn(a)) /\ WF_vars(Deliver(a))

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Invariants: CallCredit.tla's, per direction.

NoHOL == \A a \in Agents : down[a] # <<>> =>
    LET m == Head(down[a]) IN gone[m.c] \/ m.k = "grant" \/ Room(m.d, m.c)

BufferBound == \A d \in Dirs, c \in Calls : Len(buf[d][c]) <= W(d) /\ Len(pipe[d][c]) <= P

Conservation == \A d \in Dirs, c \in Calls : ~gone[c] =>
    cr[d][c] + DataOn(up[Sender(d)], d, c) + Len(pipe[d][c]) + DataOn(down[Receiver(d)], d, c)
      + Len(buf[d][c]) + cons[d][c]
      + OfK(up[Receiver(d)], "grant", d, c, TRUE) + Sum(gch[d][c]) + OfK(down[Sender(d)], "grant", d, c, TRUE)
    = W(d)

GrantBound == \A d \in Dirs, c \in Calls :
    OfK(up[Receiver(d)], "grant", d, c, FALSE) + Len(gch[d][c]) + OfK(down[Sender(d)], "grant", d, c, FALSE)
      <= W(d) \div T(d)

\* Each call's frames of each direction arrive in order, once each.
Nums(s, d, c) == LET f[i \in 0..Len(s)] ==
        IF i = 0 THEN <<>>
        ELSE IF s[i].k = "data" /\ s[i].d = d /\ s[i].c = c THEN Append(f[i-1], s[i].n) ELSE f[i-1]
    IN f[Len(s)]
Seq1(a, b) == [k \in 1..(b - a + 1) |-> a + k - 1]
Ordered == \A d \in Dirs, c \in Calls : ~gone[c] =>
    buf[d][c] \o Nums(down[Receiver(d)], d, c) \o pipe[d][c] \o Nums(up[Sender(d)], d, c)
      = Seq1(got[d][c] + 1, sent[d][c])

\* Liveness: every call with no stuck reader gets all its frames both ways.
HealthyReqDone == \A c \in Calls \ Ends : <>(got["req"][c] = N)
HealthyRespDone == \A c \in Calls \ Ends : <>(got["resp"][c] = N)
HealthyDone == HealthyReqDone /\ HealthyRespDone

\* Witnesses (each must be violated: scripts/spec.sh mutants).
\* A healthy call done both ways while the stuck one's buffers are full both ways.
W_BothFullHealthyDone == ~(\E s \in Ends, h \in Calls \ Ends :
    ~gone[s] /\ Len(buf["req"][s]) = WReq /\ Len(buf["resp"][s]) = WResp
    /\ got["req"][h] = N /\ got["resp"][h] = N)
\* A window update behind data on one connection.
W_GrantBehindData == ~(\E a \in Agents : \E i, j \in 1..Len(down[a]) :
    i < j /\ down[a][i].k = "data" /\ down[a][j].k = "grant")
\* A Recv that sends a window update waits for room on its connection.
W_ReadWaits == ~(\E d \in Dirs, c \in Calls :
    <<d, c>> \notin Stuck /\ ~gone[c] /\ buf[d][c] # <<>> /\ cons[d][c] + 1 >= T(d) /\ Len(up[Receiver(d)]) = Q)
W_LateGrant == ~late
=============================================================================
