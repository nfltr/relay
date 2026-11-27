------------------------------ MODULE UDPFlow ------------------------------
(* Raw UDP tunnels (design only, no code yet): the lifecycle of one
   client mapping's flows and the agent's flows of one udp service. The
   design is nfltr's docs/decisions/udp-tunnels-2026-11-08.md; this module
   is its checked state machine (spec/README.md "UDPFlow.tla").

   The client listens on one local UDP socket. Each source address the
   application sends from is a flow: the client opens one link session to
   the agent's udp service for it and carries the source's datagrams on
   that session, each framed with its length; the agent dials one
   connected UDP socket to its target per session and carries the
   target's replies back the same way. The session is the flow: its id is
   the flow's identity on the wire, its end is the flow's end.

   Below this module (assumed, the layers' own specs and tests): link
   sessions are ordered, credited and never reuse an id on a connection
   (link WIRE.md sections 5 and 7: a Mux picks ids as increasing
   uvarints; data for a session the receiver closed is dropped there); a
   session that one side closes reaches the other side's reader after the
   data before it; when a link connection dies (relay restart, a peer
   gone), every session on it ends at both ends, each end learning it on
   its own time (link liveness, relay-core's paired-session reset).
   Abstracted: datagram contents and sizes (each one counts 1 against a
   queue or a window); the relay hop (one FIFO per session and
   direction); real time (idle expiry is enabled once its side has had
   nothing to send: the application quiet, nothing queued to move).

   Mutants (scripts/spec.sh mutants), one per failure the design prevents:
   "no-idle" (no idle timer at either side: AllFlowsEnd),
   "agent-only-close" (the agent ends a flow only on the client's close:
   no idle backstop, the reset ignored: AllFlowsEnd), "deliver-after-close"
   (a side hands on a datagram that reached a flow it already closed:
   NoDeliverAfterClose), "no-client-cap" and "no-agent-cap" (a new source
   or session gets a flow past the table's cap: TableBounded),
   "grow-queue" (a full flow queue takes the datagram instead of dropping
   it: MemoryBound), "block-on-full" (the client's one socket reader waits
   for a full flow's queue instead of dropping: NoHOL). *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Srcs,     \* the application's source addresses at the client's listener
    Ids,      \* session ids the client may open (link never reuses one)
    Busy,     \* the source that sends N datagrams (each other source sends one)
    N,
    MaxFlows, \* the flow table's cap, per side (client mapping, agent service)
    Q,        \* datagrams a flow queues at its sender (per side, per flow)
    W,        \* datagrams of a session in flight or unread (link credit)
    MaxCuts,  \* link connection deaths: relay restart, client gone, agent gone
    Mutant

ASSUME Busy \in Srcs /\ Ids \subseteq Nat /\ N >= 1 /\ MaxFlows >= 1 /\ Q >= 1 /\ W >= 1

None == 0
Sends(s) == IF s = Busy THEN N ELSE 1
Live == {"opening", "open"}
Msg == [k : {"open", "accept", "refuse", "d", "close"}]

VARIABLES
    sent,    \* sent[s]: datagrams source s sent to the listener
    sock,    \* sock[s]: of those, not yet read by the client's reader
    cst,     \* cst[f]: the client's state of flow f: free, opening, open, closed
    csrc,    \* csrc[f]: its source
    cq,      \* cq[f]: datagrams queued at the client for f's session
    ccut,    \* ccut[f]: f's session died under the client (not yet noticed)
    ast,     \* ast[f]: the agent's state of f: free, open, closed
    aq,      \* aq[f]: the target's replies queued at the agent for f
    acut,    \* acut[f]: f's session died under the agent (not yet noticed)
    c2a,     \* c2a[f]: f's session, client to agent
    a2c,     \* a2c[f]: f's session, agent to client
    blocked, \* the flow the client's reader waits on (None: it never does)
    cuts,    \* connection deaths so far
    late,    \* a datagram was handed on by a side that had closed its flow
    got,     \* the application got a reply
    postCut  \* the target got a datagram of a flow opened after a cut

vars == <<sent, sock, cst, csrc, cq, ccut, ast, aq, acut, c2a, a2c,
          blocked, cuts, late, got, postCut>>

TypeOK ==
    /\ sent \in [Srcs -> 0..N] /\ sock \in [Srcs -> 0..N]
    /\ cst \in [Ids -> {"free", "opening", "open", "closed"}]
    /\ csrc \in [Ids -> Srcs \cup {None}]
    /\ cq \in [Ids -> Nat] /\ aq \in [Ids -> Nat]
    /\ ccut \in [Ids -> BOOLEAN] /\ acut \in [Ids -> BOOLEAN]
    /\ ast \in [Ids -> {"free", "open", "closed"}]
    /\ \A f \in Ids : \A i \in 1..Len(c2a[f]) : c2a[f][i] \in Msg
    /\ \A f \in Ids : \A i \in 1..Len(a2c[f]) : a2c[f][i] \in Msg
    /\ blocked \in Ids \cup {None}
    /\ cuts \in 0..MaxCuts
    /\ late \in BOOLEAN /\ got \in BOOLEAN /\ postCut \in BOOLEAN

Init ==
    /\ sent = [s \in Srcs |-> 0] /\ sock = [s \in Srcs |-> 0]
    /\ cst = [f \in Ids |-> "free"] /\ csrc = [f \in Ids |-> None]
    /\ cq = [f \in Ids |-> 0] /\ ccut = [f \in Ids |-> FALSE]
    /\ ast = [f \in Ids |-> "free"] /\ aq = [f \in Ids |-> 0]
    /\ acut = [f \in Ids |-> FALSE]
    /\ c2a = [f \in Ids |-> <<>>] /\ a2c = [f \in Ids |-> <<>>]
    /\ blocked = None /\ cuts = 0
    /\ late = FALSE /\ got = FALSE /\ postCut = FALSE

Data(ch) == Cardinality({i \in 1..Len(ch) : ch[i].k = "d"})
D == [k |-> "d"]
LiveC == {f \in Ids : cst[f] \in Live}
LiveA == {f \in Ids : ast[f] = "open"}
FlowOf(s) == {f \in LiveC : csrc[f] = s}
\* A side sends on a session only while it is alive under it.
SendC(f, m) == IF ccut[f] THEN c2a ELSE [c2a EXCEPT ![f] = Append(@, m)]
SendA(f, m) == IF acut[f] THEN a2c ELSE [a2c EXCEPT ![f] = Append(@, m)]
\* A queue takes a datagram while it has room; else the datagram is dropped.
Enq(n) == IF n < Q \/ Mutant = "grow-queue" THEN n + 1 ELSE n

agentVars == <<ast, aq, acut>>

----------------------------------------------------------------------------
\* The application.

\* It sends a datagram from s to the listener (the kernel buffers it).
AppSend(s) ==
    /\ sent[s] < Sends(s)
    /\ sent' = [sent EXCEPT ![s] = @ + 1]
    /\ sock' = [sock EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<cst, csrc, cq, ccut, c2a, a2c, blocked, cuts, late, got, postCut>>
    /\ UNCHANGED agentVars

----------------------------------------------------------------------------
\* The client: one reader of the listener's socket, a flow table keyed by
\* source, one session per flow.

\* The reader takes s's next datagram (the kernel's arrival order is
\* abstracted: any source's next): onto s's flow's queue, or dropped when
\* that queue is full (it never waits: one stalled flow would hold every
\* source's datagrams); a source with no flow gets a new one, a new session
\* opened, while the table has room; else the datagram is dropped.
\* block-on-full: the reader waits on the full flow (blocked) and reads
\* nothing else until that flow has room or ends.
Read(s) ==
    /\ sock[s] > 0
    /\ IF blocked = None THEN TRUE
       ELSE s = csrc[blocked] /\ (cq[blocked] < Q \/ cst[blocked] \notin Live)
    /\ IF FlowOf(s) # {}
       THEN LET f == CHOOSE g \in FlowOf(s) : TRUE IN
            IF cq[f] >= Q /\ Mutant = "block-on-full"
            THEN /\ blocked' = f
                 /\ UNCHANGED <<sock, cst, csrc, cq, c2a>>
            ELSE /\ sock' = [sock EXCEPT ![s] = @ - 1]
                 /\ cq' = [cq EXCEPT ![f] = Enq(@)]
                 /\ blocked' = None
                 /\ UNCHANGED <<cst, csrc, c2a>>
       ELSE /\ sock' = [sock EXCEPT ![s] = @ - 1]
            /\ IF /\ \E f \in Ids : cst[f] = "free"
                  /\ Cardinality(LiveC) < MaxFlows \/ Mutant = "no-client-cap"
               THEN LET f == CHOOSE g \in Ids : cst[g] = "free" /\ \A h \in Ids : cst[h] = "free" => g <= h IN
                    /\ cst' = [cst EXCEPT ![f] = "opening"]
                    /\ csrc' = [csrc EXCEPT ![f] = s]
                    /\ cq' = [cq EXCEPT ![f] = 1]
                    /\ c2a' = [c2a EXCEPT ![f] = <<[k |-> "open"]>>]
               ELSE UNCHANGED <<cst, csrc, cq, c2a>>
            /\ blocked' = None
    /\ UNCHANGED <<sent, ccut, a2c, cuts, late, got, postCut>> /\ UNCHANGED agentVars

\* An open flow's sender writes its next datagram on the session (link
\* credit: at most W of the session's datagrams in flight or unread).
PumpC(f) ==
    /\ cst[f] = "open" /\ cq[f] > 0 /\ ~ccut[f]
    /\ Data(c2a[f]) < W
    /\ cq' = [cq EXCEPT ![f] = @ - 1]
    /\ c2a' = [c2a EXCEPT ![f] = Append(@, D)]
    /\ UNCHANGED <<sent, sock, cst, csrc, ccut, a2c, blocked, cuts, late, got, postCut>>
    /\ UNCHANGED agentVars

\* The client reads f's session: the open's answer, a reply (written to
\* the flow's source), the agent's close. A reply that reaches a flow the
\* client closed is dropped (link drops it already, the flow drops it too).
RecvC(f) ==
    /\ a2c[f] # <<>>
    /\ LET m == Head(a2c[f]) IN
       /\ a2c' = [a2c EXCEPT ![f] = Tail(@)]
       /\ CASE m.k = "accept" ->
                 /\ cst' = IF cst[f] = "opening" THEN [cst EXCEPT ![f] = "open"] ELSE cst
                 /\ UNCHANGED <<cq, late, got>>
            [] m.k = "refuse" ->
                 /\ cst' = IF cst[f] \in Live THEN [cst EXCEPT ![f] = "closed"] ELSE cst
                 /\ cq' = [cq EXCEPT ![f] = 0]
                 /\ UNCHANGED <<late, got>>
            [] m.k = "d" ->
                 IF cst[f] = "open" \/ (Mutant = "deliver-after-close" /\ cst[f] = "closed")
                 THEN /\ got' = TRUE
                      /\ late' = (late \/ cst[f] # "open")
                      /\ UNCHANGED <<cst, cq>>
                 ELSE UNCHANGED <<cst, cq, late, got>>
            [] m.k = "close" ->
                 /\ cst' = IF cst[f] \in Live THEN [cst EXCEPT ![f] = "closed"] ELSE cst
                 /\ cq' = [cq EXCEPT ![f] = 0]
                 /\ UNCHANGED <<late, got>>
    /\ UNCHANGED <<sent, sock, csrc, ccut, c2a, blocked, cuts, postCut>> /\ UNCHANGED agentVars

\* Idle expiry: the flow's timer fired (its source quiet for the idle
\* bound; an opening flow: the open timeout). The client closes the
\* session; what it queued is dropped.
ExpireC(f) ==
    /\ Mutant # "no-idle"
    /\ cst[f] \in Live /\ sock[csrc[f]] = 0
    /\ cst' = [cst EXCEPT ![f] = "closed"]
    /\ cq' = [cq EXCEPT ![f] = 0]
    /\ c2a' = SendC(f, [k |-> "close"])
    /\ UNCHANGED <<sent, sock, csrc, ccut, a2c, blocked, cuts, late, got, postCut>>
    /\ UNCHANGED agentVars

\* The client learns its session died (the session's error): the flow
\* ends; the source's next datagram opens a new flow.
NoticeC(f) ==
    /\ ccut[f] /\ cst[f] \in Live
    /\ cst' = [cst EXCEPT ![f] = "closed"]
    /\ cq' = [cq EXCEPT ![f] = 0]
    /\ UNCHANGED <<sent, sock, csrc, ccut, c2a, a2c, blocked, cuts, late, got, postCut>>
    /\ UNCHANGED agentVars

----------------------------------------------------------------------------
\* The agent: one flow per session of the service, a connected UDP socket
\* to the target each.

\* The agent reads f's session: the open (a flow while the table has
\* room, else a refusal), a datagram (written to the target, whose reply
\* is queued for the session, or dropped on a full queue), the client's
\* close. A datagram that reaches a flow the agent closed is dropped.
RecvA(f) ==
    /\ c2a[f] # <<>>
    /\ LET m == Head(c2a[f]) IN
       /\ c2a' = [c2a EXCEPT ![f] = Tail(@)]
       /\ CASE m.k = "open" ->
                 /\ IF Cardinality(LiveA) < MaxFlows \/ Mutant = "no-agent-cap"
                    THEN /\ ast' = [ast EXCEPT ![f] = "open"]
                         /\ a2c' = SendA(f, [k |-> "accept"])
                    ELSE /\ ast' = [ast EXCEPT ![f] = "closed"]
                         /\ a2c' = SendA(f, [k |-> "refuse"])
                 /\ UNCHANGED <<aq, late, postCut>>
            [] m.k = "d" ->
                 IF ast[f] = "open" \/ (Mutant = "deliver-after-close" /\ ast[f] = "closed")
                 THEN /\ aq' = IF ast[f] = "open" THEN [aq EXCEPT ![f] = Enq(@)] ELSE aq
                      /\ late' = (late \/ ast[f] # "open")
                      /\ postCut' = (postCut \/ cuts > 0)
                      /\ UNCHANGED <<ast, a2c>>
                 ELSE UNCHANGED <<ast, aq, a2c, late, postCut>>
            [] m.k = "close" ->
                 /\ ast' = IF ast[f] = "open" THEN [ast EXCEPT ![f] = "closed"] ELSE ast
                 /\ aq' = [aq EXCEPT ![f] = 0]
                 /\ UNCHANGED <<a2c, late, postCut>>
    /\ UNCHANGED <<sent, sock, cst, csrc, cq, ccut, acut, blocked, cuts, got>>

\* The agent writes the flow's next reply on the session (link credit).
PumpA(f) ==
    /\ ast[f] = "open" /\ aq[f] > 0 /\ ~acut[f]
    /\ Data(a2c[f]) < W
    /\ aq' = [aq EXCEPT ![f] = @ - 1]
    /\ a2c' = [a2c EXCEPT ![f] = Append(@, D)]
    /\ UNCHANGED <<sent, sock, cst, csrc, cq, ccut, c2a, ast, acut, blocked, cuts, late, got, postCut>>

\* The agent's own idle timer (a backstop to the client's): nothing came
\* from the client for the bound. It closes the session.
ExpireA(f) ==
    /\ Mutant \notin {"no-idle", "agent-only-close"}
    /\ ast[f] = "open" /\ Data(c2a[f]) = 0
    /\ ast' = [ast EXCEPT ![f] = "closed"]
    /\ aq' = [aq EXCEPT ![f] = 0]
    /\ a2c' = SendA(f, [k |-> "close"])
    /\ UNCHANGED <<sent, sock, cst, csrc, cq, ccut, c2a, acut, blocked, cuts, late, got, postCut>>

\* The agent learns its session died: the flow ends, its socket closed.
NoticeA(f) ==
    /\ Mutant # "agent-only-close"
    /\ acut[f] /\ ast[f] = "open"
    /\ ast' = [ast EXCEPT ![f] = "closed"]
    /\ aq' = [aq EXCEPT ![f] = 0]
    /\ UNCHANGED <<sent, sock, cst, csrc, cq, ccut, c2a, a2c, acut, blocked, cuts, late, got, postCut>>

----------------------------------------------------------------------------
\* The environment: a link connection dies. Every session on it ends:
\* what was in flight is lost, and each side still alive learns it on its
\* own time (NoticeC, NoticeA). "relay": the relay restarted (or a drain
\* deadline cut the sessions); "client": the client process died (its
\* flows go with it; the sources' later datagrams are read by its next
\* process); "agent": the agent process died.
Cut(who) ==
    /\ cuts < MaxCuts
    /\ cuts' = cuts + 1
    /\ c2a' = [f \in Ids |-> <<>>] /\ a2c' = [f \in Ids |-> <<>>]
    /\ IF who = "client"
       THEN /\ cst' = [f \in Ids |-> IF cst[f] \in Live THEN "closed" ELSE cst[f]]
            /\ cq' = [f \in Ids |-> 0]
            /\ UNCHANGED ccut
       ELSE /\ ccut' = [f \in Ids |-> ccut[f] \/ cst[f] \in Live]
            /\ UNCHANGED <<cst, cq>>
    /\ IF who = "agent"
       THEN /\ ast' = [f \in Ids |-> IF ast[f] = "open" THEN "closed" ELSE ast[f]]
            /\ aq' = [f \in Ids |-> 0]
            /\ UNCHANGED acut
       ELSE /\ acut' = [f \in Ids |-> acut[f] \/ ast[f] = "open"]
            /\ UNCHANGED <<ast, aq>>
    /\ UNCHANGED <<sent, sock, csrc, blocked, late, got, postCut>>

----------------------------------------------------------------------------

Next ==
    \/ \E s \in Srcs : AppSend(s) \/ Read(s)
    \/ \E f \in Ids : PumpC(f) \/ RecvC(f) \/ ExpireC(f) \/ NoticeC(f)
                      \/ RecvA(f) \/ PumpA(f) \/ ExpireA(f) \/ NoticeA(f)
    \/ \E who \in {"relay", "client", "agent"} : Cut(who)

\* Every step but a cut is fair; a cut may never happen.
Fairness ==
    /\ \A s \in Srcs : WF_vars(AppSend(s)) /\ WF_vars(Read(s))
    /\ \A f \in Ids : /\ WF_vars(PumpC(f)) /\ WF_vars(RecvC(f))
                      /\ WF_vars(ExpireC(f)) /\ WF_vars(NoticeC(f))
                      /\ WF_vars(RecvA(f)) /\ WF_vars(PumpA(f))
                      /\ WF_vars(ExpireA(f)) /\ WF_vars(NoticeA(f))

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Invariants.

\* NoDeliverAfterClose: no datagram is handed on (to the target, to the
\* application) by a side after it closed the flow it came on.
NoDeliverAfterClose == ~late

\* TableBounded: each side's flow table holds at most MaxFlows flows.
TableBounded == Cardinality(LiveC) <= MaxFlows /\ Cardinality(LiveA) <= MaxFlows

\* MemoryBound: per flow, at most Q datagrams queued at each sender and W
\* in flight each way; so per side at most MaxFlows x (Q + W) datagrams.
MemoryBound ==
    \A f \in Ids : cq[f] <= Q /\ aq[f] <= Q /\ Data(c2a[f]) <= W /\ Data(a2c[f]) <= W

\* NoHOL: the client's reader never waits on one flow while another
\* source's datagrams wait to be read.
NoHOL == blocked # None => \A s \in Srcs \ {csrc[blocked]} : sock[s] = 0

\* A closed flow stays closed: link never reuses a session id.
ClosedFinal == [][\A f \in Ids : /\ (cst[f] = "closed" => cst'[f] = "closed")
                                  /\ (ast[f] = "closed" => ast'[f] = "closed")]_vars

\* AllFlowsEnd: every flow ends at both sides.
AllFlowsEnd == \A f \in Ids : /\ ((cst[f] \in Live) ~> (cst[f] = "closed"))
                               /\ ((ast[f] = "open") ~> (ast[f] = "closed"))

\* Witnesses (each must be violated: scripts/spec.sh mutants).
\* The agent refuses an open: its table is full.
W_Refused == ~(\E f \in Ids : \E i \in 1..Len(a2c[f]) : a2c[f][i].k = "refuse")
\* The reader's next datagram of s is dropped: s's flow queue is full.
W_DropFull == ~(\E f \in LiveC : cq[f] = Q /\ sock[csrc[f]] > 0)
\* A reply is on its way to a flow the client already closed.
W_LateReply == ~(\E f \in Ids : cst[f] = "closed" /\ Data(a2c[f]) > 0)
\* A datagram is on its way to a flow the agent already closed.
W_LateDatagram == ~(\E f \in Ids : ast[f] = "closed" /\ Data(c2a[f]) > 0)
\* The client's idle expiry closed a flow the agent still holds.
W_Expired == ~(\E f \in Ids : cst[f] = "closed" /\ ast[f] = "open" /\ ~acut[f])
\* The application got a reply.
W_Reply == ~got
\* A flow opened after a cut carried a datagram to the target.
W_CutRecovered == ~postCut
=============================================================================
