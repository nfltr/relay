--------------------------- MODULE DatagramAssoc ---------------------------
(* Datagram sessions between identities (design, no code yet): the
   lifecycle of the flows of one association. The design is nfltr's
   docs/decisions/nf1-udp-2026-11-14.md; this module is its checked state
   machine (spec/README.md "DatagramAssoc.tla"). It refines the flow
   lifecycle of UDPFlow.tla (lane UDPTUN) from one session per flow to
   many flows on one association, and adds what that design left out: a
   second, lossy path (QUIC DATAGRAM frames on the direct connection),
   moving between the paths, revocation, and the amplification bound.

   An association is one end-to-end session (an nf1 session, or an
   organisation session) from a client's datagram listener to an
   identity's datagram service: the same rendezvous, pinned TLS and
   admission as a stream session (cap_address.pv, e2ee_tcp.pv). Inside
   it, flows: a source address at the client's listener is a flow with a
   flow id the client picks (increasing, never reused in an association);
   the agent dials one connected UDP socket per flow. Control (a flow's
   open, the agent's accept or refusal, a flow's close) always rides the
   association's reliable stream. A datagram rides that stream (the
   relayed path, or the stream after pathswitch moved it) or, once the
   association is bound to the direct QUIC connection at both ends, a
   QUIC DATAGRAM frame tagged with the association's tag and the flow id.
   One direct QUIC connection may carry several associations of one
   client process (one connection per client process and address), and it
   may outlive an association, so a late frame can carry an older tag.

   Below this module (assumed, their own specs): the stream is ordered,
   credited and survives path moves (link Link.tla, DirectPath.tla); the
   binding of an association to a direct connection takes both ends'
   tokens (cap_address.pv queries 17-18, e2ee_tcp.pv 21-26); QUIC frames
   are authenticated and a replayed packet is discarded (RFC 9000 12.3).
   Abstracted: contents and sizes (a datagram counts 1 against credit,
   queues and the amplification budget), real time (an idle timer may
   fire once its side has nothing to move), the open's handshake (one
   step), the punch (Bind: never fair, a pair may never go direct).

   Mutants (scripts/spec.sh mutants), one per failure the design prevents:
   deliver-after-close, reuse-id, tag-unchecked, direct-ignores-assoc,
   no-client-cap, no-agent-cap, grow-queue, block-on-credit,
   no-source-check, no-amp-cap, per-flow-budget, no-idle. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Srcs,     \* source addresses that send to the client's listener
    Adm,      \* those the listener admits (loopback, allow list, a knock)
    Busy, N,  \* Busy sends N datagrams, every other source one
    Ids,      \* flow ids of one association
    MaxEp,    \* associations the client opens, one after another
    MaxFlowsC, \* the client's flow cap per association (udp_max_flows)
    MaxFlows, \* the agent's (max_flows): set independently, so a client may ask past it
    W,        \* datagrams of the stream in flight each way (link credit)
    Q,        \* the target's replies queued per flow at the agent
    Amp,      \* replies the target sends per datagram it gets
    R, B,     \* amplification: to a source at most R x what it sent + B
    MaxCuts,  \* the association's end: session reset, client or agent death
    MaxLoss,  \* the direct connection's deaths
    Mutant

ASSUME Adm \subseteq Srcs /\ Busy \in Srcs /\ N >= 1 /\ MaxEp >= 1
ASSUME MaxFlowsC >= 1 /\ MaxFlows >= 1 /\ W >= 1 /\ Q >= 1 /\ Amp >= 1

None == "none"
NoKey == <<0, 0>>  \* the reader waits on no flow
Sends(s) == IF s = Busy THEN N ELSE 1
Eps == 1..MaxEp
Keys == Eps \X Ids
Live == {"opening", "open"}
Msg == [k : {"open", "accept", "refuse", "d", "close"}, f : Ids, src : Srcs \cup {None}]
Dg == [dir : {"c2a", "a2c"}, e : Eps, f : Ids, src : Srcs]

VARIABLES
    sent, sock,     \* datagrams each source sent; of those, not yet read
    inb, outb,      \* per source: datagrams the listener read from it, wrote to it
    fin, fout,      \* the same per flow (only per-flow-budget uses them)
    cep, cup, ccut, crefused, \* client: association epoch, up, died unnoticed, open refused
    cst, csrc, cbnd,          \* client: flow states, their sources, epochs bound direct
    aep, aup, acut, adead,    \* agent: epoch, up, died unnoticed, cleanup pending
    ast, asrc, aq, abnd,      \* agent: flow states, sources (ghost), reply queues, bound epochs
    c2a, a2c,       \* the association's stream (control and relayed datagrams)
    dg,             \* QUIC DATAGRAM frames in flight on the direct connection (lossy)
    revoked, cuts, losses, blocked,
    late, cross, lateRev, \* ghosts: a datagram handed on after close, to another flow, after revoke
    got, viaDirect, moved, staleTag, ampDrop

vars == <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst, csrc,
          cbnd, aep, aup, acut, adead, ast, asrc, aq, abnd, c2a, a2c, dg,
          revoked, cuts, losses, blocked, late, cross, lateRev, got,
          viaDirect, moved, staleTag, ampDrop>>

TypeOK ==
    /\ sent \in [Srcs -> 0..N] /\ sock \in [Srcs -> 0..N]
    /\ inb \in [Srcs -> Nat] /\ outb \in [Srcs -> Nat]
    /\ fin \in [Keys -> Nat] /\ fout \in [Keys -> Nat]
    /\ cep \in 0..MaxEp /\ aep \in 0..MaxEp
    /\ cup \in BOOLEAN /\ ccut \in BOOLEAN /\ crefused \in BOOLEAN
    /\ aup \in BOOLEAN /\ acut \in BOOLEAN /\ adead \in BOOLEAN
    /\ cst \in [Keys -> {"free", "opening", "open", "closed"}]
    /\ ast \in [Keys -> {"free", "open", "closed"}]
    /\ csrc \in [Keys -> Srcs \cup {None}] /\ asrc \in [Keys -> Srcs \cup {None}]
    /\ aq \in [Keys -> Nat]
    /\ cbnd \subseteq Eps /\ abnd \subseteq Eps
    /\ \A i \in 1..Len(c2a) : c2a[i] \in Msg
    /\ \A i \in 1..Len(a2c) : a2c[i] \in Msg
    /\ dg \subseteq Dg
    /\ blocked \in Keys \cup {NoKey}
    /\ viaDirect \subseteq Keys

Init ==
    /\ sent = [s \in Srcs |-> 0] /\ sock = [s \in Srcs |-> 0]
    /\ inb = [s \in Srcs |-> 0] /\ outb = [s \in Srcs |-> 0]
    /\ fin = [k \in Keys |-> 0] /\ fout = [k \in Keys |-> 0]
    /\ cep = 0 /\ cup = FALSE /\ ccut = FALSE /\ crefused = FALSE
    /\ cst = [k \in Keys |-> "free"] /\ csrc = [k \in Keys |-> None] /\ cbnd = {}
    /\ aep = 0 /\ aup = FALSE /\ acut = FALSE /\ adead = FALSE
    /\ ast = [k \in Keys |-> "free"] /\ asrc = [k \in Keys |-> None]
    /\ aq = [k \in Keys |-> 0] /\ abnd = {}
    /\ c2a = <<>> /\ a2c = <<>> /\ dg = {}
    /\ revoked = FALSE /\ cuts = 0 /\ losses = 0 /\ blocked = NoKey
    /\ late = FALSE /\ cross = FALSE /\ lateRev = FALSE
    /\ got = FALSE /\ viaDirect = {} /\ moved = FALSE /\ staleTag = FALSE /\ ampDrop = FALSE

Data(ch) == Cardinality({i \in 1..Len(ch) : ch[i].k \in {"open", "d"}})
EpKeys(e) == {<<e, i>> : i \in Ids}
LiveC == {k \in Keys : cst[k] \in Live}
LiveA == {k \in Keys : ast[k] = "open"}
FlowOf(s) == {k \in LiveC : k[1] = cep /\ csrc[k] = s}
Ctl(kind, f) == [k |-> kind, f |-> f, src |-> None]
\* A side writes on the stream only while it is alive under it.
SendC(m) == IF ccut \/ ~cup THEN c2a ELSE Append(c2a, m)
SendA(m) == IF acut \/ ~aup THEN a2c ELSE Append(a2c, m)
\* A new flow's id: the lowest never used in this association (reuse-id:
\* a closed one too).
Usable(k) == cst[k] = "free" \/ (Mutant = "reuse-id" /\ cst[k] = "closed")
NewKey == CHOOSE k \in EpKeys(cep) : Usable(k) /\ \A h \in EpKeys(cep) : Usable(h) => k[2] <= h[2]
\* The amplification budget of a reply to source s on flow k.
Budget(s, k) == IF Mutant = "per-flow-budget" THEN fout[k] < R * fin[k] + B
                ELSE outb[s] < R * inb[s] + B

----------------------------------------------------------------------------
\* The application (and whoever spoofs a source address).

AppSend(s) ==
    /\ sent[s] < Sends(s)
    /\ sent' = [sent EXCEPT ![s] = @ + 1]
    /\ sock' = [sock EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<inb, outb, fin, fout, cep, cup, ccut, crefused, cst, csrc,
                   cbnd, aep, aup, acut, adead, ast, asrc, aq, abnd, c2a, a2c, dg,
                   revoked, cuts, losses, blocked, late, cross, lateRev, got,
                   viaDirect, moved, staleTag, ampDrop>>

----------------------------------------------------------------------------
\* The client: one reader of the listener's socket, one association, its
\* flow table keyed by source.

\* The association opens (rendezvous, pinned TLS, proof: one step) when an
\* admitted source has a datagram and no association is up; after a
\* revocation the open is refused (the address no longer served, the
\* certificate revoked) and the reader drops from then on.
AssocOpen ==
    /\ ~cup /\ ~ccut /\ ~crefused /\ cep < MaxEp
    /\ ~aup /\ ~acut /\ ~adead
    /\ \E s \in Adm : sock[s] > 0
    /\ IF revoked
       THEN /\ crefused' = TRUE
            /\ UNCHANGED <<cep, cup, aep, aup, c2a, a2c>>
       ELSE /\ cep' = cep + 1 /\ aep' = cep + 1
            /\ cup' = TRUE /\ aup' = TRUE
            /\ c2a' = <<>> /\ a2c' = <<>>
            /\ UNCHANGED crefused
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, ccut, cst, csrc, cbnd, acut,
                   adead, ast, asrc, aq, abnd, dg, revoked, cuts, losses, blocked,
                   late, cross, lateRev, got, viaDirect, moved, staleTag, ampDrop>>

\* The reader takes s's next datagram. Not admitted: dropped before any
\* lookup (no-source-check: treated as admitted). An open flow's datagram
\* goes direct when the association is bound there, else on the stream
\* while it has credit, else it is dropped (block-on-credit: the reader
\* waits for credit and reads nothing else). An opening flow's goes on
\* the stream behind its open (the agent drops it if it refuses the flow).
\* A new source gets a flow (its open carries the datagram) while the
\* table has room and the stream has credit; else dropped.
Read(s) ==
    /\ sock[s] > 0
    /\ IF blocked = NoKey THEN TRUE
       ELSE s = csrc[blocked] /\ (Data(c2a) < W \/ ccut \/ cst[blocked] \notin Live)
    /\ IF s \notin Adm /\ Mutant # "no-source-check"
       THEN /\ sock' = [sock EXCEPT ![s] = @ - 1]
            /\ blocked' = NoKey
            /\ UNCHANGED <<inb, fin, cst, csrc, c2a, dg>>
       ELSE IF ~cup
       THEN /\ crefused \/ cep = MaxEp   \* else it waits for the open
            /\ sock' = [sock EXCEPT ![s] = @ - 1]
            /\ blocked' = NoKey
            /\ UNCHANGED <<inb, fin, cst, csrc, c2a, dg>>
       ELSE IF FlowOf(s) # {}
       THEN LET k == CHOOSE h \in FlowOf(s) : TRUE IN
            IF (cst[k] = "opening" \/ cep \notin cbnd) /\ ~ccut /\ Data(c2a) >= W
               /\ Mutant = "block-on-credit"
            THEN /\ blocked' = k
                 /\ UNCHANGED <<sock, inb, fin, cst, csrc, c2a, dg>>
            ELSE
            /\ sock' = [sock EXCEPT ![s] = @ - 1]
            /\ inb' = [inb EXCEPT ![s] = @ + 1]
            /\ fin' = [fin EXCEPT ![k] = @ + 1]
            /\ blocked' = NoKey
            /\ IF cst[k] = "open" /\ cep \in cbnd
               THEN /\ dg' = dg \cup {[dir |-> "c2a", e |-> cep, f |-> k[2], src |-> s]}
                    /\ UNCHANGED c2a
               ELSE IF ~ccut /\ Data(c2a) < W
               THEN /\ c2a' = Append(c2a, [k |-> "d", f |-> k[2], src |-> s])
                    /\ UNCHANGED dg
               ELSE UNCHANGED <<c2a, dg>>
            /\ UNCHANGED <<cst, csrc>>
       ELSE /\ sock' = [sock EXCEPT ![s] = @ - 1]
            /\ inb' = [inb EXCEPT ![s] = @ + 1]
            /\ blocked' = NoKey
            /\ IF /\ \E k \in EpKeys(cep) : Usable(k)
                  /\ Cardinality(LiveC \cap EpKeys(cep)) < MaxFlowsC \/ Mutant = "no-client-cap"
                  /\ ~ccut /\ Data(c2a) < W
               THEN LET k == NewKey IN
                    /\ cst' = [cst EXCEPT ![k] = "opening"]
                    /\ csrc' = [csrc EXCEPT ![k] = s]
                    /\ fin' = [fin EXCEPT ![k] = 1]
                    /\ c2a' = Append(c2a, [k |-> "open", f |-> k[2], src |-> s])
               ELSE UNCHANGED <<cst, csrc, fin, c2a>>
            /\ UNCHANGED dg
    /\ UNCHANGED <<sent, outb, fout, cep, cup, ccut, crefused, cbnd, aep, aup, acut,
                   adead, ast, asrc, aq, abnd, a2c, revoked, cuts, losses, late, cross,
                   lateRev, got, viaDirect, moved, staleTag, ampDrop>>

\* A reply reaches flow k at the client (from the stream or a frame, its
\* sender's source as a ghost); written to k's source within the source's
\* amplification budget, else dropped.
Reply(k, src, direct) ==
    IF cst[k] = "open" \/ (Mutant = "deliver-after-close" /\ cst[k] = "closed")
    THEN LET s == csrc[k] IN
         IF Budget(s, k) \/ Mutant = "no-amp-cap"
         THEN /\ outb' = [outb EXCEPT ![s] = @ + 1]
              /\ fout' = [fout EXCEPT ![k] = @ + 1]
              /\ got' = TRUE
              /\ late' = (late \/ cst[k] # "open")
              /\ cross' = (cross \/ src # s)
              /\ UNCHANGED ampDrop
         ELSE /\ ampDrop' = TRUE
              /\ UNCHANGED <<outb, fout, got, late, cross>>
    ELSE UNCHANGED <<outb, fout, got, late, cross, ampDrop>>

\* The client reads the stream: an open's answer, a relayed reply, a close.
RecvC ==
    /\ a2c # <<>>
    /\ LET m == Head(a2c)
           k == <<cep, m.f>> IN
       /\ a2c' = Tail(a2c)
       /\ CASE m.k = "accept" ->
                 /\ cst' = IF cst[k] = "opening" THEN [cst EXCEPT ![k] = "open"] ELSE cst
                 /\ UNCHANGED <<outb, fout, got, late, cross, ampDrop>>
            [] m.k \in {"refuse", "close"} ->
                 /\ cst' = IF cst[k] \in Live THEN [cst EXCEPT ![k] = "closed"] ELSE cst
                 /\ UNCHANGED <<outb, fout, got, late, cross, ampDrop>>
            [] m.k = "d" ->
                 /\ Reply(k, m.src, FALSE)
                 /\ UNCHANGED cst
    /\ UNCHANGED <<sent, sock, inb, fin, cep, cup, ccut, crefused, csrc, cbnd, aep,
                   aup, acut, adead, ast, asrc, aq, abnd, c2a, dg, revoked, cuts,
                   losses, blocked, lateRev, viaDirect, moved, staleTag>>

\* The client takes a frame off the direct connection: handed on only when
\* its tag is this association's, bound here, and the flow is open.
RecvDgC(m) ==
    /\ m \in dg /\ m.dir = "a2c"
    /\ dg' = dg \ {m}
    /\ IF m.e = cep /\ m.e \in cbnd /\ cup
       THEN Reply(<<m.e, m.f>>, m.src, TRUE)
       ELSE UNCHANGED <<outb, fout, got, late, cross, ampDrop>>
    /\ UNCHANGED <<sent, sock, inb, fin, cep, cup, ccut, crefused, cst, csrc, cbnd,
                   aep, aup, acut, adead, ast, asrc, aq, abnd, c2a, a2c, revoked,
                   cuts, losses, blocked, lateRev, viaDirect, moved, staleTag>>

\* Idle: a flow's source has been quiet for the idle bound (an opening
\* flow: the open timeout). The client closes it on the stream.
ExpireC(k) ==
    /\ Mutant # "no-idle"
    /\ k \in LiveC /\ k[1] = cep /\ cup /\ sock[csrc[k]] = 0
    /\ cst' = [cst EXCEPT ![k] = "closed"]
    /\ c2a' = SendC(Ctl("close", k[2]))
    /\ blocked' = IF blocked = k THEN NoKey ELSE blocked
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, csrc,
                   cbnd, aep, aup, acut, adead, ast, asrc, aq, abnd, a2c, dg, revoked,
                   cuts, losses, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

\* The client reads its association's end (the stream's reset or error):
\* every flow of it ends, its direct binding goes.
NoticeC ==
    /\ ccut
    /\ ccut' = FALSE /\ cup' = FALSE
    /\ cst' = [k \in Keys |-> IF k \in LiveC THEN "closed" ELSE cst[k]]
    /\ cbnd' = cbnd \ {cep}
    /\ blocked' = NoKey
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, crefused, csrc, aep, aup,
                   acut, adead, ast, asrc, aq, abnd, c2a, a2c, dg, revoked, cuts,
                   losses, late, cross, lateRev, got, viaDirect, moved, staleTag,
                   ampDrop>>

----------------------------------------------------------------------------
\* The agent: the association's flows of one datagram service, one
\* connected socket to the target each.

\* A datagram of flow k (sent in association e) reaches the target; the target's Amp replies are
\* queued for k (at most Q: the rest dropped; grow-queue: taken).
Deliver(k, e, src, direct) ==
    /\ aq' = [aq EXCEPT ![k] = IF Mutant = "grow-queue" THEN @ + Amp
                                ELSE IF @ + Amp > Q THEN Q ELSE @ + Amp]
    /\ late' = (late \/ ast[k] # "open")
    /\ cross' = (cross \/ src # asrc[k] \/ e # k[1])
    /\ lateRev' = (lateRev \/ revoked)
    /\ viaDirect' = IF direct THEN viaDirect \cup {k} ELSE viaDirect
    /\ moved' = (moved \/ (~direct /\ k \in viaDirect))

RecvA ==
    /\ c2a # <<>>
    /\ LET m == Head(c2a)
           k == <<aep, m.f>> IN
       /\ c2a' = Tail(c2a)
       /\ CASE m.k = "open" ->
                 IF /\ ast[k] = "free" \/ (Mutant = "reuse-id" /\ ast[k] = "closed")
                    /\ Cardinality(LiveA \cap EpKeys(aep)) < MaxFlows \/ Mutant = "no-agent-cap"
                 THEN /\ ast' = [ast EXCEPT ![k] = "open"]
                      /\ asrc' = [asrc EXCEPT ![k] = m.src]
                      /\ a2c' = SendA(Ctl("accept", m.f))
                      /\ aq' = [aq EXCEPT ![k] = IF Amp > Q /\ Mutant # "grow-queue" THEN Q ELSE Amp]
                      /\ lateRev' = (lateRev \/ revoked)
                      /\ UNCHANGED <<late, cross, viaDirect, moved>>
                 ELSE /\ ast' = IF ast[k] = "free" THEN [ast EXCEPT ![k] = "closed"] ELSE ast
                      /\ a2c' = SendA(Ctl("refuse", m.f))
                      /\ UNCHANGED <<asrc, aq, late, cross, lateRev, viaDirect, moved>>
            [] m.k = "d" ->
                 /\ IF ast[k] = "open" \/ (Mutant = "deliver-after-close" /\ ast[k] = "closed")
                    THEN Deliver(k, aep, m.src, FALSE)
                    ELSE UNCHANGED <<aq, late, cross, lateRev, viaDirect, moved>>
                 /\ UNCHANGED <<ast, asrc, a2c>>
            [] m.k = "close" ->
                 /\ ast' = IF ast[k] = "open" THEN [ast EXCEPT ![k] = "closed"] ELSE ast
                 /\ aq' = [aq EXCEPT ![k] = 0]
                 /\ UNCHANGED <<asrc, a2c, late, cross, lateRev, viaDirect, moved>>
            [] OTHER -> UNCHANGED <<ast, asrc, aq, a2c, late, cross, lateRev, viaDirect, moved>>
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, cbnd, aep, aup, acut, adead, abnd, dg, revoked, cuts, losses,
                   blocked, got, staleTag, ampDrop>>

\* The agent takes a frame off the direct connection: handed to flow
\* <<tag, id>> only while the association with that tag is up and bound
\* here and the flow is open. tag-unchecked: the id looked up in the
\* current association, whatever the tag. direct-ignores-assoc: the
\* association's end (a reset, a revocation) not checked on this path
\* until the cleanup removes the binding.
RecvDgA(m) ==
    /\ m \in dg /\ m.dir = "c2a"
    /\ dg' = dg \ {m}
    /\ staleTag' = (staleTag \/ (m.e < aep /\ aup))
    /\ LET k == IF Mutant = "tag-unchecked" THEN <<aep, m.f>> ELSE <<m.e, m.f>>
           tagOK == IF Mutant = "tag-unchecked" THEN aep \in abnd
                    ELSE m.e = aep /\ m.e \in abnd
       IN IF tagOK /\ (aup \/ Mutant = "direct-ignores-assoc") /\ ast[k] = "open"
          THEN Deliver(k, m.e, m.src, TRUE)
          ELSE UNCHANGED <<aq, late, cross, lateRev, viaDirect, moved>>
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, cbnd, aep, aup, acut, adead, ast, asrc, abnd, c2a, a2c,
                   revoked, cuts, losses, blocked, got, ampDrop>>

\* The agent sends flow k's next reply: direct when bound, else on the
\* stream on credit, else dropped (it never waits).
ReplyA(k) ==
    /\ aq[k] > 0 /\ ast[k] = "open" /\ k[1] = aep /\ aup
    /\ aq' = [aq EXCEPT ![k] = @ - 1]
    /\ IF aep \in abnd
       THEN /\ dg' = dg \cup {[dir |-> "a2c", e |-> aep, f |-> k[2], src |-> asrc[k]]}
            /\ UNCHANGED a2c
       ELSE IF ~acut /\ Data(a2c) < W
       THEN /\ a2c' = Append(a2c, [k |-> "d", f |-> k[2], src |-> asrc[k]])
            /\ UNCHANGED dg
       ELSE UNCHANGED <<a2c, dg>>
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, cbnd, aep, aup, acut, adead, ast, asrc, abnd, c2a, revoked,
                   cuts, losses, blocked, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

\* The agent's idle backstop: nothing for flow k in flight from the client.
ExpireA(k) ==
    /\ Mutant # "no-idle"
    /\ ast[k] = "open" /\ k[1] = aep /\ aup
    /\ \A i \in 1..Len(c2a) : c2a[i].f # k[2]
    /\ \A m \in dg : ~(m.dir = "c2a" /\ m.e = k[1] /\ m.f = k[2])
    /\ ast' = [ast EXCEPT ![k] = "closed"]
    /\ aq' = [aq EXCEPT ![k] = 0]
    /\ a2c' = SendA(Ctl("close", k[2]))
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, cbnd, aep, aup, acut, adead, asrc, abnd, c2a, dg, revoked,
                   cuts, losses, blocked, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

\* The agent reads its association's end: marked down at once; the
\* cleanup (CleanupA) closes its flows and drops its binding.
NoticeA ==
    /\ acut
    /\ acut' = FALSE /\ aup' = FALSE /\ adead' = TRUE
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, cbnd, aep, ast, asrc, aq, abnd, c2a, a2c, dg, revoked, cuts,
                   losses, blocked, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

CleanupA ==
    /\ adead
    /\ adead' = FALSE
    /\ ast' = [k \in Keys |-> IF ast[k] = "open" THEN "closed" ELSE ast[k]]
    /\ aq' = [k \in Keys |-> 0]
    /\ abnd' = abnd \ {aep}
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, cbnd, aep, aup, acut, asrc, c2a, a2c, dg, revoked, cuts,
                   losses, blocked, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

----------------------------------------------------------------------------
\* The environment.

\* The association binds to the direct connection (the punch and both
\* tokens: cap_address.pv, DirectPath.tla). Never fair.
Bind ==
    /\ cup /\ aup /\ cep = aep /\ cep \notin cbnd /\ ~ccut /\ ~acut
    /\ cbnd' = cbnd \cup {cep} /\ abnd' = abnd \cup {aep}
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, aep, aup, acut, adead, ast, asrc, aq, c2a, a2c, dg, revoked,
                   cuts, losses, blocked, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

\* The direct connection dies: its frames are lost, every binding goes;
\* the stream carries on relayed (pathswitch).
PathLoss ==
    /\ losses < MaxLoss /\ (cbnd # {} \/ abnd # {})
    /\ losses' = losses + 1
    /\ cbnd' = {} /\ abnd' = {} /\ dg' = {}
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, ccut, crefused, cst,
                   csrc, aep, aup, acut, adead, ast, asrc, aq, c2a, a2c, revoked,
                   cuts, blocked, late, cross, lateRev, got, viaDirect, moved,
                   staleTag, ampDrop>>

\* The association ends: "session" (its stream reset: the relay lost both
\* paths, a detach bound), each side learning it on its own time, the
\* direct connection kept (it may carry the client's next association);
\* "client" or "agent": that process died, its direct connection with it.
Cut(who) ==
    /\ cuts < MaxCuts /\ (cup \/ aup)
    /\ cuts' = cuts + 1
    /\ c2a' = <<>> /\ a2c' = <<>>
    /\ IF who = "client"
       THEN /\ cup' = FALSE /\ ccut' = FALSE
            /\ cst' = [k \in Keys |-> IF k \in LiveC THEN "closed" ELSE cst[k]]
            /\ cbnd' = {} /\ dg' = {} /\ abnd' = {}
            /\ inb' = [s \in Srcs |-> 0] /\ outb' = [s \in Srcs |-> 0]
            /\ blocked' = NoKey
       ELSE /\ ccut' = cup
            /\ UNCHANGED <<cup, cst, cbnd, inb, outb, blocked>>
            /\ IF who = "agent" THEN dg' = {} /\ abnd' = {} ELSE UNCHANGED <<dg, abnd>>
    /\ IF who = "agent"
       THEN /\ aup' = FALSE /\ acut' = FALSE /\ adead' = FALSE
            /\ ast' = [k \in Keys |-> IF ast[k] = "open" THEN "closed" ELSE ast[k]]
            /\ aq' = [k \in Keys |-> 0]
       ELSE /\ acut' = aup
            /\ UNCHANGED <<aup, adead, ast, aq>>
    /\ UNCHANGED <<sent, sock, fin, fout, cep, crefused, csrc, aep, asrc, revoked,
                   losses, late, cross, lateRev, got, viaDirect, moved, staleTag, ampDrop>>

\* The client's right ends (the agent applies a revocation: the address
\* replaced, the client's certificate revoked): the agent marks the
\* association down and resets its stream at once; the cleanup follows.
Revoke ==
    /\ ~revoked /\ aup
    /\ revoked' = TRUE
    /\ aup' = FALSE /\ adead' = TRUE
    /\ c2a' = <<>> /\ a2c' = <<>>
    /\ ccut' = cup
    /\ UNCHANGED <<sent, sock, inb, outb, fin, fout, cep, cup, crefused, cst, csrc,
                   cbnd, aep, acut, ast, asrc, aq, abnd, dg, cuts, losses, blocked,
                   late, cross, lateRev, got, viaDirect, moved, staleTag, ampDrop>>

----------------------------------------------------------------------------

Next ==
    \/ \E s \in Srcs : AppSend(s) \/ Read(s)
    \/ AssocOpen \/ RecvC \/ NoticeC \/ RecvA \/ NoticeA \/ CleanupA
    \/ \E m \in dg : RecvDgC(m) \/ RecvDgA(m)
    \/ \E k \in Keys : ExpireC(k) \/ ReplyA(k) \/ ExpireA(k)
    \/ Bind \/ PathLoss \/ Revoke
    \/ \E who \in {"session", "client", "agent"} : Cut(who)

\* Every step but the environment's (Bind, PathLoss, Revoke, Cut) is fair.
Fairness ==
    /\ \A s \in Srcs : WF_vars(AppSend(s)) /\ WF_vars(Read(s))
    /\ WF_vars(AssocOpen) /\ WF_vars(RecvC) /\ WF_vars(NoticeC)
    /\ WF_vars(RecvA) /\ WF_vars(NoticeA) /\ WF_vars(CleanupA)
    /\ WF_vars(\E m \in dg : RecvDgC(m) \/ RecvDgA(m))
    /\ \A k \in Keys : WF_vars(ExpireC(k)) /\ WF_vars(ReplyA(k)) /\ WF_vars(ExpireA(k))

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Invariants.

\* No datagram is handed on (to the target, to a source) by a side after
\* it closed the flow it came on.
NoDeliverAfterClose == ~late
\* No datagram is handed to a flow other than its own: another source's,
\* another association's.
NoCrossFlow == ~cross
\* Nothing reaches the target once the association's right was revoked.
NoDeliverAfterRevoke == ~lateRev
\* Each side's flow table per association holds at most its cap.
TableBounded == \A e \in Eps : /\ Cardinality(LiveC \cap EpKeys(e)) <= MaxFlowsC
                               /\ Cardinality(LiveA \cap EpKeys(e)) <= MaxFlows
\* At most Q replies queued per flow, W datagrams of the stream in flight.
MemoryBound == (\A k \in Keys : aq[k] <= Q) /\ Data(c2a) <= W /\ Data(a2c) <= W
\* The reader never waits on one flow while another source's datagrams wait.
NoHOL == blocked # NoKey => \A s \in Srcs \ {csrc[blocked]} : sock[s] = 0
\* No source the listener does not admit is ever written to.
NoReflection == \A s \in Srcs \ Adm : outb[s] = 0
\* To each source at most R times what it sent, plus B (per client process).
AmpBound == \A s \in Srcs : outb[s] <= R * inb[s] + B

\* A closed flow stays closed (ids never reused in an association).
ClosedFinal == [][\A k \in Keys : /\ (cst[k] = "closed" => cst'[k] = "closed")
                                  /\ (ast[k] = "closed" => ast'[k] = "closed")]_vars
\* Every flow ends at both sides.
AllFlowsEnd == \A k \in Keys : /\ ((cst[k] \in Live) ~> (cst[k] = "closed"))
                               /\ ((ast[k] = "open") ~> (ast[k] = "closed"))

\* Witnesses (each must be violated: scripts/spec.sh mutants).
W_Direct == viaDirect = {}                    \* a datagram reached the target direct
W_Moved == ~moved                             \* a flow that went direct carried on relayed
W_StaleTag == ~staleTag                       \* an older association's frame reached a newer one
W_Revoked == ~(revoked /\ \E k \in Keys : ast[k] = "closed" /\ asrc[k] # None)
W_Refused == ~crefused                        \* an open after the revocation refused
W_AmpDrop == ~ampDrop                         \* a reply dropped by the budget
W_Reply == ~got
W_FlowRefused == ~(\E i \in 1..Len(a2c) : a2c[i].k = "refuse")
=============================================================================
