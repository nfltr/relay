------------------------- MODULE TraceDatagramAssoc -------------------------
(* Trace validation of DatagramAssoc.tla (spec/README.md "DatagramAssoc
   traces"): the steps both sides of one relayed association took in a
   real run (-tags relaytrace, client/dgram trace_on.go) must be a
   behaviour of DatagramAssoc with that one association (MaxEp 1): the
   open (AssocOpen), the listener's reader taking a source's datagram
   (Read: a flow's open, a datagram on it, or a drop: a source not
   admitted, the flow table full), each side's reader taking the head
   frame of its stream (RecvC, RecvA: the frame's kind and flow must be
   the head's, and what the side did with a datagram, delivered or
   dropped, must be the model's), the agent sending a target's reply
   (ReplyA), and each side's idle close (ExpireC, ExpireA); on the
   direct path (lane DGRAMTRACE, client/agent's tests that move direct)
   the agent's attach (BindA), the client's check of its token (BindC),
   each side taking a frame off the direct connection (RecvDgA, RecvDgC:
   delivered or dropped, the model's), the carrier a datagram or a reply
   took (direct, the stream, or spilled to it), and an end finding its
   direct path gone (PathLoss: the first end's is the model's, the other
   end's changes nothing). The
   application's sends (AppSend) are not logged: TLC takes one only when
   the next logged step needs it. Recording stops at the association's
   end. Bounds the run does not have are lifted: stream credit, reply
   queues, the target's replies per datagram and the amplification
   budget are the trace's length (the byte budget is the Go tests'); the
   flow caps are the run's (its Serve and AssocOpen lines). Accepted when
   TLC reaches the trace's end: TraceNotDone is then violated
   (scripts/spec.sh traces). *)
EXTENDS Json, DatagramAssoc, TLC

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)
Reads == SelectSeq(Log, LAMBDA e : e.ev = "Read")
TraceSrcs == {Reads[i].s : i \in 1..Len(Reads)}
TraceAdm == {Reads[i].s : i \in {j \in 1..Len(Reads) : Reads[j].adm}}
TraceLen == Len(Log) + 1
TraceIds == 1..(LET fs == {Log[i].f : i \in {j \in 1..Len(Log) : "f" \in DOMAIN Log[j]}}
                IN IF fs = {} THEN 1 ELSE CHOOSE m \in fs : \A x \in fs : x <= m) + 1
Cap(ev) == LET o == SelectSeq(Log, LAMBDA e : e.ev = ev) IN IF o = <<>> THEN 1 ELSE o[1].n
TraceMaxFlowsC == Cap("AssocOpen")
TraceMaxFlowsA == Cap("Serve")
\* Every source sends as many datagrams as the trace reads from it.
TraceSends(s) == Cardinality({i \in 1..Len(Reads) : Reads[i].s = s})
TraceBusy == CHOOSE s \in TraceSrcs : TRUE

VARIABLE l
E == Log[l]

Last(s) == s[Len(s)]
\* The frame a Read put on the stream or the direct connection (none for a
\* drop): on the stream while the flow is open and bound only spilled.
ReadOut ==
    CASE E.op = "drop" -> c2a' = c2a /\ dg' = dg
      [] E.op = "direct" -> /\ c2a' = c2a
                            /\ [dir |-> "c2a", e |-> cep, f |-> E.f, src |-> E.s] \in dg'
      [] OTHER -> /\ Len(c2a') = Len(c2a) + 1
                  /\ Last(c2a').k = IF E.op = "open" THEN "open" ELSE "d"
                  /\ Last(c2a').f = E.f
                  /\ E.op = "d" => ~(cst[<<cep, E.f>>] = "open" /\ cep \in cbnd)
                  /\ E.op = "spill" => cep \in cbnd
\* The carrier of the agent's reply.
ReplyOut ==
    CASE E.out = "direct" -> /\ a2c' = a2c
                             /\ [dir |-> "a2c", e |-> aep, f |-> E.f, src |-> asrc[<<aep, E.f>>]] \in dg'
      [] OTHER -> /\ Len(a2c') = Len(a2c) + 1
                  /\ E.out = "stream" => ~(aep \in abnd /\ aep \in aheard)
                  /\ E.out = "spill" => aep \in abnd
HeadIs(ch) == ch # <<>> /\ Head(ch).k = E.k /\ Head(ch).f = E.f
\* A frame of flow E.f taken off the direct connection, handed on or not
\* as the model does.
RecvDg(dir) ==
    \E m \in dg :
       /\ m.dir = dir /\ m.f = E.f
       /\ IF dir = "c2a"
          THEN /\ RecvDgA(m)
               /\ (E.out = "deliver") = (m.e = aep /\ aep \in abnd /\ aup /\ ast[<<m.e, m.f>>] = "open")
          ELSE /\ RecvDgC(m)
               /\ (E.out = "deliver") = (m.e = cep /\ cep \in cbnd /\ cup /\ cst[<<m.e, m.f>>] \in Live)

Step ==
    CASE E.ev = "Serve" -> UNCHANGED vars
      [] E.ev = "AssocOpen" -> AssocOpen
      [] E.ev = "Read" -> Read(E.s) /\ ReadOut
      [] E.ev = "RecvC" -> /\ HeadIs(a2c)
                           /\ E.k = "d" => ((E.out = "deliver") = (cst[<<cep, E.f>>] = "open"))
                           /\ RecvC
      [] E.ev = "RecvA" -> /\ HeadIs(c2a)
                           /\ E.k = "d" => ((E.out = "deliver") = (ast[<<aep, E.f>>] = "open"))
                           /\ RecvA
                           /\ E.k = "open" => ((E.out = "accept") = (ast'[<<aep, E.f>>] = "open"))
      [] E.ev = "ReplyA" -> ReplyA(<<aep, E.f>>) /\ ReplyOut
      [] E.ev = "RecvDgA" -> RecvDg("c2a")
      [] E.ev = "RecvDgC" -> RecvDg("a2c")
      [] E.ev = "BindA" -> BindA
      [] E.ev = "BindC" -> BindC
      [] E.ev = "PathLoss" -> IF cbnd \cup abnd # {} THEN PathLoss ELSE UNCHANGED vars
      [] E.ev = "ExpireC" -> ExpireC(<<cep, E.f>>)
      [] E.ev = "ExpireA" -> ExpireA(<<aep, E.f>>)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ (\E s \in Srcs : AppSend(s)) /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
