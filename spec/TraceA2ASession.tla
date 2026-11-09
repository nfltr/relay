-------------------------- MODULE TraceA2ASession --------------------------
(* Trace validation of A2ASession.tla (spec/README.md "A2ASession
   traces"): the session steps a real run recorded (-tags relaytrace,
   client/rpcclient trace_a2asession_on.go traceAS) between one caller
   (Caller) and one callee (Callee) must be a behaviour of A2ASession with
   that pair's calls and sessions alone. The callee logs Handshake, Warm
   and Retry (a retry answered: Unknown's handshake; the line names the
   resume it retries, which must be the call's) when it keeps the new
   session, Deliver when it takes a resume, DropIn when it drops a
   session, Restart when it loses them all; the caller logs Resume (its
   session and call number must be the model's), Confirm, Fail (a retry
   refused: Unknown's failure) and DropOut. A session is numbered in the
   order the trace names it, which is the order the model makes it. The
   relay's and the clock's steps are not logged: TLC takes them only when
   the next logged step needs them (the retry bound passing, Late; the
   caller losing a session the model gave it, ExpireCaller: an ack the
   caller never took; a call the callee took starting, Finish: Deliver is
   logged once its record is synced, before the handler starts). Accepted when TLC reaches the trace's end:
   TraceNotDone is then violated (scripts/spec.sh astraces). *)
EXTENDS Json, A2ASession, Sequences, TLC

CONSTANTS TraceFile, Caller, Callee

Log == SelectSeq(ndJsonDeserialize(TraceFile),
                 LAMBDA e : e.t = Callee /\ (e.f = Caller \/ e.ev = "Restart"))
TraceCalls == {Log[i].k : i \in DOMAIN Log} \ {""}
TraceSess == Cardinality({Log[i].s : i \in DOMAIN Log} \ {0})

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Handshake" -> E.s = nsess + 1 /\ Handshake(E.k)
      [] E.ev = "Warm" -> E.s = nsess + 1 /\ Warm
      [] E.ev = "Retry" -> /\ E.s = nsess + 1 /\ res[E.k] = [s |-> E.os, c |-> E.oc]
                           /\ Unknown(E.k) /\ st'[E.k] = "done"
      [] E.ev = "Fail" -> Unknown(E.k) /\ st'[E.k] = "failed"
      [] E.ev = "Resume" -> cs.id = E.s /\ cs.next = E.c /\ Resume(E.k)
      [] E.ev = "Deliver" -> Deliver([s |-> E.s, c |-> E.c, k |-> E.k])
      [] E.ev = "Confirm" -> Confirm(E.k)
      [] E.ev = "DropOut" -> cs.id = E.s /\ ExpireCaller
      [] E.ev = "DropIn" -> ExpireCallee(E.s)
      [] E.ev = "Restart" -> Restart
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

\* The steps no end logs, taken only when the next logged one waits for them.
EnvStep == ExpireCaller \/ (\E k \in Calls : Late(k)) \/ \E m \in pend : Finish(m)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ EnvStep /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
