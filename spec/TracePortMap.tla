---------------------------- MODULE TracePortMap ----------------------------
(* Trace validation of PortMap.tla (spec/README.md "PortMap traces"): one
   direct endpoint's steps in a real run (-tags relaytrace, client/agent
   trace_portmap_on.go) must be a behaviour of PortMap: each Round (the
   protocol it asks first), each protocol's Mapped or NotMapped, the
   Close. Each line also says whether a delete of the held mapping went
   with it (del: a Mapped with another protocol than the held one, a
   Close holding one) and the lease asked (life: never 0 for a mapping). The gateway's protocols, its leases, its lost deletes and its
   changes are not logged: TLC takes Expire and GatewayChange only when
   the next logged step needs one, and picks the initial gateway.
   Accepted when TLC reaches the trace's end: TraceNotDone is then
   violated (scripts/spec.sh ptraces). *)
EXTENDS Json, PortMap, TLC, Sequences

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Round" -> Round /\ Order[ask'] = E.p
      [] E.ev = "Mapped" -> /\ Order[ask] = E.p /\ Mapped
                            /\ E.life > 0
                            /\ (held \in Protos /\ held # E.p => E.del)
      [] E.ev = "NotMapped" -> Order[ask] = E.p /\ NotMapped
      [] E.ev = "Close" -> Close /\ E.del = (held \in Protos)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ /\ ~ENABLED Step
          /\ GatewayChange \/ \E p \in Protos : Expire(p)
          /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
