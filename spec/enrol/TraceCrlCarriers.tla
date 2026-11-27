-------------------------- MODULE TraceCrlCarriers --------------------------
(* Trace check of CrlCarriers.tla's carrier steps (spec/enrol/README.md     *)
(* "Traces"), recorded by client/orgid and org/orgenrol (-tags enroltrace: *)
(* trace_on.go, <pid>.crlcarriers), one JSON line per step:                *)
(*   put      issuer directory d puts CRL num of issuer key k on the        *)
(*            relay's copy (PutCopy; logged before it is sent)              *)
(*   publish  d published CRL num on the mailbox (Publish)                  *)
(*   take     member v's take of a CRL message through carrier via          *)
(*            ("mailbox": Push, "copy": ReadCopy) at t: res taken, same     *)
(*            (the CRL held already) or refused                             *)
(* RevocationBound: a CRL taken, whatever its carrier, is not past its      *)
(* NextUpdate (stale-copy). RevokedMachineRefused: a CRL taken is newer     *)
(* than every CRL v took of k before, whatever carried either               *)
(* (copy-rollback). PutBeforePublish: once d puts copies, a CRL it          *)
(* publishes was put first (a mailbox failure never holds the copy back).  *)
(* Known: a line maps to an action. TraceDone is violated when every line  *)
(* was read: accepted.                                                       *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, held, put, bad

vars == <<l, held, put, bad>>

\* held: <<v, k>> -> the Number v took last; put: <<d, k, num>> put.
Init == l = 1 /\ held = [x \in {} |-> 0] /\ put = {} /\ bad = {}

E == Log[l]
HK == <<E.v, E.k>>
Held == IF HK \in DOMAIN held THEN held[HK] ELSE 0

TakeBad ==
    CASE E.via \notin {"mailbox", "copy"} \/ E.res \notin {"taken", "same", "refused"} -> {"Known"}
      [] E.res = "taken" /\ E.next <= E.t -> {"RevocationBound"}
      [] E.res = "taken" /\ E.num <= Held -> {"RevokedMachineRefused"}
      [] OTHER -> {}

Step ==
    /\ l <= Len(Log)
    /\ l' = l + 1
    /\ CASE E.ev = "put" ->
                /\ put' = put \cup {<<E.d, E.k, E.num>>}
                /\ UNCHANGED <<held, bad>>
         [] E.ev = "publish" ->
                /\ bad' = IF (\E p \in put : p[1] = E.d) /\ <<E.d, E.k, E.num>> \notin put
                          THEN bad \cup {"PutBeforePublish"} ELSE bad
                /\ UNCHANGED <<held, put>>
         [] E.ev = "take" ->
                /\ bad' = bad \cup TakeBad
                /\ held' = IF E.res = "taken" THEN (HK :> E.num) @@ held ELSE held
                /\ UNCHANGED put
         [] OTHER ->
                /\ bad' = bad \cup {"Known"}
                /\ UNCHANGED <<held, put>>

Next == Step

RevocationBound == "RevocationBound" \notin bad
RevokedMachineRefused == "RevokedMachineRefused" \notin bad
PutBeforePublish == "PutBeforePublish" \notin bad
Known == "Known" \notin bad
TraceDone == l <= Len(Log)
=============================================================================
