-------------------------- MODULE TraceRevokePush --------------------------
(* Trace check of the issuer service's RevokePush.tla steps                 *)
(* (spec/enrol/README.md "Traces"), recorded by org/orgenrol (-tags         *)
(* enroltrace: trace_on.go), one JSON line per step of the issuer          *)
(* directory d, for a CRL of issuer key k, num its Number (a rotation's     *)
(* new issuer numbers afresh):                                             *)
(*   notice   a file-change notice; num: the CRL then in the directory      *)
(*            (Revoke's write, and the notice it makes)                     *)
(*   read     maintain read CRL num under the directory's lock (Read)       *)
(*   publish  it published CRL num to the relay (Publish)                   *)
(* ReadSeesNotice: a read after a notice reads that write or a newer one    *)
(* (the notice is logged after its write, the read under the lock).        *)
(* PublishesRead: the CRL published is the one the round read.             *)
(* A line of another kind maps to no action (Known). TraceDone is violated *)
(* when every line was read: accepted.                                       *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, noticed, lastRead, bad

vars == <<l, noticed, lastRead, bad>>

\* noticed: <<d, k>> -> the newest CRL noticed; lastRead: d -> the CRL its
\* round read last.
Init == l = 1 /\ noticed = [x \in {} |-> 0] /\ lastRead = [x \in {} |-> 0] /\ bad = {}

E == Log[l]
DK == <<E.d, E.k>>
Noticed == IF DK \in DOMAIN noticed THEN noticed[DK] ELSE 0
LastRead == IF E.d \in DOMAIN lastRead THEN lastRead[E.d] ELSE [k |-> "", num |-> -1]

Step ==
    /\ l <= Len(Log)
    /\ l' = l + 1
    /\ CASE E.ev = "notice" ->
                /\ noticed' = (DK :> IF E.num > Noticed THEN E.num ELSE Noticed) @@ noticed
                /\ UNCHANGED <<lastRead, bad>>
         [] E.ev = "read" ->
                /\ lastRead' = (E.d :> [k |-> E.k, num |-> E.num]) @@ lastRead
                /\ bad' = IF E.num < Noticed THEN bad \cup {"ReadSeesNotice"} ELSE bad
                /\ UNCHANGED noticed
         [] E.ev = "publish" ->
                /\ bad' = IF [k |-> E.k, num |-> E.num] # LastRead THEN bad \cup {"PublishesRead"} ELSE bad
                /\ UNCHANGED <<noticed, lastRead>>
         [] OTHER ->
                /\ bad' = bad \cup {"Known"}
                /\ UNCHANGED <<noticed, lastRead>>

Next == Step

ReadSeesNotice == "ReadSeesNotice" \notin bad
PublishesRead == "PublishesRead" \notin bad
Known == "Known" \notin bad
TraceDone == l <= Len(Log)
=============================================================================
