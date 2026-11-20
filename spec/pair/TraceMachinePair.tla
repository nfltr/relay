-------------------------- MODULE TraceMachinePair --------------------------
(* Trace check (spec/pair/README.md "Traces"): client/pairfile's steps as  *)
(* the code recorded them (-tags pairtrace: trace_on.go, PAIRTRACE=<dir>),  *)
(* one JSON line each, with the files as the step left them:               *)
(*   ev   lock, recover, next, cert, swap (MachinePair.tla's writer), or   *)
(*        read (the reader took a pair; from: "key" or "next")            *)
(*   ck   the certificate certifies machine.key                            *)
(*   cn   ... certifies machine.key.next                                   *)
(*   nx   machine.key.next exists                                          *)
(* Read in order, each line must be one of MachinePair.tla's steps from   *)
(* the step before (a lock at any point: the writer before it stopped,    *)
(* MachinePair.tla Crash), leave the files as that step does, and leave a *)
(* usable pair (Usable). TraceDone is violated when every line was read:  *)
(* accepted.                                                               *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, pc, bad

vars == <<l, pc, bad>>

Init == l = 1 /\ pc = "idle" /\ bad = {}

E == Log[l]
\* the step before, and what the files are after it
From == [lock |-> {"idle", "locked", "ready", "nexted", "certed"},
         recover |-> {"locked"}, next |-> {"ready"}, cert |-> {"nexted"}, swap |-> {"certed"}]
To == [lock |-> "locked", recover |-> "ready", next |-> "nexted", cert |-> "certed", swap |-> "idle"]
Leaves ==
    CASE E.ev = "lock" -> TRUE
      [] E.ev = "recover" -> ~(~E.ck /\ E.cn /\ E.nx)
      [] E.ev = "next" -> E.nx
      [] E.ev = "cert" -> E.cn /\ E.nx
      [] E.ev = "swap" -> E.ck /\ ~E.nx
      [] E.ev = "read" -> IF E.from = "next" THEN E.cn /\ E.nx ELSE E.ck

Bad ==
    IF ~(E.ev \in {"lock", "recover", "next", "cert", "swap", "read"}) THEN {"diverged"}
    ELSE (IF E.ev # "read" /\ ~(pc \in From[E.ev]) THEN {"order"} ELSE {})
         \cup (IF ~Leaves THEN {"order"} ELSE {})
         \cup (IF ~(E.ck \/ (E.cn /\ E.nx)) THEN {"unusable"} ELSE {})

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ pc' = IF E.ev \in DOMAIN To THEN To[E.ev] ELSE pc
    /\ bad' = bad \cup {<<b, l>> : b \in Bad}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
Ordered == None({"order"})
Usable == None({"unusable"})
TraceDone == l <= Len(Log)
=============================================================================
