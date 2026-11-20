----------------------------- MODULE TraceJoin -----------------------------
(* Trace check of Join.tla's machine side (spec/enrol/README.md "Traces"): *)
(* the lines org/orgenrol's Join records (-tags enroltrace: trace_on.go)    *)
(* beside the issuer's (TraceEnrol.tla checks those, Join.tla's Issue       *)
(* rules among them), read in order:                                        *)
(*   jroot   the join's check of the root the relay gave: own (the pinned  *)
(*           root, or one the pinned recovery key certifies), ok (taken)    *)
(*           (Start's Trusts)                                               *)
(*   jstart  machine m's run asks for token tok with key k, under request  *)
(*           id run; first: the first run's id (Start)                      *)
(*   jend    the run ended: joined by answer id for key ak (Install),       *)
(*           refused (Install of a refusal), failed (GiveUp)                *)
(* A line of another kind the issuer or a verifier writes is no step here; *)
(* a kind no recorder writes is diverged (Conforms). TraceDone is violated *)
(* when every line was read: accepted.                                      *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, kept, runs, bad

vars == <<l, kept, runs, bad>>

Init ==
    /\ l = 1
    /\ kept = [x \in {} |-> 0]  \* <<org, machine, token>> -> [k, first]: the key a join keeps for its token
    /\ runs = [x \in {} |-> 0]  \* <<org, machine, token>> -> [k, run, first]: a run under way
    /\ bad = {}

E == Log[l]
JK == <<E.o, E.m, E.tok>>

\* Lines TraceEnrol.tla and TraceOrgHosted.tla read: no step of the join.
Others == {"issue", "refuse", "revoke", "rebind", "crl", "take", "rotate", "check", "itake"}

\* Start's Trusts: the owner's roots, and only those, are taken.
RootBad ==
    CASE E.ok /\ ~E.own -> {"any-root"}
      [] E.own /\ ~E.ok -> {"pin-root-only"}
      [] OTHER -> {}

\* Start: a run asks with the key the join keeps for the token (a new one
\* only when it keeps none), and names the first run's request.
StartBad ==
    CASE JK \in DOMAIN runs -> {"diverged"}
      [] JK \in DOMAIN kept -> (IF kept[JK].k # E.k THEN {"new-key-per-join"} ELSE {})
                               \cup (IF kept[JK].first # E.first THEN {"diverged"} ELSE {})
      [] OTHER -> IF E.first # E.run THEN {"diverged"} ELSE {}

\* Install: the answer to this run's request or the first run's, for the
\* key it asked with.
EndBad ==
    CASE JK \notin DOMAIN runs -> {"diverged"}
      [] E.res = "joined" ->
            IF E.id \in {runs[JK].run, runs[JK].first} /\ E.ak = runs[JK].k THEN {} ELSE {"diverged"}
      [] E.res \in {"refused", "failed"} -> {}
      [] OTHER -> {"diverged"}

Drop(f, k) == [x \in DOMAIN f \ {k} |-> f[x]]

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ kept' = CASE E.ev = "jstart" -> (JK :> [k |-> E.k, first |-> E.first]) @@ kept
                 [] E.ev = "jend" /\ E.res \in {"joined", "refused"} -> Drop(kept, JK)
                 [] OTHER -> kept
    /\ runs' = CASE E.ev = "jstart" -> (JK :> [k |-> E.k, run |-> E.run, first |-> E.first]) @@ runs
                 [] E.ev = "jend" -> Drop(runs, JK)
                 [] OTHER -> runs
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev = "jroot" -> RootBad
                  [] E.ev = "jstart" -> StartBad
                  [] E.ev = "jend" -> EndBad
                  [] E.ev \in Others -> {}
                  [] OTHER -> {"diverged"}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
\* Join.tla's: a lost or late answer never burns the name (the run asks
\* with its kept key), a rotation never strands a join (a root the pinned
\* recovery key certifies is taken); only the owner's roots are taken.
RefusedOnlyForCause == None({"new-key-per-join", "pin-root-only"})
JoinRootsAreOwners == None({"any-root"})
TraceDone == l <= Len(Log)
=============================================================================
