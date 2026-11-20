---------------------------- MODULE TraceOrgMove ----------------------------
(* Trace check (spec/orgmove/README.md "Traces"): the issuer's commits and  *)
(* a move's sends as the code recorded them (org/orgpki,   *)
(* -tags enroltrace: trace_on.go, ORGMOVETRACE=<dir>), one JSON line each:  *)
(*   act     an issuer of organisation o committed a log line of hash h     *)
(*           after the line of hash p (act: its act; num: a CRL's Number)   *)
(*   fence   ... the move's fence naming receive key k (OrgMove.tla Fence)  *)
(*   import  ... the arrival naming receive key k (Import)                  *)
(*   send    the old machine sealed its log of head h to receive key k     *)
(*           (Send)                                                        *)
(* Read in order, each line must keep OrgMove.tla's properties as far as   *)
(* one process sees them: one history (no two lines after the same p:      *)
(* AtMostOneIssuer, AuditContinuous), nothing after a fence but its        *)
(* arrival (OldCannotIssue), an import and a send only of a fence naming    *)
(* their key (import-unfenced, fence-names-no-recipient), CRL Numbers that *)
(* only grow (CRLMonotone). A restore from a backup (OrgMove.tla Revive:   *)
(* act restored, num the published CRL's Number it took) continues an      *)
(* older line, the lost machine's after it lost: no fork, but its Number   *)
(* must be at least every one before (restore-behind). TraceDone is        *)
(* violated when every line was read: accepted.                            *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, line, parents, crl, bad

vars == <<l, line, parents, crl, bad>>

Init ==
    /\ l = 1
    /\ line = [x \in {} |-> 0]   \* hash -> [act, k]: the lines committed
    /\ parents = {}              \* the hashes a line was committed after
    /\ crl = [x \in {} |-> 0]    \* org -> its last CRL Number
    /\ bad = {}

E == Log[l]
Commit == E.ev \in {"act", "fence", "import"}
After == E.p \in DOMAIN line
Fenced(h, k) == h \in DOMAIN line /\ line[h].act = "moved" /\ line[h].k = k

Bad ==
    CASE ~(E.ev \in {"act", "fence", "import", "send"}) -> {"diverged"}
      [] E.ev = "send" -> IF Fenced(E.h, E.k) THEN {} ELSE {"send-unfenced"}
      [] OTHER ->
            (IF E.p \in parents /\ E.act # "restored" THEN {"fork"} ELSE {})
            \cup (IF After /\ line[E.p].act = "moved" /\ E.ev # "import" THEN {"after-fence"} ELSE {})
            \cup (IF E.ev = "import" /\ ~Fenced(E.p, E.k) THEN {"import-unfenced"} ELSE {})
            \cup (IF E.act = "crl" /\ E.o \in DOMAIN crl /\ E.num <= crl[E.o] THEN {"crl-back"} ELSE {})
            \cup (IF E.act = "restored" /\ E.o \in DOMAIN crl /\ E.num < crl[E.o] THEN {"restore-behind"} ELSE {})

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ line' = IF Commit THEN (E.h :> [act |-> E.act, k |-> E.k]) @@ line ELSE line
    /\ parents' = IF Commit THEN parents \cup {E.p} ELSE parents
    /\ crl' = IF Commit /\ E.act \in {"crl", "restored"} THEN (E.o :> E.num) @@ crl ELSE crl
    /\ bad' = bad \cup {<<b, l>> : b \in Bad}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
AtMostOneIssuer == None({"fork"})
OldCannotIssue == None({"after-fence"})
ImportFenced == None({"import-unfenced", "send-unfenced"})
CRLMonotone == None({"crl-back", "restore-behind"})
TraceDone == l <= Len(Log)
=============================================================================
