---------------------------- MODULE MoveAudit ----------------------------
\* The session audit across an organisation move (relay org/orgissuer
\* bundle.go, org/orgenrol audit.go; nfltr
\* docs/decisions/service-access-2026-11-25.md "SA5 gaps" (d)): a machine
\* posts its audit lines to the issuer and moves its cursor (sessions.sent)
\* past the lines an answer acknowledges; the issuer's held lines and per
\* log positions (sessions.jsonl, sessions-heads.json) are issuer state, so
\* they move in the bundle (spec/orgmove/OrgMove.tla Send, Import), and the
\* issuer takes no audit post after its fence (OrgMove.tla Serving): the
\* post stays unanswered, the new machine answers it.
\* OrgMove.tla owns the move itself (one issuer, the fence, the import);
\* here only what the audit needs of it: the bundle is made under the
\* directory's lock after the fence, and a host serves until its fence.
EXTENDS Integers, FiniteSets

CONSTANTS
    NH,        \* hosts 1..NH; host 1 holds the organisation at first
    MaxLines,  \* lines the machine writes (state bound)
    Mutant

Hosts == 1..NH
None == [none |-> TRUE]

VARIABLES
    lines,    \* the machine wrote lines 1..lines
    acked,    \* the machine's cursor: the issuer answered up to here
    dir,      \* dir[h]: None or [held, fenced, to]: h's issuer directory
    bundles,  \* the bundles in flight: [to, held]
    gap       \* a serving issuer took lines after a hole (a "gap" finding)

vars == <<lines, acked, dir, bundles, gap>>

Has(h) == dir[h] # None
\* take-after-fence: the old issuer answers audit posts after its fence.
Takes(h) == Has(h) /\ (~dir[h].fenced \/ Mutant = "take-after-fence")
Serving(h) == Has(h) /\ ~dir[h].fenced

TypeOK ==
    /\ lines \in 0..MaxLines /\ acked \in 0..lines
    /\ \A h \in Hosts : dir[h] = None \/ (dir[h].held \in 0..MaxLines /\ dir[h].fenced \in BOOLEAN)
    /\ gap \in BOOLEAN

Init ==
    /\ lines = 0 /\ acked = 0 /\ gap = FALSE /\ bundles = {}
    /\ dir = [h \in Hosts |-> IF h = 1 THEN [held |-> 0, fenced |-> FALSE, to |-> 0] ELSE None]

\* A session's line, in the machine's log.
Write ==
    /\ lines < MaxLines
    /\ lines' = lines + 1
    /\ UNCHANGED <<acked, dir, bundles, gap>>

\* The keeper posts lines acked+1..n (the complete lines it read, n <=
\* lines); issuer h appends them (a hole before them is a gap) and
\* answers, or the answer is lost (answered FALSE): the next post repeats
\* the lines, which h holds already.
Take(h, n, answered) ==
    /\ Takes(h) /\ n \in acked + 1..lines
    /\ gap' = (gap \/ dir[h].held < acked)
    /\ dir' = [dir EXCEPT ![h].held = IF @ >= n THEN @ ELSE n]
    /\ acked' = IF answered THEN n ELSE acked
    /\ UNCHANGED <<lines, bundles>>

\* nfltr org move send: the fence, then (under the same lock, and again
\* until the recipient serves) the bundle with the sessions files
\* (bundle-no-sessions: without them, the code before).
Fence(h, r) ==
    /\ Serving(h) /\ r # h /\ ~Has(r)
    /\ dir' = [dir EXCEPT ![h].fenced = TRUE, ![h].to = r]
    /\ UNCHANGED <<lines, acked, bundles, gap>>
Send(h) ==
    /\ Has(h) /\ dir[h].fenced
    /\ bundles' = bundles \cup {[to |-> dir[h].to, held |-> IF Mutant = "bundle-no-sessions" THEN 0 ELSE dir[h].held]}
    /\ UNCHANGED <<lines, acked, dir, gap>>

\* nfltr org move receive.
Import(r, b) ==
    /\ b \in bundles /\ b.to = r /\ ~Has(r)
    /\ dir' = [dir EXCEPT ![r] = [held |-> b.held, fenced |-> FALSE, to |-> 0]]
    /\ bundles' = bundles \ {b}
    /\ UNCHANGED <<lines, acked, gap>>

Next ==
    \/ Write
    \/ \E h \in Hosts, n \in 1..MaxLines, a \in BOOLEAN : Take(h, n, a)
    \/ \E h, r \in Hosts : Fence(h, r)
    \/ \E h \in Hosts : Send(h)
    \/ \E r \in Hosts, b \in bundles : Import(r, b)

Spec == Init /\ [][Next]_vars

\* Every line the machine was answered for is held by the serving issuer.
AckedHeld == \A h \in Hosts : Serving(h) => dir[h].held >= acked

\* No move makes a serving issuer report a gap.
NoGap == ~gap

\* Witnesses (each must be violated: reachable).
W_TakenAfterMove == ~\E h \in Hosts : h # 1 /\ Serving(h) /\ acked = MaxLines /\ dir[h].held = MaxLines /\ dir[1] # None /\ dir[1].held < MaxLines
W_AckedBeforeMove == ~\E h \in Hosts : h # 1 /\ Serving(h) /\ acked > 0 /\ dir[h].held = acked
=============================================================================
