---------------------------- MODULE AuditLog ----------------------------
\* A machine's session audit log (relay org/orgmachine audit.go; nfltr
\* docs/decisions/service-access-2026-11-25.md "SA5", "SA5 gaps"): every
\* process of the machine appends a session's open and close lines to one
\* file under one lock; the keeper ships the lines and the issuer
\* acknowledges a prefix. Two gaps closed here:
\*   (c) a killed process leaves an open with no close. Each process holds
\*       an owner file (its lock held for its life) listing the sessions it
\*       opened, written BEFORE the open line and pruned AFTER the close
\*       line. Any later process of the machine finds an owner file whose
\*       lock it can take (its process is gone) and, under the log's lock,
\*       writes a "lost" close for each listed session whose open is in the
\*       file and whose close is not; then deletes the owner file. The log is
\*       the truth; the owner file only says whose sessions they were.
\*   (a) the file is rotated: a prefix of lines the issuer acknowledged is
\*       dropped, never the last line (the next line chains to it: the same
\*       log goes on) and never an open whose close is not yet written
\*       (recovery reads it).
\* A process may crash between any two steps (Crash), also while it holds
\* the lock (flock is released with the process).
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Procs,     \* process incarnations of the machine (each runs once)
    MayCrash,  \* the ones that may be killed
    Sess,      \* session ids
    MaxRot,    \* rotations (state bound)
    Mutant

None == "none"

VARIABLES
    log,    \* every line the machine ever wrote, in order: [k, s, lost]
    base,   \* the local file holds log[base..Len(log)] (rotation dropped the rest)
    acked,  \* the issuer holds log[1..acked]
    logs,   \* log ids started (a line appended to an empty file starts one)
    st,     \* st[p]: "idle" (not started), "up", "dead"
    of,     \* of[p]: p's owner file exists
    owner,  \* owner[p]: the sessions p's owner file lists
    ses,    \* ses[s]: "new", "intent", "open", "closing", "done" (its owner's progress)
    who,    \* who[s]: the process that opened s
    lock,   \* the log's lock: a process or None
    rots

vars == <<log, base, acked, logs, st, of, owner, ses, who, lock, rots>>

Idx(k, s) == {i \in 1..Len(log) : log[i].k = k /\ log[i].s = s}
InFile(i) == i >= base
Closes(s) == Idx("close", s)
OpenInFile(s) == \E i \in Idx("open", s) : InFile(i)
ClosedInFile(s) == \E i \in Closes(s) : InFile(i)
\* Recovery writes a close for s: its open is in the file, its close is not
\* (recover-no-log-check: every listed session).
NeedsClose(s) == IF Mutant = "recover-no-log-check" THEN TRUE ELSE OpenInFile(s) /\ ~ClosedInFile(s)
\* q's process is gone: its owner lock can be taken (recover-live: any other).
Gone(q) == IF Mutant = "recover-live" THEN st[q] # "idle" ELSE st[q] = "dead"

TypeOK ==
    /\ base \in 1..Len(log) + 1 /\ acked \in 0..Len(log)
    /\ st \in [Procs -> {"idle", "up", "dead"}]
    /\ of \in [Procs -> BOOLEAN] /\ owner \in [Procs -> SUBSET Sess]
    /\ ses \in [Sess -> {"new", "intent", "open", "closing", "done"}]
    /\ who \in [Sess -> Procs \cup {None}]
    /\ lock \in Procs \cup {None}

Init ==
    /\ log = <<>> /\ base = 1 /\ acked = 0 /\ logs = 0
    /\ st = [p \in Procs |-> "idle"] /\ of = [p \in Procs |-> FALSE]
    /\ owner = [p \in Procs |-> {}]
    /\ ses = [s \in Sess |-> "new"] /\ who = [s \in Sess |-> None]
    /\ lock = None /\ rots = 0

\* AppendAudit: a line after the file's last; to an empty file, a new log.
Write(l) ==
    /\ log' = Append(log, l)
    /\ logs' = IF base > Len(log) THEN logs + 1 ELSE logs

Start(p) ==
    /\ st[p] = "idle"
    /\ st' = [st EXCEPT ![p] = "up"] /\ of' = [of EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<log, base, acked, logs, owner, ses, who, lock, rots>>

\* A session admitted: under the lock, the owner file lists it first ...
Intent(p, s) ==
    /\ st[p] = "up" /\ lock = None /\ ses[s] = "new"
    /\ lock' = p /\ ses' = [ses EXCEPT ![s] = "intent"] /\ who' = [who EXCEPT ![s] = p]
    /\ IF Mutant = "open-before-intent"
       THEN Write([k |-> "open", s |-> s, lost |-> FALSE]) /\ UNCHANGED owner
       ELSE owner' = [owner EXCEPT ![p] = @ \cup {s}] /\ UNCHANGED <<log, logs>>
    /\ UNCHANGED <<base, acked, st, of, rots>>

\* ... then its open line, and the lock is released.
OpenLine(p, s) ==
    /\ st[p] = "up" /\ lock = p /\ ses[s] = "intent" /\ who[s] = p
    /\ IF Mutant = "open-before-intent"
       THEN owner' = [owner EXCEPT ![p] = @ \cup {s}] /\ UNCHANGED <<log, logs>>
       ELSE Write([k |-> "open", s |-> s, lost |-> FALSE]) /\ UNCHANGED owner
    /\ lock' = None /\ ses' = [ses EXCEPT ![s] = "open"]
    /\ UNCHANGED <<base, acked, st, of, who, rots>>

\* The session ended: under the lock its close line, then the owner file
\* forgets it.
CloseLine(p, s) ==
    /\ st[p] = "up" /\ lock = None /\ ses[s] = "open" /\ who[s] = p
    /\ Write([k |-> "close", s |-> s, lost |-> FALSE])
    /\ lock' = p /\ ses' = [ses EXCEPT ![s] = "closing"]
    /\ UNCHANGED <<base, acked, st, of, owner, who, rots>>

Forget(p, s) ==
    /\ st[p] = "up" /\ lock = p /\ ses[s] = "closing" /\ who[s] = p
    /\ owner' = [owner EXCEPT ![p] = @ \ {s}]
    /\ lock' = None /\ ses' = [ses EXCEPT ![s] = "done"]
    /\ UNCHANGED <<log, base, acked, logs, st, of, who, rots>>

\* The process is killed: its flocks go with it, its files stay.
Crash(p) ==
    /\ st[p] = "up" /\ p \in MayCrash
    /\ st' = [st EXCEPT ![p] = "dead"]
    /\ lock' = IF lock = p THEN None ELSE lock
    /\ UNCHANGED <<log, base, acked, logs, of, owner, ses, who, rots>>

\* A live process (its keeper's round) finds q's owner file free: one lost
\* close per listed session the file has open (no-recovery: never).
Recover(p, q, s) ==
    /\ Mutant # "no-recovery"
    /\ st[p] = "up" /\ q # p /\ Gone(q) /\ of[q] /\ lock = None
    /\ s \in owner[q] /\ NeedsClose(s)
    /\ Write([k |-> "close", s |-> s, lost |-> TRUE])
    /\ UNCHANGED <<base, acked, st, of, owner, ses, who, lock, rots>>

\* ... and, every listed session closed or never opened, deletes the file.
RecoverDone(p, q) ==
    /\ Mutant # "no-recovery"
    /\ st[p] = "up" /\ q # p /\ Gone(q) /\ of[q] /\ lock = None
    /\ \A s \in owner[q] : ~(OpenInFile(s) /\ ~ClosedInFile(s))
    /\ of' = [of EXCEPT ![q] = FALSE] /\ owner' = [owner EXCEPT ![q] = {}]
    /\ UNCHANGED <<log, base, acked, logs, st, ses, who, lock, rots>>

\* The keeper's post answered: the issuer holds every line written so far
\* (it reads complete lines, no lock).
Ship ==
    /\ acked < Len(log)
    /\ acked' = Len(log)
    /\ UNCHANGED <<log, base, logs, st, of, owner, ses, who, lock, rots>>

\* The keeper rotates the file under the lock: drops log[base..b-1].
\* rotate-unacked: lines the issuer lacks; rotate-all: the last line too;
\* rotate-drops-open: an open still without its close.
Droppable(b) ==
    /\ b > base
    /\ b <= acked + 1 \/ Mutant = "rotate-unacked"
    /\ b <= Len(log) \/ (Mutant = "rotate-all" /\ b = Len(log) + 1)
    /\ Mutant = "rotate-drops-open" \/
       \A i \in base..b - 1 : log[i].k = "open" => Closes(log[i].s) # {}
Rotate(p) ==
    /\ st[p] = "up" /\ lock = None /\ rots < MaxRot
    /\ \E b \in 1..Len(log) + 1 : Droppable(b) /\ base' = b
    /\ rots' = rots + 1
    /\ UNCHANGED <<log, acked, logs, st, of, owner, ses, who, lock>>

Next ==
    \/ \E p \in Procs : Start(p) \/ Crash(p) \/ Rotate(p)
    \/ \E p \in Procs, s \in Sess : Intent(p, s) \/ OpenLine(p, s) \/ CloseLine(p, s) \/ Forget(p, s)
    \/ \E p, q \in Procs, s \in Sess : Recover(p, q, s)
    \/ \E p, q \in Procs : RecoverDone(p, q)
    \/ Ship

Spec == Init /\ [][Next]_vars

\* Fair: every process starts, a session of a live process ends, the
\* keepers recover and ship. MayCrash # Procs: some process stays up.
LiveSpec == Spec
    /\ (\A p \in Procs : WF_vars(Start(p)))
    /\ (\A p \in Procs, s \in Sess : WF_vars(OpenLine(p, s)) /\ WF_vars(CloseLine(p, s)) /\ WF_vars(Forget(p, s)))
    /\ (\A p, q \in Procs, s \in Sess : WF_vars(Recover(p, q, s)))
    /\ (\A p, q \in Procs : WF_vars(RecoverDone(p, q)))
    /\ WF_vars(Ship)

----------------------------------------------------------------------------
\* Safety.

\* A session has at most one close.
AtMostOneClose == \A s \in Sess : Cardinality(Closes(s)) <= 1

\* Every close follows its open.
CloseHasOpen == \A s \in Sess : \A i \in Closes(s) : \E j \in Idx("open", s) : j < i

\* A session its live process still serves is not recorded closed.
LiveOpenNotClosed == \A s \in Sess : (ses[s] = "open" /\ st[who[s]] = "up") => Closes(s) = {}

\* Rotation drops only what the issuer holds.
NothingLost == base <= acked + 1

\* The machine keeps one log: rotation never starts a new one.
OneLog == logs <= 1

\* Liveness (LiveSpec): every open is closed, also a killed process's.
EveryOpenCloses == \A s \in Sess : (Idx("open", s) # {}) ~> (Closes(s) # {})

\* Witnesses (each must be violated: reachable).
W_LostClose == ~\E i \in 1..Len(log) : log[i].lost
\* A process killed between its close line and its owner file's prune:
\* recovery finds the close and writes none.
W_CloseThenKilled == ~\E p \in Procs, s \in Sess : st[p] = "dead" /\ s \in owner[p] /\ Closes(s) # {} /\ of[p] /\ ses[s] = "closing"
\* ... between its owner file's line and its open line: nothing to close.
W_IntentOnly == ~\E p \in Procs, s \in Sess : st[p] = "dead" /\ ses[s] = "intent" /\ who[s] = p /\ ~of[p]
W_Rotated == ~(base > 1 /\ Len(log) >= base + 1)
=============================================================================
