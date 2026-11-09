---------------------------- MODULE A2ASession ----------------------------
(* A2A E2EE sessions (client/rpcclient a2a_e2ee_session.go; the message
   exchange is spec/proverif/a2a_machine.pv "Sessions"): the state the
   ProVerif model cannot hold. One caller, one callee, the relay between
   them able to drop, delay, duplicate and reorder every resume (net is a
   set: a resume sent stays deliverable, so every replay is in) and to
   forge the callee's answer to one (resumed and unknown are not sealed:
   a callee that lost the session has no key to seal with).

   A keyed handshake makes a session at both ends (Handshake, or Warm: a
   handshake with no call); a later call
   takes the caller's next call number on it (Resume) and sends its request
   with the resume; the callee takes a number once, above its window's
   floor, and serves the call (Deliver); a resume it does not take it
   answers unknown. The caller confirms on resumed (Confirm); on unknown,
   real or forged (Unknown), it handshakes once on that call, naming the
   resume it retries (sid, call number, when it was sent); the callee
   refuses that handshake when it took that call number (the relay forged
   the unknown: the request ran already), takes the number when it answers
   it (the resume, delivered later, is refused), and refuses it when the
   resume is older than the retry bound (Late).

   The replay record (lane A2AL1, nfltr
   docs/decisions/a2a-at-most-once-restart-2026-11-09.md): every call
   number the callee takes, it first writes durably to its record (rec), a
   restart keeps it; a record is kept while a retry naming it is within
   the bound (Forget). A retry of a session the callee no longer keeps
   (lost to a restart, expired, evicted) is answered by the record: refused
   when the number is in it, else taken. The callee may restart, also
   between writing the record and serving the call (Deliver, Finish); either
   end may drop a session at any time; the owner may revoke the machine.

   Invariants: AtMostOnce (a call is served at most once, a callee restart
   between serving it and its retry included: limit L1, closed by the
   record), NoKeyReuse (a call number is used once per
   session: a call's keys are HKDF(S, txn, c, dir), so no key and no nonce
   twice), RevokeEnds (nothing served after the revoke), OnceRetry (a call
   handshakes at most once after an unknown). Witnesses W_* must be
   violated. Mutants: counter-reset, no-window, restart-keeps-sessions
   (sessions persisted, their windows not), survive-revoke, retry-loop
   (an unknown after the handshake handshakes again), no-retry-check (the
   callee answers a retry without looking at the call number),
   retry-no-take (answering a retry does not take its call number),
   no-retry-bound (no bound on a retry's age: the record may have let its
   number go), record-in-memory (a restart loses the record: L1, the code
   before lane A2AL1), record-after-serve (the call is served before its
   record is durable), short-retention (the record forgets a number a
   retry within the bound may still name). *)
EXTENDS Naturals, FiniteSets

CONSTANTS Calls, MaxSess, W, Mutant

VARIABLES
    cs,        \* caller's session: [id |-> 0..MaxSess, next |-> Nat], id 0: none
    known,     \* callee: its sessions' ids
    hi, seen,  \* callee's window per session: highest number, numbers taken above the floor
    nsess,     \* sessions made so far (ids 1..nsess)
    net,       \* resumes sent: [s, c, k]
    used,      \* caller: [s, c] pairs used, with how often (a bag as a function)
    res,       \* per call: its resume [s, c] ([s |-> 0, c |-> 0]: none)
    st,        \* per call: "idle", "wait" (resumed, unanswered), "done", "failed"
    fresh,     \* per call: its resume is within the retry bound
    retries,   \* per call: handshakes after an unknown
    served,    \* per call: times served
    lost,      \* calls served before a callee restart, still waiting
    revoked, servedAfter,
    rec,       \* callee's replay record: the <<s, c>> it took (durable)
    pend       \* callee: resumes taken whose Deliver has not finished

vars == <<cs, known, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter, rec, pend>>

Ids == 1..MaxSess
Nums == 1..Cardinality(Calls) + 1
None == [s |-> 0, c |-> 0]

TypeOK ==
    /\ cs \in [id : 0..MaxSess, next : Nat]
    /\ known \subseteq Ids /\ nsess \in 0..MaxSess
    /\ hi \in [Ids -> Nat] /\ seen \in [Ids -> SUBSET Nat]
    /\ st \in [Calls -> {"idle", "wait", "done", "failed"}]
    /\ fresh \in [Calls -> BOOLEAN] /\ lost \subseteq Calls
    /\ retries \in [Calls -> Nat] /\ served \in [Calls -> Nat]
    /\ revoked \in BOOLEAN /\ servedAfter \in Nat
    /\ rec \subseteq Ids \X Nums /\ pend \subseteq net

Init ==
    /\ cs = [id |-> 0, next |-> 1]
    /\ known = {} /\ nsess = 0
    /\ hi = [s \in Ids |-> 0] /\ seen = [s \in Ids |-> {}]
    /\ net = {} /\ used = [p \in Ids \X Nums |-> 0]
    /\ res = [k \in Calls |-> None]
    /\ st = [k \in Calls |-> "idle"] /\ fresh = [k \in Calls |-> TRUE]
    /\ retries = [k \in Calls |-> 0] /\ served = [k \in Calls |-> 0]
    /\ lost = {} /\ revoked = FALSE /\ servedAfter = 0
    /\ rec = {} /\ pend = {}

Serve(k) ==
    /\ served' = [served EXCEPT ![k] = @ + 1]
    /\ servedAfter' = IF revoked THEN servedAfter + 1 ELSE servedAfter

\* A handshake (wire v2, injective by a2a_machine.pv 5-8): a fresh session
\* at both ends, the call served. For refuses a revoked machine.
HandshakeFor(k) ==
    /\ ~revoked /\ nsess < MaxSess
    /\ nsess' = nsess + 1
    /\ cs' = [id |-> nsess + 1, next |-> 1]
    /\ known' = known \cup {nsess + 1}
    /\ st' = [st EXCEPT ![k] = "done"]
    /\ Serve(k)

\* NewStream with no session (takeCall: none, expired, or its key no longer holds).
Handshake(k) ==
    /\ st[k] = "idle" /\ cs.id = 0
    /\ HandshakeFor(k)
    /\ UNCHANGED <<hi, seen, net, used, res, fresh, retries, lost, revoked, rec, pend>>

\* WarmA2AE2EE (lane A2AWARM): the handshake alone, with no call; the
\* session at both ends, nothing served. A no-op with a session.
Warm ==
    /\ cs.id = 0 /\ ~revoked /\ nsess < MaxSess
    /\ nsess' = nsess + 1
    /\ cs' = [id |-> nsess + 1, next |-> 1]
    /\ known' = known \cup {nsess + 1}
    /\ UNCHANGED <<hi, seen, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter, rec, pend>>

\* NewStream on the session: call number next (counter-reset: always 1).
Resume(k) ==
    /\ st[k] = "idle" /\ cs.id # 0 /\ ~revoked /\ cs.next \in Nums
    /\ net' = net \cup {[s |-> cs.id, c |-> cs.next, k |-> k]}
    /\ used' = [used EXCEPT ![<<cs.id, cs.next>>] = @ + 1]
    /\ res' = [res EXCEPT ![k] = [s |-> cs.id, c |-> cs.next]]
    /\ cs' = [cs EXCEPT !.next = IF Mutant = "counter-reset" THEN 1 ELSE @ + 1]
    /\ st' = [st EXCEPT ![k] = "wait"]
    /\ UNCHANGED <<known, hi, seen, nsess, fresh, retries, served, lost, revoked, servedAfter, rec, pend>>

Floor(s) == IF hi[s] > W THEN hi[s] - W ELSE 0

\* takeCallNumber's refusal: c is at or below the floor, or taken.
Taken(s, c) == c <= Floor(s) \/ c \in seen[s]

\* resume: the session known, the keyring's check, the window.
Takes(m) ==
    /\ m.s \in known
    /\ ~revoked \/ Mutant = "survive-revoke"
    /\ Mutant = "no-window" \/ ~Taken(m.s, m.c)

\* takeCallNumber: c taken on s, the floor moved up to it.
Take(s, c) ==
    LET h == IF c > hi[s] THEN c ELSE hi[s]
        f == IF h > W THEN h - W ELSE 0
    IN /\ hi' = [hi EXCEPT ![s] = h]
       /\ seen' = [seen EXCEPT ![s] = {n \in @ \cup {c} : n > f}]

\* The callee takes a resume and writes it to its record, durably; then
\* it serves the call (Finish; its answer, resumed, is the relay's to
\* deliver or replace). A restart in between: the call does not run, its
\* retry is refused. record-after-serve: it serves the call first and
\* writes the record at Finish.
Deliver(m) ==
    /\ m \in net /\ Takes(m)
    /\ Take(m.s, m.c)
    /\ pend' = pend \cup {m}
    /\ IF Mutant = "record-after-serve"
          THEN Serve(m.k) /\ UNCHANGED rec
          ELSE rec' = rec \cup {<<m.s, m.c>>} /\ UNCHANGED <<served, servedAfter>>
    /\ UNCHANGED <<cs, known, nsess, net, used, res, st, fresh, retries, lost, revoked>>

\* The second step of Deliver. A revoke ends a call taken and not yet
\* served (RecheckA2AE2EE).
Finish(m) ==
    /\ m \in pend /\ (~revoked \/ Mutant = "survive-revoke")
    /\ pend' = pend \ {m}
    /\ IF Mutant = "record-after-serve"
          THEN rec' = rec \cup {<<m.s, m.c>>} /\ UNCHANGED <<served, servedAfter>>
          ELSE Serve(m.k) /\ UNCHANGED rec
    /\ UNCHANGED <<cs, known, hi, seen, nsess, net, used, res, st, fresh, retries, lost, revoked>>

\* resumed reached the caller: only for a resume the callee took.
Confirm(k) ==
    /\ st[k] = "wait" /\ served[k] > 0
    /\ st' = [st EXCEPT ![k] = "done"]
    /\ UNCHANGED <<cs, known, hi, seen, nsess, net, used, res, fresh, retries, served, lost, revoked, servedAfter, rec, pend>>

\* The retry bound passed for k's resume.
Late(k) ==
    /\ fresh[k] /\ fresh' = [fresh EXCEPT ![k] = FALSE]
    /\ UNCHANGED <<cs, known, hi, seen, nsess, net, used, res, st, retries, served, lost, revoked, servedAfter, rec, pend>>

\* The record lets <<s, c>> go once no retry naming it is within the bound
\* (short-retention: while one may still be).
Forget(p) ==
    /\ p \in rec
    /\ Mutant = "short-retention" \/ \A k \in Calls : <<res[k].s, res[k].c>> = p => ~fresh[k]
    /\ rec' = rec \ {p}
    /\ UNCHANGED <<cs, known, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter, pend>>

\* The callee's check of a retry (handleE2EEInit): within the bound, and
\* not a call number taken: by the session's window when the callee keeps
\* the session, else by the record. Answering it takes the number, so the
\* resume, delivered late, is refused (retry-no-take: it is not).
RetryOK(k) ==
    /\ fresh[k] \/ Mutant = "no-retry-bound"
    /\ \/ Mutant = "no-retry-check"
       \/ IF res[k].s \in known
             THEN ~Taken(res[k].s, res[k].c)
             ELSE <<res[k].s, res[k].c>> \notin rec

\* unknown reached the caller, the callee's or forged: the caller drops
\* the session and handshakes once on the call (rehandshake); the callee
\* serves it when RetryOK, else the call fails (retry-loop: it goes on
\* waiting, to handshake again on the next unknown).
Unknown(k) ==
    /\ st[k] = "wait"
    /\ LET dropped == IF cs.id = res[k].s THEN [id |-> 0, next |-> 1] ELSE cs
           p == <<res[k].s, res[k].c>> IN
       \/ /\ ~revoked /\ nsess < MaxSess /\ RetryOK(k)
          /\ retries[k] = 0 \/ Mutant = "retry-loop"
          /\ retries' = [retries EXCEPT ![k] = @ + 1]
          /\ nsess' = nsess + 1
          /\ known' = known \cup {nsess + 1}
          /\ cs' = [id |-> nsess + 1, next |-> 1]
          /\ st' = [st EXCEPT ![k] = IF Mutant = "retry-loop" THEN "wait" ELSE "done"]
          /\ IF Mutant = "retry-no-take"
                THEN UNCHANGED <<hi, seen, rec>>
                ELSE /\ rec' = rec \cup {p}
                     /\ IF res[k].s \in known THEN Take(res[k].s, res[k].c) ELSE UNCHANGED <<hi, seen>>
          /\ Serve(k)
       \/ /\ (revoked \/ nsess = MaxSess \/ retries[k] > 0 \/ ~RetryOK(k))
          /\ cs' = dropped
          /\ st' = [st EXCEPT ![k] = "failed"]
          \* a handshake the callee refused counts too
          /\ retries' = IF ~revoked /\ nsess < MaxSess /\ (retries[k] = 0 \/ Mutant = "retry-loop")
                           THEN [retries EXCEPT ![k] = @ + 1] ELSE retries
          /\ UNCHANGED <<nsess, known, served, servedAfter, hi, seen, rec>>
    /\ UNCHANGED <<net, used, res, fresh, lost, revoked, pend>>

\* The callee restarts: its sessions go, its record stays, a call taken
\* and not yet finished goes (restart-keeps-sessions: sessions stay, their
\* windows do not; record-in-memory: the record goes too). lost: the calls
\* it served whose callers still wait.
Restart ==
    /\ known' = IF Mutant = "restart-keeps-sessions" THEN known ELSE {}
    /\ hi' = [s \in Ids |-> 0] /\ seen' = [s \in Ids |-> {}]
    /\ rec' = IF Mutant = "record-in-memory" THEN {} ELSE rec
    /\ pend' = {}
    /\ lost' = lost \cup {k \in Calls : st[k] = "wait" /\ served[k] > 0}
    /\ UNCHANGED <<cs, nsess, net, used, res, st, fresh, retries, served, revoked, servedAfter>>

ExpireCaller ==
    /\ cs.id # 0 /\ cs' = [id |-> 0, next |-> 1]
    /\ UNCHANGED <<known, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter, rec, pend>>

\* A callee keeps a session longer than the retry bound past its last
\* call (a2aSessionCalleeIdle > a2aResumeRetryBound + skew); a session it
\* no longer keeps, its retries are answered by the record.
ExpireCallee(s) ==
    /\ s \in known
    /\ \/ Mutant = "no-retry-bound"
       \/ \A k \in Calls : st[k] = "wait" /\ res[k].s = s => ~fresh[k]
    /\ known' = known \ {s}
    /\ UNCHANGED <<cs, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter, rec, pend>>

\* The owner revokes the machine: both keyrings refuse it from now on
\* (takeCall and resume check For/Valid; a revoked session is dropped).
Revoke ==
    /\ ~revoked /\ revoked' = TRUE
    /\ cs' = [id |-> 0, next |-> 1]
    /\ known' = IF Mutant = "survive-revoke" THEN known ELSE {}
    /\ UNCHANGED <<hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, servedAfter, rec, pend>>

Next ==
    \/ \E k \in Calls : Handshake(k) \/ Resume(k) \/ Confirm(k) \/ Unknown(k) \/ Late(k)
    \/ \E m \in net : Deliver(m) \/ Finish(m)
    \/ \E p \in rec : Forget(p)
    \/ Warm \/ Restart \/ ExpireCaller \/ \E s \in Ids : ExpireCallee(s)
    \/ Revoke

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
AtMostOnce == \A k \in Calls : served[k] <= 1
NoKeyReuse == \A p \in DOMAIN used : used[p] <= 1
RevokeEnds == servedAfter = 0
OnceRetry == \A k \in Calls : retries[k] <= 1

\* Witnesses (TLC must violate each): a resumed call confirmed, one served
\* after its handshake, one failed, a forged unknown on a served call
\* refused, a call served before a restart still waiting, and its retry
\* refused by the record after the restart.
W_Resumed == ~\E k \in Calls : st[k] = "done" /\ retries[k] = 0 /\ res[k] # None
W_Rehandshake == ~\E k \in Calls : st[k] = "done" /\ retries[k] = 1
W_Failed == ~\E k \in Calls : st[k] = "failed"
W_ForgedRefused == ~\E k \in Calls : st[k] = "failed" /\ served[k] = 1 /\ ~revoked
W_Lost == lost = {}
W_RestartRefused == ~\E k \in Calls : k \in lost /\ st[k] = "failed" /\ served[k] = 1 /\ ~revoked
=============================================================================
