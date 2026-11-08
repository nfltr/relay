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
   it (the resume, delivered later, is refused), and refuses it when the resume is older than
   the retry bound (Late: a callee keeps a session past that bound since
   its last call, so a callee that no longer knows the session lost it to
   a restart). The callee may restart, either end may let a session expire,
   the owner may revoke the machine.

   Invariants: AtMostOnce (a call is served at most once, unless the callee
   restarted between serving it and its retry: lost, nfltr's decision doc
   "Session reuse" limit L1), NoKeyReuse (a call number is used once per
   session: a call's keys are HKDF(S, txn, c, dir), so no key and no nonce
   twice), RevokeEnds (nothing served after the revoke), OnceRetry (a call
   handshakes at most once after an unknown). Witnesses W_* must be
   violated. Mutants: counter-reset, no-window, restart-keeps-sessions
   (sessions persisted, their windows not), survive-revoke, retry-loop
   (an unknown after the handshake handshakes again), no-retry-check (the
   callee answers a retry without looking at the call number),
   retry-no-take (answering a retry does not take its call number),
   no-retry-bound (no bound on a retry's age: the callee may have let the
   session expire). *)
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
    revoked, servedAfter

vars == <<cs, known, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter>>

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

Init ==
    /\ cs = [id |-> 0, next |-> 1]
    /\ known = {} /\ nsess = 0
    /\ hi = [s \in Ids |-> 0] /\ seen = [s \in Ids |-> {}]
    /\ net = {} /\ used = [p \in Ids \X Nums |-> 0]
    /\ res = [k \in Calls |-> None]
    /\ st = [k \in Calls |-> "idle"] /\ fresh = [k \in Calls |-> TRUE]
    /\ retries = [k \in Calls |-> 0] /\ served = [k \in Calls |-> 0]
    /\ lost = {} /\ revoked = FALSE /\ servedAfter = 0

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
    /\ UNCHANGED <<hi, seen, net, used, res, fresh, retries, lost, revoked>>

\* WarmA2AE2EE (lane A2AWARM): the handshake alone, with no call; the
\* session at both ends, nothing served. A no-op with a session.
Warm ==
    /\ cs.id = 0 /\ ~revoked /\ nsess < MaxSess
    /\ nsess' = nsess + 1
    /\ cs' = [id |-> nsess + 1, next |-> 1]
    /\ known' = known \cup {nsess + 1}
    /\ UNCHANGED <<hi, seen, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter>>

\* NewStream on the session: call number next (counter-reset: always 1).
Resume(k) ==
    /\ st[k] = "idle" /\ cs.id # 0 /\ ~revoked /\ cs.next \in Nums
    /\ net' = net \cup {[s |-> cs.id, c |-> cs.next, k |-> k]}
    /\ used' = [used EXCEPT ![<<cs.id, cs.next>>] = @ + 1]
    /\ res' = [res EXCEPT ![k] = [s |-> cs.id, c |-> cs.next]]
    /\ cs' = [cs EXCEPT !.next = IF Mutant = "counter-reset" THEN 1 ELSE @ + 1]
    /\ st' = [st EXCEPT ![k] = "wait"]
    /\ UNCHANGED <<known, hi, seen, nsess, fresh, retries, served, lost, revoked, servedAfter>>

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

\* The callee takes a resume and serves the call (its answer, resumed, is
\* the relay's to deliver or replace).
Deliver(m) ==
    /\ m \in net /\ Takes(m)
    /\ Take(m.s, m.c)
    /\ Serve(m.k)
    /\ UNCHANGED <<cs, known, nsess, net, used, res, st, fresh, retries, lost, revoked>>

\* resumed reached the caller: only for a resume the callee took.
Confirm(k) ==
    /\ st[k] = "wait" /\ served[k] > 0
    /\ st' = [st EXCEPT ![k] = "done"]
    /\ UNCHANGED <<cs, known, hi, seen, nsess, net, used, res, fresh, retries, served, lost, revoked, servedAfter>>

\* The retry bound passed for k's resume.
Late(k) ==
    /\ fresh[k] /\ fresh' = [fresh EXCEPT ![k] = FALSE]
    /\ UNCHANGED <<cs, known, hi, seen, nsess, net, used, res, st, retries, served, lost, revoked, servedAfter>>

\* The callee's check of a retry (handleE2EEInit): within the bound, and
\* not a call number the session took; answering it takes the number, so
\* the resume, delivered late, is refused (retry-no-take: it is not).
RetryOK(k) ==
    /\ fresh[k] \/ Mutant = "no-retry-bound"
    /\ \/ Mutant = "no-retry-check"
       \/ ~(res[k].s \in known /\ Taken(res[k].s, res[k].c))

\* unknown reached the caller, the callee's or forged: the caller drops
\* the session and handshakes once on the call (rehandshake); the callee
\* serves it when RetryOK, else the call fails (retry-loop: it goes on
\* waiting, to handshake again on the next unknown).
Unknown(k) ==
    /\ st[k] = "wait"
    /\ LET dropped == IF cs.id = res[k].s THEN [id |-> 0, next |-> 1] ELSE cs IN
       \/ /\ ~revoked /\ nsess < MaxSess /\ RetryOK(k)
          /\ retries[k] = 0 \/ Mutant = "retry-loop"
          /\ retries' = [retries EXCEPT ![k] = @ + 1]
          /\ nsess' = nsess + 1
          /\ known' = known \cup {nsess + 1}
          /\ cs' = [id |-> nsess + 1, next |-> 1]
          /\ st' = [st EXCEPT ![k] = IF Mutant = "retry-loop" THEN "wait" ELSE "done"]
          /\ IF res[k].s \in known /\ Mutant # "retry-no-take"
                THEN Take(res[k].s, res[k].c)
                ELSE UNCHANGED <<hi, seen>>
          /\ Serve(k)
       \/ /\ (revoked \/ nsess = MaxSess \/ retries[k] > 0 \/ ~RetryOK(k))
          /\ cs' = dropped
          /\ st' = [st EXCEPT ![k] = "failed"]
          /\ UNCHANGED <<retries, nsess, known, served, servedAfter, hi, seen>>
    /\ UNCHANGED <<net, used, res, fresh, lost, revoked>>

\* The callee restarts: its sessions go (restart-keeps-sessions: they stay,
\* their windows do not). A call it served and whose caller still waits
\* may run again on a forged unknown (lost).
Restart ==
    /\ known' = IF Mutant = "restart-keeps-sessions" THEN known ELSE {}
    /\ hi' = [s \in Ids |-> 0] /\ seen' = [s \in Ids |-> {}]
    /\ lost' = lost \cup {k \in Calls : st[k] = "wait" /\ served[k] > 0}
    /\ UNCHANGED <<cs, nsess, net, used, res, st, fresh, retries, served, revoked, servedAfter>>

ExpireCaller ==
    /\ cs.id # 0 /\ cs' = [id |-> 0, next |-> 1]
    /\ UNCHANGED <<known, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter>>

\* A callee keeps a session longer than the retry bound past its last
\* call (a2aSessionCalleeIdle > a2aResumeRetryBound + skew).
ExpireCallee(s) ==
    /\ s \in known
    /\ \/ Mutant = "no-retry-bound"
       \/ \A k \in Calls : st[k] = "wait" /\ res[k].s = s => ~fresh[k]
    /\ known' = known \ {s}
    /\ UNCHANGED <<cs, hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, revoked, servedAfter>>

\* The owner revokes the machine: both keyrings refuse it from now on
\* (takeCall and resume check For/Valid; a revoked session is dropped).
Revoke ==
    /\ ~revoked /\ revoked' = TRUE
    /\ cs' = [id |-> 0, next |-> 1]
    /\ known' = IF Mutant = "survive-revoke" THEN known ELSE {}
    /\ UNCHANGED <<hi, seen, nsess, net, used, res, st, fresh, retries, served, lost, servedAfter>>

Next ==
    \/ \E k \in Calls : Handshake(k) \/ Resume(k) \/ Confirm(k) \/ Unknown(k) \/ Late(k)
    \/ \E m \in net : Deliver(m)
    \/ Warm \/ Restart \/ ExpireCaller \/ \E s \in Ids : ExpireCallee(s)
    \/ Revoke

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
AtMostOnce == \A k \in Calls : served[k] <= 1 \/ k \in lost
NoKeyReuse == \A p \in DOMAIN used : used[p] <= 1
RevokeEnds == servedAfter = 0
OnceRetry == \A k \in Calls : retries[k] <= 1

\* Witnesses (TLC must violate each): a resumed call confirmed, one served
\* after its handshake, one failed, a forged unknown on a served call
\* refused, a call lost to a restart.
W_Resumed == ~\E k \in Calls : st[k] = "done" /\ retries[k] = 0 /\ res[k] # None
W_Rehandshake == ~\E k \in Calls : st[k] = "done" /\ retries[k] = 1
W_Failed == ~\E k \in Calls : st[k] = "failed"
W_ForgedRefused == ~\E k \in Calls : st[k] = "failed" /\ served[k] = 1 /\ ~revoked
W_Lost == lost = {}
=============================================================================
