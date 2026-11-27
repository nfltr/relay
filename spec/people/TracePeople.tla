---------------------------- MODULE TracePeople ----------------------------
(* Trace check (spec/people/README.md "Traces"): the people lines of the   *)
(* issuer's log that org/orgpki committed (-tags enroltrace,                *)
(* PEOPLETRACE=<dir>: trace_on.go peopleTrace), one JSON line each, read in *)
(* order:                                                                   *)
(*   invite  by (the admin, "" the owner) with role ar invited u as r,      *)
(*           invite id, expiring at exp (Invite)                            *)
(*   join    u joined by invite id with role r, name n of app a (Join)      *)
(*   add     a certificate of name n (relay machine id mid, app a) for u:   *)
(*           a code's, a renewal's, a sign-in again's (Redeem)              *)
(*   role    by with role ar set u's role to r (ChangeRole)                 *)
(*   remove  by with role ar removed u, whose role was sr, filing f: each   *)
(*           machine's <<name, relay machine id>> (Offboard)                *)
(*   revoke  name n, or every name of app a, revoked (no person act)        *)
(* Times are Unix seconds. Each line must be what People.tla's rules allow  *)
(* given the lines before it; a wrong step that a model mutant names is     *)
(* reported by that mutant's property, any other by Conforms. TraceDone is  *)
(* violated when every line was read: accepted.                             *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, people, invites, nm, bad

vars == <<l, people, invites, nm, bad>>

Init ==
    /\ l = 1
    /\ people = [x \in {} |-> 0]   \* <<org, email>> -> [st: active|removed, r]
    /\ invites = [x \in {} |-> 0]  \* <<org, id>> -> [u, r, exp, used]
    /\ nm = [x \in {} |-> 0]       \* <<org, name>> -> [u, a, mid, live]
    /\ bad = {}

E == Log[l]
Set(sq) == {sq[i] : i \in DOMAIN sq}
PK == <<E.o, E.u>>
IK == <<E.o, E.id>>
NK == <<E.o, E.n>>
In == PK \in DOMAIN people
Active == In /\ people[PK].st = "active"
Removed == In /\ people[PK].st = "removed"

\* People.tla Allowed: the owner anything; an admin invites and removes
\* members only.
Allowed(ar, act, sr) == ar = "owner" \/ (ar = "admin" /\ act \in {"invite", "remove"} /\ sr = "member")

\* The actor is the owner (no person) or a person whose role in the log
\* is the one the line names.
BK == <<E.o, E.by>>
ActorBad ==
    IF E.ar = "owner" THEN (IF E.by = "" THEN {} ELSE {"diverged"})
    ELSE IF BK \in DOMAIN people /\ people[BK].st = "removed" THEN {"admin-after-offboard"}
    ELSE IF BK \in DOMAIN people /\ people[BK].r = E.ar THEN {}
    ELSE {"no-role-check"}

InviteBad ==
    ActorBad
    \cup (IF Allowed(E.ar, "invite", E.r) THEN {} ELSE {"admin-invites-admin"})
    \cup (IF In THEN {"reinvite"} ELSE {})
    \cup (IF E.r \in {"admin", "member"} /\ IK \notin DOMAIN invites THEN {} ELSE {"diverged"})

Inv == invites[IK]
JoinBad ==
    IF Removed THEN {"rejoin-old-invite"}
    ELSE IF In \/ IK \notin DOMAIN invites THEN {"idp-alone-enrols"}
    ELSE (IF Inv.used \/ Inv.u # E.u \/ E.t >= Inv.exp THEN {"idp-alone-enrols"} ELSE {})
         \cup (IF Inv.r # E.r THEN {"role-from-request"} ELSE {})

AddBad == IF Removed THEN {"code-outlives-offboard"} ELSE {}

RoleBad ==
    ActorBad
    \cup (IF Allowed(E.ar, "role", E.r) THEN {} ELSE {"admin-changes-role"})
    \cup (IF Active /\ E.r \in {"admin", "member"} /\ people[PK].r # E.r THEN {} ELSE {"diverged"})

\* The person's live names (from the lines before) and what the removal filed.
Live == {x[2] : x \in {y \in DOMAIN nm : y[1] = E.o /\ nm[y].u = E.u /\ nm[y].live}}
FiledNames == {x[1] : x \in Set(E.f)}
RemoveBad ==
    ActorBad
    \cup (IF Allowed(E.ar, "remove", E.sr) THEN {} ELSE {"admin-offboards-admin"})
    \cup (IF Removed \/ (Active /\ people[PK].r # E.sr) \/ (~In /\ E.ar # "owner") THEN {"diverged"} ELSE {})
    \cup (IF Live \subseteq FiledNames THEN {} ELSE {"offboard-misses-machine"})
    \cup (IF \E x \in Set(E.f) : <<E.o, x[1]>> \in DOMAIN nm /\ nm[<<E.o, x[1]>>].mid # x[2] THEN {"relay-not-filed"} ELSE {})

Kinds == {"invite", "join", "add", "role", "remove", "revoke"}

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ people' = CASE E.ev = "join" -> (PK :> [st |-> "active", r |-> E.r]) @@ people
                   [] E.ev = "role" /\ In -> [people EXCEPT ![PK].r = E.r]
                   [] E.ev = "remove" -> (PK :> [st |-> "removed", r |-> E.sr]) @@ people
                   [] OTHER -> people
    /\ invites' = CASE E.ev = "invite" -> (IK :> [u |-> E.u, r |-> E.r, exp |-> E.exp, used |-> FALSE]) @@ invites
                    [] E.ev = "join" /\ IK \in DOMAIN invites -> [invites EXCEPT ![IK].used = TRUE]
                    [] OTHER -> invites
    /\ nm' = CASE E.ev = "join" -> (NK :> [u |-> E.u, a |-> E.a, mid |-> "", live |-> TRUE]) @@ nm
               [] E.ev = "add" -> (NK :> [u |-> E.u, a |-> E.a, mid |-> E.mid, live |-> TRUE]) @@ nm
               [] E.ev = "remove" -> [x \in DOMAIN nm |-> IF x[1] = E.o /\ nm[x].u = E.u THEN [nm[x] EXCEPT !.live = FALSE] ELSE nm[x]]
               [] E.ev = "revoke" -> [x \in DOMAIN nm |-> IF x[1] = E.o /\ (x[2] = E.n \/ (E.a # "" /\ nm[x].a = E.a)) THEN [nm[x] EXCEPT !.live = FALSE] ELSE nm[x]]
               [] OTHER -> nm
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev \notin Kinds -> {"diverged"}
                  [] E.ev = "invite" -> InviteBad
                  [] E.ev = "join" -> JoinBad
                  [] E.ev = "add" -> AddBad
                  [] E.ev = "role" -> RoleBad
                  [] E.ev = "remove" -> RemoveBad
                  [] OTHER -> {}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
AuthorizedActs == None({"admin-invites-admin", "admin-changes-role", "admin-offboards-admin", "no-role-check", "admin-after-offboard", "reinvite"})
AdminsByOwner == None({"role-from-request"})
JoinNeedsInvite == None({"idp-alone-enrols"})
NoOrphan == None({"code-outlives-offboard", "offboard-misses-machine"})
ReachBound == None({"relay-not-filed"})
RemovedStaysOut == None({"rejoin-old-invite"})
TraceDone == l <= Len(Log)
=============================================================================
