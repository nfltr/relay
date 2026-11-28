----------------------------- MODULE MemberLog -----------------------------
(***************************************************************************)
(* The root-held member log (lane ROOTHELD, 2026-11-28, design; nfltr      *)
(* docs/decisions/root-held-membership-2026-11-28.md). Every fact that     *)
(* admits a machine key is an entry of an append-only, hash-chained log    *)
(* signed by the root or by an admin key the root delegated in the log.    *)
(* The attacker owns the relay AND the issuer: it carries, orders,         *)
(* withholds and replays every entry, signs anything with the issuer key   *)
(* and with every admin key it stole, and forks the log at any prefix.     *)
(* Honest: the root, the admins it did not steal (they sign only on the    *)
(* head their own copy holds; a stale copy signs a fork, the R85PREP       *)
(* stale-head case), the verifiers (serving machines).                     *)
(*                                                                         *)
(* An entry is <<prefix, item>>: the hash chain binds an item to its whole *)
(* prefix (prev = the head's hash), so two entries on one prefix are a     *)
(* fork. A verifier's copy is the chain its fork-choice rule picks from    *)
(* the valid entries it has seen; an addition admits only from that copy;  *)
(* a removal or undelegation takes effect from any valid entry seen, on    *)
(* any branch (denial is monotone: only a valid signer can deny).          *)
(*                                                                         *)
(* Abstracted: time, the issuer's CRL and status (it can only deny, so it  *)
(* shrinks Admit and no invariant needs it; spec/enrol/Enrol.tla holds     *)
(* their lifetimes), groups and persons (an add item stands for the whole  *)
(* (key, machine, person, groups) fact it signs), root rotation (a         *)
(* recovery-signed rotate entry ends the old root exactly as Undelegate    *)
(* ends an admin: the same position rule), invites and add codes (one-shot *)
(* signers an entry of the root or an admin authorises: lane RH1 adds      *)
(* them), the signatures (spec/proverif/rootheld.pv).                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Keys,       \* machine keys an entry may add or remove
    Admins,     \* admin device keys the root may delegate
    V,          \* verifiers
    Names,      \* a sequence of Keys \cup Admins: the fork choice's order
    MaxLen,     \* the longest chain anyone signs on
    MaxForge,   \* entries the attacker signs
    Mutant      \* "none" or a bug put back (scripts/spec-rootheld.sh mutants)

Root == "root"
Iss == "iss"
Signers == {Root, Iss} \cup Admins

VARIABLES
    log,        \* the canonical log: what the honest issuer sequenced
    signed,     \* every entry anyone signed (the attacker sees them all)
    stolen,     \* admin keys the attacker holds
    forged,     \* entries the attacker signed
    stale,      \* an honest signer signed on a stale copy (once)
    seen,       \* the entries each verifier has received
    copy        \* each verifier's chosen chain

vars == <<log, signed, stolen, forged, stale, seen, copy>>

Ops == {"add", "rm", "dlg", "undlg"}
Item(o, s, b) == [op |-> o, subj |-> s, by |-> b]
Items == {Item(o, s, b) : o \in {"add", "rm"}, s \in Keys, b \in Signers}
    \cup {Item(o, s, b) : o \in {"dlg", "undlg"}, s \in Admins, b \in Signers}
Entry(p, i) == [log |-> p, it |-> i]
Range(s) == {s[i] : i \in DOMAIN s}
Take(s, n) == SubSeq(s, 1, n)
IsPrefix(p, s) == Len(p) <= Len(s) /\ Take(s, Len(p)) = p
\* The entries a chain consists of.
EntriesOf(c) == {Entry(Take(c, i - 1), c[i]) : i \in 1..Len(c)}

\* a is delegated on prefix p: the root's dlg, no undlg.
Delegated(p, a) ==
    /\ Item("dlg", a, Root) \in Range(p)
    /\ (Mutant = "undelegate-ignored" \/ Item("undlg", a, Root) \notin Range(p))

\* The verifier's rule: who may sign item i on prefix p. The root signs
\* every op; a delegated admin adds and removes keys; nothing else (the
\* issuer signs no entry).
Authorised(p, i) ==
    \/ i.by = Root
    \/ i.by \in Admins /\ i.op \in {"add", "rm"} /\ Delegated(p, i.by)
    \/ Mutant = "issuer-member" /\ i.by = Iss /\ i.op = "add"

\* u is the root's undelegation of a.
Undelegates(u, a) == u.it = Item("undlg", a, Root)

\* An admin's entry is refused once its undelegation is seen anywhere,
\* unless the entry lies in that undelegation's own prefix (signed before
\* it, on the chain the root built on): a fork a stolen key signs behind
\* the undelegation is refused retroactively.
NotRevoked(S, e) ==
    \/ e.it.by \notin Admins
    \/ Mutant \in {"revoke-not-retroactive", "undelegate-ignored"}
    \/ \A u \in S : Undelegates(u, e.it.by) => IsPrefix(Append(e.log, e.it), u.log)

\* e is valid for a verifier holding S: its prefix's entries are held,
\* its signer is authorised there, and not revoked.
Valid(S, e) ==
    /\ EntriesOf(e.log) \subseteq S
    /\ Authorised(e.log, e.it)
    /\ NotRevoked(S, e)

\* Fork choice: on one prefix the root's item beats an admin's; then the
\* lower rank (the item's hash, Tailnet Lock's lowest-hash tie-break).
\* The configs' order (TLC configs take no sequence literal).
CfgNames == <<"a1", "k1", "k2">>
Idx(x) == CHOOSE i \in 1..Len(Names) : Names[i] = x
OpRank(o) == CASE o = "dlg" -> 1 [] o = "undlg" -> 2 [] o = "add" -> 3 [] o = "rm" -> 4
SignerRank(b) == IF b = Root THEN 0 ELSE IF b = Iss THEN 9 ELSE Idx(b)
Rank(i) == SignerRank(i.by) * 100 + OpRank(i.op) * 10 + Idx(i.subj)
Best(C) == CHOOSE e \in C : \A f \in C : Rank(e.it) <= Rank(f.it)

RECURSIVE ChainFrom(_, _)
ChainFrom(S, p) ==
    LET C == {e \in S : e.log = p /\ Valid(S, e)}
    IN IF C = {} THEN p ELSE ChainFrom(S, Append(p, Best(C).it))

\* The verifier's new copy after receiving entries.
NewCopy(v, S) ==
    IF Mutant = "first-seen"
    THEN \* keeps the branch it took first: extends only its own chain
         LET c == ChainFrom(S, <<>>)
         IN IF IsPrefix(copy[v], c) THEN c ELSE ChainFrom(S, copy[v])
    ELSE ChainFrom(S, <<>>)

AddsIn(c) == {c[i].subj : i \in {j \in DOMAIN c : c[j].op = "add"}}
\* A key is removed for v by any valid removal it has seen, on any branch.
Removed(v, k) ==
    IF Mutant = "rm-in-copy-only"
    THEN \E i \in DOMAIN copy[v] : copy[v][i].op = "rm" /\ copy[v][i].subj = k
    ELSE \E e \in seen[v] : e.it.op = "rm" /\ e.it.subj = k /\ Valid(seen[v], e)

\* The keys v admits now (the issuer's CRL and status may only shrink this).
Admit(v) ==
    IF Mutant = "admit-from-seen"
    THEN {k \in Keys : (\E e \in seen[v] : e.it.op = "add" /\ e.it.subj = k /\ Valid(seen[v], e)) /\ ~Removed(v, k)}
    ELSE {k \in AddsIn(copy[v]) : ~Removed(v, k)}

TypeOK ==
    /\ log \in Seq(Items)
    /\ signed \subseteq [log : Seq(Items), it : Items]
    /\ stolen \subseteq Admins
    /\ forged \in 0..MaxForge
    /\ stale \in BOOLEAN
    /\ seen \in [V -> SUBSET signed]
    /\ copy \in [V -> Seq(Items)]

Init ==
    /\ log = <<>>
    /\ signed = {}
    /\ stolen = {}
    /\ forged = 0
    /\ stale = FALSE
    /\ seen = [v \in V |-> {}]
    /\ copy = [v \in V |-> <<>>]

\* An honest signer appends i to the canonical log (it held the head; the
\* honest issuer's compare-and-set took it).
Append1(i) ==
    /\ Len(log) < MaxLen
    /\ Authorised(log, i)
    /\ signed' = signed \cup {Entry(log, i)}
    /\ log' = Append(log, i)
    /\ UNCHANGED <<stolen, forged, stale, seen, copy>>

Once(i) == i \notin Range(log)
Delegate(a) == Once(Item("dlg", a, Root)) /\ Append1(Item("dlg", a, Root))
Undelegate(a) ==
    /\ Item("dlg", a, Root) \in Range(log)
    /\ Once(Item("undlg", a, Root))
    /\ Append1(Item("undlg", a, Root))
\* s: the root or an admin (honest, or its owner before it was stolen).
Add(s, k) ==
    /\ \A b \in Signers : Item("add", k, b) \notin Range(log)
    /\ Append1(Item("add", k, s))
Remove(s, k) ==
    /\ \E b \in Signers : Item("add", k, b) \in Range(log)
    /\ \A b \in Signers : Item("rm", k, b) \notin Range(log)
    /\ Append1(Item("rm", k, s))

\* An honest signer whose copy is stale signs i on an older prefix; the
\* honest issuer refuses it (the head moved) and the signer re-signs on the
\* head it is sent, but the entry exists and the attacker may carry it.
StaleSign(s, k, n) ==
    /\ ~stale
    /\ n < Len(log)
    /\ Authorised(Take(log, n), Item("add", k, s))
    /\ signed' = signed \cup {Entry(Take(log, n), Item("add", k, s))}
    /\ stale' = TRUE
    /\ UNCHANGED <<log, stolen, forged, seen, copy>>

Steal(a) ==
    /\ a \notin stolen
    /\ stolen' = stolen \cup {a}
    /\ UNCHANGED <<log, signed, forged, stale, seen, copy>>

\* The attacker signs any add or remove with the issuer key or a stolen
\* key, on any prefix of a chain that exists (a fork, or a later entry).
Prefixes == {<<>>} \cup {Append(e.log, e.it) : e \in signed}
Forge(p, o, k, b) ==
    /\ forged < MaxForge
    /\ Len(p) < MaxLen
    /\ b \in {Iss} \cup stolen
    /\ signed' = signed \cup {Entry(p, Item(o, k, b))}
    /\ forged' = forged + 1
    /\ UNCHANGED <<log, stolen, stale, seen, copy>>

\* The relay (the attacker) hands v any signed chain (an entry with its
\* prefix: a verifier asks for what it lacks), any branch, in any order, or
\* none.
Deliver(v, e) ==
    /\ e \notin seen[v]
    /\ seen' = [seen EXCEPT ![v] = @ \cup EntriesOf(Append(e.log, e.it))]
    /\ copy' = [copy EXCEPT ![v] = NewCopy(v, seen'[v])]
    /\ UNCHANGED <<log, signed, stolen, forged, stale>>

\* An honest carrier (a session with a member that holds the canonical
\* log: every session exchanges heads end to end) gives v the whole log.
Sync(v) ==
    /\ ~(EntriesOf(log) \subseteq seen[v])
    /\ seen' = [seen EXCEPT ![v] = @ \cup EntriesOf(log)]
    /\ copy' = [copy EXCEPT ![v] = NewCopy(v, seen'[v])]
    /\ UNCHANGED <<log, signed, stolen, forged, stale>>

Next ==
    \/ \E a \in Admins : Delegate(a) \/ Undelegate(a) \/ Steal(a)
    \/ \E s \in {Root} \cup Admins, k \in Keys : Add(s, k) \/ Remove(s, k)
    \/ \E s \in {Root} \cup Admins, k \in Keys, n \in 0..MaxLen : StaleSign(s, k, n)
    \/ \E p \in Prefixes, o \in {"add", "rm"}, k \in Keys, b \in Signers : Forge(p, o, k, b)
    \/ \E v \in V : \E e \in signed : Deliver(v, e)
    \/ \E v \in V : Sync(v)

Spec == Init /\ [][Next]_vars
LiveSpec == Spec /\ \A v \in V : WF_vars(Sync(v))

-----------------------------------------------------------------------------
\* Ground truth, independent of the verifier's rule: e was signed by the
\* root, or by an admin the root had delegated on e's own prefix and not
\* undelegated there.
RootOrDelegate(e) ==
    \/ e.it.by = Root
    \/ /\ e.it.by \in Admins
       /\ Item("dlg", e.it.by, Root) \in Range(e.log)
       /\ Item("undlg", e.it.by, Root) \notin Range(e.log)

\* 1. No admission without a root- or delegate-signed add in the log.
AdmitOnlyLogged ==
    \A v \in V : \A k \in Admit(v) :
        \E e \in signed : e.it.op = "add" /\ e.it.subj = k /\ RootOrDelegate(e)

\* 2. A revoked delegate's later entries are refused: no entry of an
\* undelegated admin in a verifier's copy past the undelegation in the
\* chain, nor outside the prefix of any undelegation the verifier saw.
RevokedDelegateRefused ==
    \A v \in V : \A i \in 1..Len(copy[v]) :
        copy[v][i].by \in Admins =>
            /\ Item("undlg", copy[v][i].by, Root) \notin Range(Take(copy[v], i - 1))
            /\ \A u \in seen[v] : Undelegates(u, copy[v][i].by) => IsPrefix(Take(copy[v], i), u.log)

\* 3. A verifier never accepts a forked log: what it admits comes from one
\* chain of valid entries it holds, never from two branches at once ...
NoForkAccepted ==
    \A v \in V :
        /\ Admit(v) \subseteq AddsIn(copy[v])
        /\ \A i \in 1..Len(copy[v]) : Entry(Take(copy[v], i - 1), copy[v][i]) \in seen[v]
\* ... and every verifier that holds the same entries picks the same chain
\* (no split view survives an exchange of entries).
Converge ==
    \A v, w \in V : seen[v] = seen[w] => copy[v] = copy[w]

\* Liveness: a removal in the canonical log ends the key at every verifier
\* once an honest carrier reached it, and for good.
RemovalTakesEffect ==
    \A k \in Keys : (\E i \in DOMAIN log : log[i].op = "rm" /\ log[i].subj = k)
        ~> (\A v \in V : k \notin Admit(v))

-----------------------------------------------------------------------------
\* Witnesses: each must be violated (reachable).
W_AdminAdmits == ~\E v \in V : \E i \in DOMAIN copy[v] :
    copy[v][i].op = "add" /\ copy[v][i].by \in Admins /\ copy[v][i].subj \in Admit(v)
\* A stolen admin's fork behind its undelegation, seen and refused.
W_RevokedForkRefused == ~\E v \in V : \E e \in seen[v] :
    e.it.by \in stolen /\ e.it.op = "add" /\ (\E u \in seen[v] : Undelegates(u, e.it.by)) /\ ~Valid(seen[v], e)
\* Two valid siblings seen by one verifier (a fork), one chain kept.
W_ForkSeen == ~\E v \in V : \E e, f \in seen[v] :
    e # f /\ e.log = f.log /\ Valid(seen[v], e) /\ Valid(seen[v], f)
\* An issuer-signed add delivered and not admitted.
W_IssuerRefused == ~\E v \in V : \E e \in seen[v] :
    e.it.by = Iss /\ e.it.op = "add" /\ e.it.subj \notin Admit(v) /\ EntriesOf(e.log) \subseteq seen[v]
\* A removal on a losing branch still denies.
W_RemovedOffChain == ~\E v \in V, k \in Keys :
    k \in AddsIn(copy[v]) /\ Removed(v, k) /\ ~\E i \in DOMAIN copy[v] : copy[v][i].op = "rm" /\ copy[v][i].subj = k
=============================================================================
