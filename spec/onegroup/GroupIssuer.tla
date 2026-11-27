---------------------------- MODULE GroupIssuer ----------------------------
(***************************************************************************)
(* One set of groups, the issuer's half (lane ONEGROUP-C1, 2026-11-27;     *)
(* nfltr docs/decisions/one-group-2026-11-25.md). relay-server             *)
(* spec/GroupMirror.tla models the relay's mirror and the peers by what    *)
(* this layer guarantees: a member's groups in the signed map change only  *)
(* by a root-signed move order (MovedOnlyAsked there), a move revokes the  *)
(* member's old certificates in the CRL the status is signed with (its     *)
(* Move and Sign: "status and CRL together"), and the issuer puts its      *)
(* newest status again (Reput). This module checks those guarantees of the *)
(* issuer itself (relay org/orgpki): its groups per name, the serials it   *)
(* certified and their groups (OU), the CRLs it signs and the statuses it  *)
(* signs, the root's orders it applies and the relay's wishes it must not. *)
(*                                                                         *)
(* Abstracted: time and lifetimes (no certificate expires here: Enrol.tla  *)
(* holds the lifetimes; an expired serial leaves the CRL and is no session *)
(* either); one organisation; the signatures (spec/proverif/orggroup.pv:   *)
(* an order is in Orders only when the root signed it); the put to the     *)
(* relay (GroupMirror.tla Deliver, Lose, Reput).                            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    M,          \* members
    G,          \* groups in the issuer's root-signed bound
    Out,        \* a group outside the bound (an order may name it)
    MaxSerial,  \* certificates per member
    MaxCRL,     \* CRLs signed
    MaxStatus,  \* statuses signed
    Mutant      \* "none" or a bug put back (scripts/spec-onegroup.sh mutants)

VARIABLES
    groups,     \* the issuer's groups per member (nameRec.groups)
    certs,      \* the groups of each certificate per member, in issue order
    moved,      \* certs[m][1..moved[m]]: revoked by a move (nameRec.moved)
    orders,     \* the root's signed orders <<m, k, gs>>: move m's k-th certificate into gs
    applied,    \* the orders applied, in order (a sequence)
    crls,       \* the CRLs signed: each the set <<m, k>> it lists
    statuses,   \* the statuses signed: [num (its CRL), map, upto (certs per member then)]
    moveDue     \* a move since the last CRL (Issuer.moveDue)

vars == <<groups, certs, moved, orders, applied, crls, statuses, moveDue>>

GS == {{g} : g \in G} \cup {{Out}}
First == CHOOSE g \in G : TRUE
\* The relay's unsigned wishes: any move of any certificate into any groups.
Wishes == M \X (1..MaxSerial) \X GS

TypeOK ==
    /\ groups \in [M -> SUBSET (G \cup {Out})]
    /\ \A m \in M : Len(certs[m]) \in 1..MaxSerial /\ moved[m] \in 0..Len(certs[m])
    /\ orders \subseteq Wishes
    /\ moveDue \in BOOLEAN

Init ==
    /\ groups = [m \in M |-> {First}]
    /\ certs = [m \in M |-> <<{First}>>]   \* each member enrolled by a token
    /\ moved = [m \in M |-> 0]
    /\ orders = {}
    /\ applied = <<>>
    /\ crls = <<{}>>
    /\ statuses = <<>>
    /\ moveDue = FALSE

\* The owner asks on the root's machine (nfltr org approve, Touch ID): the
\* root signs an order for m's newest certificate, the serial the status
\* shows (orgpki.MoveOrder).
Ask(m, k, gs) ==
    /\ k = Len(certs[m]) /\ <<m, k, gs>> \notin orders   \* the status's serial (approve.go)
    /\ orders' = orders \cup {<<m, k, gs>>}
    /\ UNCHANGED <<groups, certs, moved, applied, crls, statuses, moveDue>>

\* Issuer.ApplyOrder of a move (order.go applyMove): only the root's
\* order, of a certificate of the member's not moved already, into groups
\* within the bound and not its own. Mutants: move-without-order (a
\* wish), move-replayed (a moved certificate's order), move-outside-bound.
Apply(m, k, gs) ==
    /\ \/ <<m, k, gs>> \in orders
       \/ Mutant = "move-without-order"
    /\ k <= Len(certs[m])
    /\ k > moved[m] \/ Mutant = "move-replayed"
    /\ gs \subseteq G \/ Mutant = "move-outside-bound"
    /\ gs # groups[m]
    /\ groups' = [groups EXCEPT ![m] = gs]
    /\ moved' = [moved EXCEPT ![m] = Len(certs[m])]
    /\ applied' = Append(applied, <<m, k, gs>>)
    /\ moveDue' = TRUE
    /\ UNCHANGED <<certs, orders, crls, statuses>>

\* Issuer.Renew (the keeper's, at once when its certificate is listed:
\* orgmachine RenewDue), or a rebind token's enrolment: any certificate of
\* m, a moved one too, is followed by one in m's groups now. Mutant
\* renew-old-groups (the groups the token or the old certificate carried:
\* the rebind token's bug, rebind-token-groups in Go).
Renew(m, k) ==
    /\ k <= Len(certs[m]) /\ Len(certs[m]) < MaxSerial
    /\ certs' = [certs EXCEPT ![m] = Append(@, IF Mutant = "renew-old-groups" THEN certs[m][k] ELSE groups[m])]
    /\ UNCHANGED <<groups, moved, orders, applied, crls, statuses, moveDue>>

\* Issuer.CRL: every moved certificate. Mutant move-keeps-old-cert.
CRL ==
    /\ Len(crls) < MaxCRL
    /\ crls' = Append(crls, IF Mutant = "move-keeps-old-cert" THEN {}
                            ELSE {<<m, k>> \in M \X (1..MaxSerial) : k <= moved[m]})
    /\ moveDue' = FALSE
    /\ UNCHANGED <<groups, certs, moved, orders, applied, statuses>>

\* Issuer.SignedStatus: the map and the last CRL, refused while a move
\* waits for one (ErrCRLDue). Mutant status-before-crl.
Sign ==
    /\ Len(statuses) < MaxStatus
    /\ ~moveDue \/ Mutant = "status-before-crl"
    /\ statuses' = Append(statuses, [num |-> Len(crls), map |-> groups, upto |-> [m \in M |-> Len(certs[m])]])
    /\ UNCHANGED <<groups, certs, moved, orders, applied, crls, moveDue>>

Next ==
    \/ \E m \in M, k \in 1..MaxSerial, gs \in GS : Ask(m, k, gs) \/ Apply(m, k, gs)
    \/ \E m \in M, k \in 1..MaxSerial : Renew(m, k)
    \/ CRL \/ Sign

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Range(s) == {s[i] : i \in DOMAIN s}

\* A member's groups in a signed status change only by an order the root
\* signed (GroupMirror.tla MovedOnlyAsked, the issuer's half).
MovedOnlyAsked == \A v \in 2..Len(statuses) : \A m \in M :
    statuses[v].map[m] # statuses[v-1].map[m] =>
        \E k \in 1..MaxSerial : <<m, k, statuses[v].map[m]>> \in orders

\* Every status is signed with a CRL listing each certificate the member
\* held then whose groups are not the status's (GroupMirror.tla Move and
\* Sign: the old serial revoked in the CRL signed with the status).
StatusWithItsCRL == \A v \in 1..Len(statuses) : \A m \in M : \A k \in 1..statuses[v].upto[m] :
    certs[m][k] # statuses[v].map[m] => <<m, k>> \in crls[statuses[v].num]

\* An order is applied at most once (a replay moves nothing back).
AppliedOnce == \A i, j \in DOMAIN applied : i < j => applied[i] # applied[j]

\* Every group a status places a member in is within the issuer's bound.
InBound == \A v \in 1..Len(statuses) : \A m \in M : statuses[v].map[m] \subseteq G

-----------------------------------------------------------------------------
\* Witnesses (each must be violated: the configuration reaches it).
W_Moved == ~(\E v \in 1..Len(statuses) : \E m \in M : statuses[v].map[m] # {First})
W_RenewedInto == ~(\E m \in M : \E k \in 1..Len(certs[m]) : k > moved[m] /\ moved[m] > 0 /\ certs[m][k] # {First})
W_MovedBack == ~(\E m \in M : Len(applied) >= 2 /\ groups[m] = {First})
W_WishRefused == ~(\E w \in Wishes : w \notin orders /\ Len(applied) > 0)
=============================================================================
