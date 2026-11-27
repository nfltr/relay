------------------------------ MODULE PortMap ------------------------------
(* A direct endpoint's port mapping in three protocols (design: nfltr
   docs/decisions/hardnat-2026-11-25.md; spec/README.md "PortMap.tla").
   At each offer the endpoint asks its gateway to map its UDP port: PCP
   (RFC 6887) first, NAT-PMP (RFC 6886) when the gateway answers PCP with
   a version-0 answer or not at all, UPnP-IGD (AddPortMapping) last; the
   first that maps wins the round, and the mapped address is one more
   candidate (DirectPunch.tla's Offered or Trickled). The endpoint renews
   only the mapping it holds (every offer asks again); the gateway ends a
   lease nobody renews. A round may ask the held mapping's protocol first
   (a renewal without the others' waits); if that fails it asks in Order.
   A PCP refusal (the gateway speaks PCP and said no) skips NAT-PMP. Close
   deletes the held mapping.

   What this module checks, one endpoint and its gateway:
   - no mapping without a lease (NoPermanent): a gateway that grants only
     permanent ones (UPnP IGD v1, error 725) gets none, so a killed
     process leaves nothing open for longer than a lease;
   - one live mapping, the held one (OneLive): a round that maps with
     another protocol than the held one deletes the old one; only a lost
     delete leaves a second one live, to its lease;
   - nothing held after the close (NoMapAfterClose), and every live
     mapping then is one whose delete was lost (DeletedOnClose): an ask in
     flight at the close deletes what it got;
   - every round ends (Ends), and a mapping nobody renews ends (NoLeak).

   Abstracted: time (a renewed lease never ends; an unrenewed one ends,
   fairly), addresses, ports, the packets. The gateway may change what it
   speaks (a new router, another network) and may lose its table (a
   restart). *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    MaxRounds,   \* offers (ask rounds) per behaviour
    MaxChanges,  \* gateway changes per behaviour
    Mutant       \* "none" or the failure put back (scripts/spec.sh mutants)

Order == <<"pcp", "natpmp", "upnp">>
Protos == {"pcp", "natpmp", "upnp"}
None == "none"

VARIABLES
    ep,       \* "open" | "closed"
    ask,      \* 0: no round; i: asking Order[i]
    first,    \* the round's first ask (Order's index)
    held,     \* the protocol of the mapping the endpoint renews, or None
    live,     \* p -> "none" | "leased" | "permanent": the gateway's table for the port
    lost,     \* protocols whose delete the network lost (live to their lease)
    speaks,   \* the protocols the gateway maps with
    perm,     \* those among them it grants only permanent leases with (UPnP v1)
    rounds,
    changes

vars == <<ep, ask, first, held, live, lost, speaks, perm, rounds, changes>>

Idx(p) == CHOOSE i \in 1..Len(Order) : Order[i] = p

Init ==
    /\ ep = "open"
    /\ ask = 0
    /\ first = 1
    /\ held = None
    /\ live = [p \in Protos |-> "none"]
    /\ lost = {}
    /\ speaks \in SUBSET Protos
    /\ perm \in SUBSET speaks
    /\ rounds = 0
    /\ changes = 0

\* An offer starts a round, in Order or at the held mapping's protocol
\* (mutant map-after-close: also once closed).
Round ==
    /\ ask = 0 /\ rounds < MaxRounds
    /\ (ep = "open" \/ Mutant = "map-after-close")
    /\ \E f \in {1} \cup (IF held \in Protos THEN {Idx(held)} ELSE {}) : ask' = f /\ first' = f
    /\ rounds' = rounds + 1
    /\ UNCHANGED <<ep, held, live, lost, speaks, perm, changes>>

\* Delete q from table l (lost deletes ls), best effort, one bounded ask:
\* the outcomes <<table, lost deletes>>: gone, or the delete is lost and q
\* lives to its lease.
Deleted(q, l, ls) == {<<[l EXCEPT ![q] = "none"], ls \ {q}>>, <<l, ls \cup {q}>>}

\* The gateway maps Order[ask] with a lease (mutant accept-permanent: a
\* permanent-only gateway's 725 retried with lease 0, mapped for ever).
\* Open: held, the old held one deleted (mutant ask-all: kept, as asking
\* every protocol and keeping each answer would). Closed (the close came
\* while the ask was in flight): deleted at once (mutant map-after-close:
\* held).
Mapped ==
    LET p == Order[ask]
        kind == IF p \in perm THEN "permanent" ELSE "leased"
    IN
    /\ ask # 0
    /\ p \in speaks \ perm \/ (Mutant = "accept-permanent" /\ p \in perm)
    /\ ask' = 0
    /\ IF ep = "open" \/ Mutant = "map-after-close"
       THEN /\ held' = p
            /\ IF held \in Protos /\ held # p /\ Mutant # "ask-all"
               THEN \E o \in Deleted(held, [live EXCEPT ![p] = kind], lost \ {p}) :
                        live' = o[1] /\ lost' = o[2]
               ELSE /\ live' = [live EXCEPT ![p] = kind]
                    /\ lost' = lost \ {p}
       ELSE /\ held' = None
            /\ \E o \in Deleted(p, [live EXCEPT ![p] = kind], lost) :
                   live' = o[1] /\ lost' = o[2]
    /\ UNCHANGED <<ep, first, speaks, perm, rounds, changes>>

\* The gateway answers Order[ask] with a refusal, silence (the ask's
\* bound), or, for a permanent-only gateway, error 725: no mapping, the
\* next protocol is asked: after a held-first ask Order's first, after PCP
\* NAT-PMP or (a PCP refusal) UPnP. Mutant ask-all: a mapping does not end
\* the round.
NotMapped ==
    LET p == Order[ask] IN
    /\ ask # 0
    /\ \/ p \notin speaks
       \/ p \in perm
       \/ Mutant = "ask-all" /\ p \in speaks \ perm /\ ep = "open" /\ ask < Len(Order)
    /\ IF Mutant = "ask-all" /\ p \in speaks \ perm
       THEN /\ live' = [live EXCEPT ![p] = "leased"]
            /\ held' = p
       ELSE UNCHANGED <<live, held>>
    /\ \/ first # 1 /\ ask' = 1 /\ first' = 1
       \/ first = 1 /\ ask' = (IF ask < Len(Order) THEN ask + 1 ELSE 0) /\ first' = 1
       \/ first = 1 /\ ask = 1 /\ ask' = 3 /\ first' = 1
    /\ UNCHANGED <<ep, lost, speaks, perm, rounds, changes>>

\* The endpoint closes: the held mapping is deleted (mutant no-delete:
\* only forgotten).
Close ==
    /\ ep = "open"
    /\ ep' = "closed"
    /\ held' = None
    /\ IF held \in Protos /\ Mutant # "no-delete"
       THEN \E o \in Deleted(held, live, lost) : live' = o[1] /\ lost' = o[2]
       ELSE UNCHANGED <<live, lost>>
    /\ UNCHANGED <<ask, first, speaks, perm, rounds, changes>>

\* A lease nobody renews ends (the gateway's timer).
Expire(p) ==
    /\ live[p] = "leased" /\ (p # held \/ ep = "closed")
    /\ live' = [live EXCEPT ![p] = "none"]
    /\ lost' = lost \ {p}
    /\ UNCHANGED <<ep, ask, first, held, speaks, perm, rounds, changes>>

\* The gateway restarts (its table lost) or another one takes over (it
\* speaks other protocols): the held mapping is stale until the next round.
GatewayChange ==
    /\ changes < MaxChanges
    /\ changes' = changes + 1
    /\ \E s \in SUBSET Protos, q \in SUBSET Protos :
         /\ q \subseteq s
         /\ speaks' = s /\ perm' = q
    /\ live' = [p \in Protos |-> "none"]
    /\ lost' = {}
    /\ UNCHANGED <<ep, ask, first, held, rounds>>

Next ==
    \/ Round \/ Mapped \/ NotMapped \/ Close
    \/ \E p \in Protos : Expire(p)
    \/ GatewayChange

\* Fair: the gateway answers (or the ask's bound ends it), leases end.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(Mapped) /\ WF_vars(NotMapped)
    /\ \A p \in Protos : WF_vars(Expire(p))

TypeOK ==
    /\ ep \in {"open", "closed"}
    /\ ask \in 0..Len(Order) /\ first \in 1..Len(Order)
    /\ held \in Protos \cup {None}
    /\ live \in [Protos -> {"none", "leased", "permanent"}]
    /\ lost \subseteq Protos
    /\ speaks \subseteq Protos /\ perm \subseteq speaks
    /\ rounds \in 0..MaxRounds /\ changes \in 0..MaxChanges

NoPermanent == \A p \in Protos : live[p] # "permanent"

\* One live mapping: the held one, or one whose delete was lost.
OneLive == \A p \in Protos : live[p] = "leased" => p = held \/ p \in lost

NoMapAfterClose == ep = "closed" => held = None

\* Once closed and no ask in flight: only lost deletes left live.
DeletedOnClose == ep = "closed" /\ ask = 0 => \A p \in Protos : live[p] # "none" => p \in lost

\* Every round ends; a lease nobody renews ends.
Ends == []<>(ask = 0)
NoLeak == \A p \in Protos : (live[p] # "none" /\ (p # held \/ ep = "closed")) ~> live[p] = "none"

\* Witnesses (scripts/spec.sh mutants: each must be violated).
W_Held == ~(held \in Protos)
W_FellBackToUPnP == ~(held = "upnp" /\ ask = 0)
W_Switched == ~(held \in Protos /\ \E p \in Protos \ {held} : p \in lost)
W_ClosedInFlight == ~(ep = "closed" /\ ask # 0)
W_PermRefused == ~(ask = 0 /\ rounds > 0 /\ held = None /\ "upnp" \in perm /\ ep = "open")
W_Stale == ~(held \in Protos /\ live[held] = "none" /\ ep = "open")
=============================================================================
