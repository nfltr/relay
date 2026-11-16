---------------------------- MODULE OrgHosted ----------------------------
\* An organisation whose issuer runs on a host the owner does not run (the
\* opt-in hosted issuer: spec/orgmove/README.md "OrgHosted.tla"). The owner
\* keeps the root and the recovery key; the hosted machine holds only an
\* issuer key the root certified (NameConstraints, at most DelegLife). This
\* module checks the delegation over time: how long a hosted issuer's word
\* counts, that the root's revocation of it ends it, and that nothing but
\* the owner's own act makes an issuer serve (no automatic takeover).
\* OrgMove.tla checks the move itself (fence, bundle, one history) and
\* OrgHolds.tla the relay's holds across it; the transfer's secrecy and the
\* hosted host's compromise are spec/proverif/orghosted.pv.
\*
\* Keys: k1 is the organisation's issuer key; it starts on the owner's
\* machine (self) and moves onto the hosted machine and back by the fenced
\* move. k2 is a standby the root pre-certified on the hosted machine
\* (the shape a high-availability design would use): it may serve only by
\* the owner's signed activation, never because the hosted side decided the
\* owner's issuer was down.
\*
\* The attacker: owns the relay (it delays or withholds the root's
\* revocation as long as it likes) and may compromise the hosted machine
\* (it then holds every key there and signs whatever it wants under them;
\* a copy taken before a move off keeps working: the old disk's residual).
\* Verifiers check, at admission, the chain at now (x509 Verify: the issuer
\* certificate's NotAfter) and the root's revocations they took; a session
\* lasts until its admission's end (Until) and is cut by a revocation they
\* take.
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxTime,    \* time steps (state bound)
    DelegLife,  \* an issuer certificate's life from the root's signature (30 days)
    CertLife,   \* a machine certificate's life (24 h)
    Mutant      \* "none" or a bug put back (scripts/spec-orgmove.sh hosted)

Keys == {"k1", "k2"}
Hosts == {"self", "hosted"}
None == "none"
Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    now,       \* the clock
    signed,    \* signed[k]: the latest NotAfter the root signed for k (0: never)
    cert,      \* cert[k]: the NotAfter of the issuer certificate k presents
    loc,       \* loc[k]: "self", "hosted", "flight" (a sealed bundle) or None (lost)
    dest,      \* dest[k]: the host the fence names while k is in flight, else None
    serving,   \* the keys an issuer serves with
    auth,      \* the owner's authorisations <<k, host>>: genesis, a fence's recipient, a signed activation
    stolen,    \* keys the attacker holds (the hosted machine compromised)
    rcrl,      \* keys the root revoked (its CRL of issuers, published)
    taken,     \* keys whose revocation the verifier took
    sessions,  \* <<k, until>>: sessions a verifier admitted under k, open until until
    reach      \* the hosted side hears the owner's machine (FALSE: a partition)

vars == <<now, signed, cert, loc, dest, serving, auth, stolen, rcrl, taken, sessions, reach>>

TypeOK ==
    /\ now \in 0..MaxTime
    /\ signed \in [Keys -> 0..(MaxTime + DelegLife)]
    /\ cert \in [Keys -> 0..(MaxTime + DelegLife)]
    /\ loc \in [Keys -> Hosts \cup {"flight", None}]
    /\ dest \in [Keys -> Hosts \cup {None}]
    /\ serving \subseteq Keys
    /\ auth \subseteq Keys \X Hosts
    /\ stolen \subseteq Keys
    /\ rcrl \subseteq Keys
    /\ taken \subseteq rcrl
    /\ sessions \subseteq Keys \X (0..(MaxTime + CertLife))
    /\ reach \in BOOLEAN

Init ==
    /\ now = 0
    /\ signed = [k \in Keys |-> DelegLife]
    /\ cert = signed
    /\ loc = [k \in Keys |-> IF k = "k1" THEN "self" ELSE "hosted"]
    /\ dest = [k \in Keys |-> None]
    /\ serving = {"k1"}
    /\ auth = {<<"k1", "self">>}
    /\ stolen = {}
    /\ rcrl = {}
    /\ taken = {}
    /\ sessions = {}
    /\ reach = TRUE

\* Time passes; a session ends at its Until.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ sessions' = {s \in sessions : s[2] > now + 1}
    /\ UNCHANGED <<signed, cert, loc, dest, serving, auth, stolen, rcrl, taken, reach>>

\* The monthly renewal: the serving issuer's request, the root's answer
\* (org/orgpki renew.go). Only the root extends a delegation.
Renew(k) ==
    /\ k \in serving
    /\ k \notin rcrl
    /\ now + DelegLife > signed[k]
    /\ signed' = [signed EXCEPT ![k] = now + DelegLife]
    /\ cert' = [cert EXCEPT ![k] = now + DelegLife]
    /\ UNCHANGED <<now, loc, dest, serving, auth, stolen, rcrl, taken, sessions, reach>>

\* Mutant self-renew: the hosted issuer extends its own certificate (a
\* certificate the root did not sign that verifiers take anyway).
SelfRenew(k) ==
    /\ Mutant = "self-renew"
    /\ k \in serving
    /\ loc[k] = "hosted"
    /\ now + DelegLife > cert[k]
    /\ cert' = [cert EXCEPT ![k] = now + DelegLife]
    /\ UNCHANGED <<now, signed, loc, dest, serving, auth, stolen, rcrl, taken, sessions, reach>>

\* A verifier admits a machine certificate under k whose NotAfter is u.
\* An honest issuer caps u at its own certificate's NotAfter (org/orgpki
\* profile.go); the attacker, holding k, signs any u. The admission ends
\* at the earliest NotAfter of the chain (Until), or, under the mutant
\* until-leaf-only, at the leaf's alone.
Until(k, u) == IF Mutant = "until-leaf-only" THEN u ELSE Min(u, cert[k])

Admit(k, u) ==
    /\ k \in serving \/ k \in stolen
    /\ now < cert[k]
    /\ k \notin taken \/ Mutant = "ignore-root-crl"
    /\ k \in stolen \/ u <= cert[k]
    /\ Until(k, u) > now
    /\ sessions' = sessions \cup {<<k, Until(k, u)>>}
    /\ UNCHANGED <<now, signed, cert, loc, dest, serving, auth, stolen, rcrl, taken, reach>>

\* The hosted machine is compromised: the attacker holds every key there.
Compromise(k) ==
    /\ loc[k] = "hosted"
    /\ k \notin stolen
    /\ stolen' = stolen \cup {k}
    /\ UNCHANGED <<now, signed, cert, loc, dest, serving, auth, rcrl, taken, sessions, reach>>

\* The owner revokes an issuer: the root signs its CRL of issuers.
RevokeIssuer(k) ==
    /\ k \notin rcrl
    /\ rcrl' = rcrl \cup {k}
    /\ UNCHANGED <<now, signed, cert, loc, dest, serving, auth, stolen, taken, sessions, reach>>

\* The relay delivers the root's CRL to the verifier (when it likes): it
\* takes it and cuts every session under the revoked key.
Deliver(k) ==
    /\ Mutant # "no-push"
    /\ k \in rcrl \ taken
    /\ taken' = taken \cup {k}
    /\ sessions' = IF Mutant = "keep-sessions" THEN sessions ELSE {s \in sessions : s[1] # k}
    /\ UNCHANGED <<now, signed, cert, loc, dest, serving, auth, stolen, rcrl, reach>>

\* The fenced move (OrgMove.tla): the owner's order names the recipient
\* (onto hosted: the owner's own send to a receive key the hosting service
\* attested; off hosted: the root-signed order). The old side stops.
Fence(k, h) ==
    /\ k \in serving
    /\ loc[k] \in Hosts
    /\ h \in Hosts \ {loc[k]}
    /\ serving' = serving \ {k}
    /\ loc' = [loc EXCEPT ![k] = "flight"]
    /\ dest' = [dest EXCEPT ![k] = h]
    /\ auth' = (auth \ {<<k, loc[k]>>}) \cup {<<k, h>>}
    /\ UNCHANGED <<now, signed, cert, stolen, rcrl, taken, sessions, reach>>

Import(k) ==
    /\ loc[k] = "flight"
    /\ loc' = [loc EXCEPT ![k] = dest[k]]
    /\ dest' = [dest EXCEPT ![k] = None]
    /\ serving' = serving \cup {k}
    /\ UNCHANGED <<now, signed, cert, auth, stolen, rcrl, taken, sessions, reach>>

\* The owner's machine and its issuer are lost (no move under way).
LoseSelf(k) ==
    /\ loc[k] = "self"
    /\ loc' = [loc EXCEPT ![k] = None]
    /\ serving' = serving \ {k}
    /\ auth' = auth \ {<<k, "self">>}
    /\ UNCHANGED <<now, signed, cert, dest, stolen, rcrl, taken, sessions, reach>>

\* The hosted side's view of the owner's machine comes and goes.
Partition ==
    /\ reach' = ~reach
    /\ UNCHANGED <<now, signed, cert, loc, dest, serving, auth, stolen, rcrl, taken, sessions>>

\* The owner's signed activation of the standby, only when no issuer serves
\* (the owner's act is its fence; its design is the high-availability one).
OwnerActivate(k) ==
    /\ loc[k] = "hosted"
    /\ k \notin serving
    /\ k \notin rcrl
    /\ serving = {}
    /\ ~\E j \in Keys : loc[j] = "flight"
    /\ serving' = {k}
    /\ auth' = auth \cup {<<k, "hosted">>}
    /\ UNCHANGED <<now, signed, cert, loc, dest, stolen, rcrl, taken, sessions, reach>>

\* Mutant auto-takeover: the hosted side activates the standby because it
\* no longer hears the owner's issuer (the owner's CRL seems to lapse).
AutoActivate(k) ==
    /\ Mutant = "auto-takeover"
    /\ ~reach
    /\ loc[k] = "hosted"
    /\ k \notin serving
    /\ serving' = serving \cup {k}
    /\ UNCHANGED <<now, signed, cert, loc, dest, auth, stolen, rcrl, taken, sessions, reach>>

Next ==
    \/ Tick
    \/ Partition
    \/ \E k \in Keys :
        \/ Renew(k) \/ SelfRenew(k) \/ Compromise(k) \/ RevokeIssuer(k)
        \/ Deliver(k) \/ Import(k) \/ LoseSelf(k) \/ OwnerActivate(k) \/ AutoActivate(k)
        \/ \E h \in Hosts : Fence(k, h)
        \/ \E u \in (now + 1)..(now + CertLife) : Admit(k, u)

Spec == Init /\ [][Next]_vars

\* The relay is honest in the end: a revocation it carries is delivered.
LiveSpec == Spec /\ \A k \in Keys : WF_vars(Deliver(k))

\* At most one issuer serves at any time.
AtMostOneIssuer == Cardinality(serving) <= 1

\* No takeover: an issuer serves only where the owner put it (genesis, a
\* fence naming that host, a signed activation).
ServingAuthorized == \A k \in serving : <<k, loc[k]>> \in auth

\* The delegation's bound: no session under an issuer key outlives the
\* NotAfter the root signed for it, whoever holds the key.
DelegationBound == \A s \in sessions : s[2] <= signed[s[1]]

\* The root's revocation ends the issuer for a verifier that took it.
RevokedIssuerRefused == \A s \in sessions : s[1] \notin taken

\* Liveness (LiveSpec): a revocation the root signed reaches the verifier.
RevokeTakesEffect == \A k \in Keys : (k \in rcrl) ~> (k \in taken)

\* Witnesses (each must be violated: the states are reachable).
WitnessHostedServes == ~("k1" \in serving /\ loc["k1"] = "hosted")
WitnessMovedOff == ~("k1" \in serving /\ loc["k1"] = "self" /\ <<"k1", "hosted">> \notin auth /\ stolen # {})
WitnessStolenSession == ~(\E s \in sessions : s[1] \in stolen)
WitnessRevokedCut == ~(\E k \in stolen : k \in taken /\ now < signed[k])
WitnessOwnerActivated == ~("k2" \in serving)
WitnessRenewed == ~(signed["k1"] > DelegLife)
=============================================================================
