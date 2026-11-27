------------------------------ MODULE CertRide ------------------------------
\* A machine's certificate rides out an issuer outage (lane ORGCERT72, nfltr
\* docs/decisions/issuer-outage-2026-11-25.md "Machine certificates";
\* spec/enrol/README.md "CertRide.tla"). The machine renews at half its
\* certificate's lifetime, up to a tenth of it later (orgmachine.RenewDue:
\* spread by the serial), asking again at most FollowEvery apart while
\* the issuer does not answer (orgenrol.Keeper.Run: 30 s doubling to
\* FollowEvery). A renewal needs the issuer and the mailbox it reads
\* (the renewal path); either down is an outage here. The CRL's ride-out
\* (CrlCarriers.tla RideOutage, 22 h 45 min) bounds what an organisation
\* rides out; this model checks that the certificate does not bound it
\* lower: with the path out for less than Ride in all, the machine's
\* certificate never lapses. Time in hours, rounded against the design:
\* Ride 24 (outages up to 23 h, past the CRL's 22 h 45 min), FollowEvery
\* 1 (10 minutes), the spread a tenth rounded up; HostRide 7 (9 h left at
\* the latest due, one ask period lost per outage).
\*
\*
\* The SSH host certificate (lane ORGCERT72b): issued with every machine
\* certificate (orgpki.Issuer.HostCert), from its NotBefore, for HostLife
\* or the machine certificate's life if shorter; the machine renews both
\* when the earlier of the two is due (orgmachine.RenewDue). OpenSSH reads
\* no CRL, so with every CRL withheld ssh trusts a revoked machine until
\* its host certificate ends (HostRevokeBound: within HostBound of the
\* revoke); a revoked machine is renewed no more (Enrol.tla
\* NoRenewAfterRevoke).
\*
\* Without loss of generality the certificates are due at 0: an outage
\* that starts before the due time spends Ride without hurting.
EXTENDS Integers

CONSTANTS
    MaxTime,
    CertLife,     \* orgpki.MachineLife (72 h)
    HostLife,     \* orgpki.HostLife (24 h)
    HostBound,    \* ssh trusts a revoked machine at most this long (24 h)
    FollowEvery,  \* the machine's ask, at most this far apart (orgenrol.FollowEvery)
    Ride,         \* the outage the organisation rides out (the CRL's, rounded up)
    HostRide,     \* the outage ssh rides out (the host certificate's, rounded down)
    MaxOutages,   \* outages of the renewal path
    Revokes,      \* the owner may revoke the machine (CertRideHost.cfg)
    Mutant

VARIABLES
    now,
    next,      \* the machine certificate's NotAfter
    hostNext,  \* the host certificate's ValidBefore
    due,       \* when the machine renews (RenewDue)
    askAt,     \* when the machine last asked (-1: not yet)
    up,        \* the renewal path (issuer and mailbox) answers
    downs,
    outFor,    \* hours the path has been out in all
    renewed,   \* the machine took a new certificate
    revokedAt  \* when the machine was revoked (-1: not)

vars == <<now, next, hostNext, due, askAt, up, downs, outFor, renewed, revokedAt>>

\* day-life: the 24 h lifetime before ORGCERT72 (half life 12 h: an
\* outage of 10 h past the due time lapsed every certificate while the
\* CRL still rode it out); two-thirds: renewal at two thirds of the
\* lifetime; ask-once: no ask after the first fails; host-life-equal: the
\* host certificate as long as the machine's (ORGCERT72 before
\* ORGCERT72b: ssh trusted a revoked machine up to 72 h).
Life == IF Mutant = "day-life" THEN 24 ELSE CertLife
HLife == IF Mutant = "host-life-equal" THEN Life ELSE IF HostLife < Life THEN HostLife ELSE Life
\* Due after issue: half the lifetime, up to a tenth later (f tenths of
\* that tenth: one serial spreads both certificates), rounded up.
DueOf(l, f) == IF Mutant = "two-thirds" THEN (2 * l) \div 3 + (l * f + 99) \div 100
               ELSE l \div 2 + (l * f + 99) \div 100
\* The spread's two ends (the bound is monotone in it).
Spreads == {0, 10}
DueAfter(f) == IF DueOf(HLife, f) < DueOf(Life, f) THEN DueOf(HLife, f) ELSE DueOf(Life, f)

AskDue ==
    /\ revokedAt < 0 \/ now < next   \* a revoked machine still asks while it holds a certificate
    /\ now >= due
    /\ now - askAt >= FollowEvery
    /\ Mutant # "ask-once" \/ askAt < due

TypeOK ==
    /\ now \in 0..MaxTime
    /\ askAt \in -1..MaxTime
    /\ up \in BOOLEAN /\ renewed \in BOOLEAN
    /\ downs \in 0..MaxOutages /\ outFor \in 0..MaxTime
    /\ revokedAt \in -1..MaxTime
    /\ hostNext <= next

Init ==
    /\ now = 0
    /\ \E f \in Spreads :
        /\ next = Life - DueAfter(f)
        /\ hostNext = HLife - DueAfter(f)
    /\ due = 0
    /\ askAt = -1
    /\ up = TRUE /\ downs = 0 /\ outFor = 0 /\ renewed = FALSE
    /\ revokedAt = -1

\* The machine asks; the issuer renews both certificates when the path is
\* up and the machine is not revoked.
Ask ==
    /\ AskDue
    /\ askAt' = now
    /\ IF up /\ revokedAt < 0
       THEN /\ next' = now + Life /\ hostNext' = now + HLife /\ renewed' = TRUE
            /\ \E f \in Spreads : due' = now + DueAfter(f)
       ELSE UNCHANGED <<next, hostNext, due, renewed>>
    /\ UNCHANGED <<now, up, downs, outFor, revokedAt>>

Down ==
    /\ up /\ downs < MaxOutages
    /\ up' = FALSE /\ downs' = downs + 1
    /\ UNCHANGED <<now, next, hostNext, due, askAt, outFor, renewed, revokedAt>>
Back ==
    /\ ~up
    /\ up' = TRUE
    /\ UNCHANGED <<now, next, hostNext, due, askAt, downs, outFor, renewed, revokedAt>>

\* The owner revokes the machine; every CRL is withheld from ssh (it
\* reads none anyway).
Revoke ==
    /\ Revokes /\ revokedAt < 0
    /\ revokedAt' = now
    /\ UNCHANGED <<now, next, hostNext, due, askAt, up, downs, outFor, renewed>>

\* Time passes once the ask due now was made.
Tick ==
    /\ now < MaxTime /\ ~AskDue
    /\ now' = now + 1
    /\ outFor' = IF up THEN outFor ELSE outFor + 1
    /\ UNCHANGED <<next, hostNext, due, askAt, up, downs, renewed, revokedAt>>

Next == Ask \/ Down \/ Back \/ Revoke \/ Tick

Spec == Init /\ [][Next]_vars

\* The path out for less than Ride in all: the machine certificate of a
\* machine not revoked is valid.
CertRideOutage == revokedAt < 0 /\ outFor < Ride => now < next

\* The path out for less than HostRide in all: the host certificate of a
\* machine not revoked is valid (ssh keeps working through a short outage).
HostRideOutage == revokedAt < 0 /\ outFor < HostRide => now < hostNext

\* ssh trusts a revoked machine (its host certificate valid) at most
\* HostBound after the revoke, with every CRL withheld.
HostRevokeBound == revokedAt >= 0 /\ now >= revokedAt + HostBound => now >= hostNext

\* Witnesses (each must be violated: reachable).
WitnessRodeOutage == ~(outFor = Ride - 1 /\ renewed)
WitnessLapsed == now < next
WitnessRenewedLate == ~(renewed /\ downs = MaxOutages /\ outFor > 0)
\* ssh still trusts a revoked machine for a while: the bound is real.
WitnessHostTrustedAfterRevoke == ~(revokedAt >= 0 /\ now >= revokedAt + HostBound - 2 /\ now < hostNext)
\* The cost: a long outage lapses the host certificate while the machine
\* certificate rides it out (ssh refused until the issuer is back).
WitnessHostLapsed == ~(revokedAt < 0 /\ hostNext <= now /\ now < next)
=============================================================================
