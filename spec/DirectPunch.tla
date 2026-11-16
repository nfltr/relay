---------------------------- MODULE DirectPunch ----------------------------
(* One punch of a direct path with peer-reflexive candidates (design:
   nfltr docs/decisions/nat-symmetric-lan-2026-11-16.md; spec/README.md
   "DirectPunch.tla"). The client of a pair dials every candidate the
   agent's offer named at once on its one UDP socket; while it punches it
   also reads the agent's probes, and a probe that carries the exchange's
   tag from an address it is not dialling is a peer-reflexive candidate
   (ICE, RFC 8445 sections 7.2.5.3.1 and 7.3.1.3): the client dials it
   too. That opens a public client toward an agent behind an
   endpoint-dependent (symmetric) NAT: the agent's probe leaves from a
   fresh mapping toward the client, which only the client's answer there
   passes.

   What this module checks, one punch attempt of one pair:
   - a learned candidate comes only from a probe with the exchange's tag
     (a probe tag is an exporter of the control session's TLS: only the
     agent of that exchange can make one, so an off-path sender cannot
     aim the client's QUIC Initials at a third party);
   - at most MaxCands dials per punch, whatever the probes;
   - the punch keeps one connection: the first that passes the
     certificate check; every other is closed, and the punch returns only
     once no dial of it is left running, so no second connection outlives
     it (D7: one direct connection per machine pair);
   - the punch ends: on a win, or at its bound (the design's 5 s), and then
     the session stays relayed.

   Below this module (assumed): who answers at an address is the TLS
   certificate check (relay spec/proverif/e2ee_tcp.pv, BIND:direct.cert);
   the session's moves onto the won connection are link's
   spec/DirectPath.tla. Abstracted: time (Tick steps toward the bound),
   the NATs (an address either answers as the peer, answers as someone
   else, or never answers), packet contents. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Offered,   \* the candidates the agent's offer named
    Prflx,     \* addresses the agent's probes may leave from (its fresh mappings)
    Spoofed,   \* addresses an off-path sender puts on untagged probes
    Peer,      \* addresses where the agent answers (its certificate)
    Rogue,     \* addresses where someone else answers (refused)
    MaxCands,  \* the most dials one punch makes (quiclink.MaxCandidates)
    Bound,     \* the punch's bound, in ticks
    Mutant     \* "none" or the failure put back (scripts/spec.sh mutants)

Addrs == Offered \cup Prflx \cup Spoofed
None == "none"

VARIABLES
    dial,     \* address -> "idle" | "dialing" | "up" | "failed" | "closed"
    probes,   \* probes in flight to the client: [src, tagged]
    won,      \* the kept connection's address, or None
    t,        \* ticks since the punch began
    state     \* "punching" | "returned"

vars == <<dial, probes, won, t, state>>

Dialled == {a \in Addrs : dial[a] # "idle"}
Up == {a \in Addrs : dial[a] = "up"}
Running == {a \in Addrs : dial[a] \in {"dialing", "up"} /\ a # won}

Init ==
    /\ dial = [a \in Addrs |-> IF a \in Offered THEN "dialing" ELSE "idle"]
    /\ probes = {}
    /\ won = None
    /\ t = 0
    /\ state = "punching"

\* The agent probes the client's candidates from one of its mappings.
AgentProbe(a) ==
    /\ state = "punching" /\ t < Bound
    /\ probes' = probes \cup {[src |-> a, tagged |-> TRUE]}
    /\ UNCHANGED <<dial, won, t, state>>

\* Anyone sends a probe without the tag from an address of its choosing.
SpoofProbe(a) ==
    /\ state = "punching"
    /\ probes' = probes \cup {[src |-> a, tagged |-> FALSE]}
    /\ UNCHANGED <<dial, won, t, state>>

\* The client reads a probe: a tagged one from an address it does not
\* dial yet is a candidate, dialled within the cap, before the bound and
\* while no connection has won.
Learn(p) ==
    /\ state = "punching"
    /\ probes' = probes \ {p}
    /\ IF /\ (p.tagged \/ Mutant = "no-tag")
          /\ dial[p.src] = "idle"
          /\ won = None /\ t < Bound
          /\ (Cardinality(Dialled) < MaxCands \/ Mutant = "no-cap")
       THEN dial' = [dial EXCEPT ![p.src] = "dialing"]
       ELSE UNCHANGED dial
    /\ UNCHANGED <<won, t, state>>

\* A dial's handshake passes the certificate check.
DialUp(a) ==
    /\ dial[a] = "dialing"
    /\ (a \in Peer \/ (Mutant = "no-cert-check" /\ a \in Rogue))
    /\ dial' = [dial EXCEPT ![a] = "up"]
    /\ UNCHANGED <<probes, won, t, state>>

\* A dial fails: someone else answered (refused), or the punch's
\* context ended it.
DialFail(a) ==
    /\ dial[a] = "dialing"
    /\ (a \in Rogue \/ t = Bound \/ won # None)
    /\ ~(Mutant = "no-cert-check" /\ a \in Rogue)
    /\ dial' = [dial EXCEPT ![a] = "failed"]
    /\ UNCHANGED <<probes, won, t, state>>

\* The first connection up is kept; the dials still running are told to
\* give up (the context's cancel).
Win(a) ==
    /\ state = "punching" /\ won = None /\ dial[a] = "up"
    /\ won' = a
    /\ UNCHANGED <<dial, probes, t, state>>

\* Another connection that came up is closed.
CloseLoser(a) ==
    /\ dial[a] = "up" /\ won # None /\ a # won
    /\ Mutant # "keep-loser"
    /\ dial' = [dial EXCEPT ![a] = "closed"]
    /\ UNCHANGED <<probes, won, t, state>>

Tick ==
    /\ state = "punching" /\ won = None /\ t < Bound
    /\ Mutant # "no-bound"
    /\ t' = t + 1
    /\ UNCHANGED <<dial, probes, won, state>>

\* The punch returns: won, or at its bound; once no dial of it runs
\* (mutant return-early: as soon as it has a winner).
Return ==
    /\ state = "punching"
    /\ (won # None \/ t = Bound)
    /\ (Running = {} \/ Mutant = "return-early")
    /\ state' = "returned"
    /\ UNCHANGED <<dial, probes, won, t>>

Next ==
    \/ \E a \in Prflx : AgentProbe(a)
    \/ \E a \in Spoofed : SpoofProbe(a)
    \/ \E p \in probes : Learn(p)
    \/ \E a \in Addrs : DialUp(a) \/ DialFail(a) \/ Win(a) \/ CloseLoser(a)
    \/ Tick
    \/ Return

\* Fair: the client reads its probes, the punch's context ends its dials,
\* the clock runs. Not fair: the agent's probes and a dial's answer (a
\* NAT may drop every packet of either).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ \A p \in [src : Addrs, tagged : BOOLEAN] : WF_vars(Learn(p))
    /\ \A a \in Addrs : WF_vars(DialFail(a)) /\ WF_vars(Win(a)) /\ WF_vars(CloseLoser(a))
    /\ WF_vars(Tick) /\ WF_vars(Return)

TypeOK ==
    /\ dial \in [Addrs -> {"idle", "dialing", "up", "failed", "closed"}]
    /\ probes \subseteq [src : Addrs, tagged : BOOLEAN]
    /\ won \in Addrs \cup {None}
    /\ t \in 0..Bound
    /\ state \in {"punching", "returned"}

\* A dialled address is an offered one or a tagged probe's source.
OnlyTagged == Dialled \subseteq Offered \cup Prflx

DialBound == Cardinality(Dialled) <= MaxCands

\* The kept connection is the peer's.
OnlyPeer == won # None => won \in Peer

\* Once the punch returned, the only connection of it is the kept one.
OneConnection == state = "returned" => Up \subseteq {won}

\* Every punch returns, and with no winner none of its connections is up.
Ends == <>(state = "returned")

\* Witnesses (scripts/spec.sh mutants: each must be violated).
W_PrflxWon == ~(state = "returned" /\ won \in Prflx \ Offered)
W_OfferedWon == ~(state = "returned" /\ won \in Offered)
W_Relayed == ~(state = "returned" /\ won = None)
W_RogueRefused == ~(\E a \in Rogue : dial[a] = "failed")
W_LoserClosed == ~(\E a \in Addrs : dial[a] = "closed")
=============================================================================
