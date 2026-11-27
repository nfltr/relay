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
     the session stays relayed;
   - direct whenever a path works (owner 2026-11-16, "direct is always
     preferred and relay is when direct not possible"): a punch with a
     working candidate never returns relayed;
   - a LAN path first: a connection to a LAN address replaces a non-LAN
     winner, and the LAN dials outlive a non-LAN win by a grace
     (lanGrace) in which a LAN probe is still learned; the rest by
     measured handshake RTT (the first up among those dialled together);
   - no dial waits for the address check (trickle, lane TRICKLE; RFC 8838):
     the offered candidates are dialled from the punch's start, and the
     agent's reflexive address, which its relay's address check (QAD)
     answers later or never, comes as one more candidate on the control
     session (Trickled), dialled as a learned one.

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
    Trickled,  \* candidates the agent sends on the control session after its offer (its QAD answer)
    Peer,      \* addresses where the agent answers (its certificate)
    Rogue,     \* addresses where someone else answers (refused)
    Lan,       \* the private (LAN) addresses among Addrs
    Reach,     \* Peer addresses that answer before the bound (a working path)
    MaxCands,  \* the most dials one punch makes (quiclink.MaxCandidates)
    Bound,     \* the punch's bound, in ticks
    Mutant     \* "none" or the failure put back (scripts/spec.sh mutants)

Addrs == Offered \cup Prflx \cup Spoofed \cup Trickled
None == "none"

VARIABLES
    dial,     \* address -> "idle" | "dialing" | "up" | "failed" | "closed"
    probes,   \* probes in flight to the client: [src, tagged]
    won,      \* the kept connection's address, or None
    t,        \* ticks since the punch began
    state,    \* "punching" | "returned"
    settled,  \* the LAN grace after a non-LAN win ended
    qad       \* the agent's address check ended (answered or timed out)

vars == <<dial, probes, won, t, state, settled, qad>>

Dialled == {a \in Addrs : dial[a] # "idle"}
Up == {a \in Addrs : dial[a] = "up"}
Running == {a \in Addrs : dial[a] \in {"dialing", "up"} /\ a # won}
\* In the grace: a non-LAN connection won and LAN dials may still beat it
\* (mutant first-wins: no grace, the first connection up is kept).
Grace == won # None /\ won \notin Lan /\ ~settled /\ Mutant # "first-wins"
\* A connection to a which beats the winner: a LAN one over a non-LAN one,
\* in the grace or after it, until the punch returns.
Beats(a) == won # None /\ won \notin Lan /\ a \in Lan /\ Mutant # "first-wins"

Init ==
    \* Mutant wait-qad: the offered candidates wait for the address check
    \* (the bug: a silent QAD port held every punch for its 3 s timeout).
    /\ dial = [a \in Addrs |-> IF a \in Offered /\ Mutant # "wait-qad" THEN "dialing" ELSE "idle"]
    /\ probes = {}
    /\ won = None
    /\ t = 0
    /\ state = "punching"
    /\ settled = FALSE
    /\ qad = FALSE

\* The agent probes the client's candidates from one of its mappings.
AgentProbe(a) ==
    /\ state = "punching" /\ t < Bound
    /\ probes' = probes \cup {[src |-> a, tagged |-> TRUE]}
    /\ UNCHANGED <<dial, won, t, state, settled, qad>>

\* The agent's address check ends: answered or timed out (it may take
\* the whole punch or never answer: no fairness). Mutant wait-qad: only
\* now are the offered candidates dialled.
QADEnd ==
    /\ ~qad
    /\ qad' = TRUE
    /\ dial' = IF Mutant = "wait-qad" /\ state = "punching"
               THEN [a \in Addrs |-> IF a \in Offered THEN "dialing" ELSE dial[a]]
               ELSE dial
    /\ UNCHANGED <<probes, won, t, state, settled>>

\* The agent trickles its reflexive candidate on the control session once
\* its address check answered: authenticated by that session's TLS as a
\* tagged probe is by its tag, read as one (Learn).
AgentTrickle(a) ==
    /\ state = "punching" /\ qad
    /\ probes' = probes \cup {[src |-> a, tagged |-> TRUE]}
    /\ UNCHANGED <<dial, won, t, state, settled, qad>>

\* Anyone sends a probe without the tag from an address of its choosing.
SpoofProbe(a) ==
    /\ state = "punching"
    /\ probes' = probes \cup {[src |-> a, tagged |-> FALSE]}
    /\ UNCHANGED <<dial, won, t, state, settled, qad>>

\* The client reads a probe: a tagged one from an address it does not
\* dial yet is a candidate, dialled within the cap, before the bound and
\* while no connection has won (or, in the grace, a LAN one).
Learn(p) ==
    /\ state = "punching"
    /\ probes' = probes \ {p}
    /\ IF /\ (p.tagged \/ Mutant = "no-tag")
          /\ dial[p.src] = "idle"
          /\ (won = None \/ (Grace /\ p.src \in Lan)) /\ t < Bound
          /\ (Cardinality(Dialled) < MaxCands \/ Mutant = "no-cap")
       THEN dial' = [dial EXCEPT ![p.src] = "dialing"]
       ELSE UNCHANGED dial
    /\ UNCHANGED <<won, t, state, settled, qad>>

\* A dial's handshake passes the certificate check.
DialUp(a) ==
    /\ dial[a] = "dialing"
    /\ (a \in Peer \/ (Mutant = "no-cert-check" /\ a \in Rogue))
    /\ dial' = [dial EXCEPT ![a] = "up"]
    /\ UNCHANGED <<probes, won, t, state, settled, qad>>

\* A dial fails: someone else answered (refused), or the punch's
\* contexts ended it: at the bound, or once a connection won (a LAN dial
\* only once the grace ended or a LAN connection won).
DialFail(a) ==
    /\ dial[a] = "dialing"
    /\ (a \in Rogue \/ t = Bound \/ (won # None /\ ~(Grace /\ a \in Lan)))
    /\ ~(Mutant = "no-cert-check" /\ a \in Rogue)
    /\ dial' = [dial EXCEPT ![a] = "failed"]
    /\ UNCHANGED <<probes, won, t, state, settled, qad>>

\* The first connection up is kept, and a LAN one replaces a non-LAN
\* winner (the old winner is then a loser); the dials still running are
\* told to give up (the contexts' cancels).
Win(a) ==
    /\ state = "punching" /\ dial[a] = "up" /\ a # won
    /\ (won = None \/ Beats(a))
    /\ won' = a
    /\ UNCHANGED <<dial, probes, t, state, settled, qad>>

\* Another connection that came up is closed (not one that beats the
\* winner: it wins instead). Mutant give-up-at-bound: at the bound with no winner,
\* a connection that came up is closed too.
CloseLoser(a) ==
    /\ dial[a] = "up" /\ a # won
    /\ ((won # None /\ ~Beats(a)) \/ (Mutant = "give-up-at-bound" /\ won = None /\ t = Bound))
    /\ Mutant # "keep-loser"
    /\ dial' = [dial EXCEPT ![a] = "closed"]
    /\ UNCHANGED <<probes, won, t, state, settled, qad>>

\* The grace ends (lanGrace after the non-LAN win). Assumed: a LAN
\* handshake that will pass ends within it (a working LAN dial is not
\* left running).
Settle ==
    /\ Grace
    /\ \A a \in Lan \cap Reach : dial[a] # "dialing"
    /\ settled' = TRUE
    /\ UNCHANGED <<dial, probes, won, t, state, qad>>

\* The clock, until a winner (and through the grace). Assumed: a working
\* path's handshake ends before the bound (no tick past a Reach dial).
Tick ==
    /\ state = "punching" /\ (won = None \/ Grace) /\ t < Bound
    /\ \A a \in Reach : dial[a] # "dialing"
    /\ Mutant # "no-bound"
    /\ t' = t + 1
    /\ UNCHANGED <<dial, probes, won, state, settled, qad>>

\* The punch returns: won (a LAN connection, or the grace ended), or at
\* its bound; once no dial of it runs (mutant return-early: as soon as
\* it has a winner).
Return ==
    /\ state = "punching"
    /\ ((won # None /\ ~Grace) \/ t = Bound)
    /\ (Running = {} \/ Mutant = "return-early")
    /\ state' = "returned"
    /\ UNCHANGED <<dial, probes, won, t, settled, qad>>

Next ==
    \/ \E a \in Prflx : AgentProbe(a)
    \/ \E a \in Spoofed : SpoofProbe(a)
    \/ QADEnd
    \/ \E a \in Trickled : AgentTrickle(a)
    \/ \E p \in probes : Learn(p)
    \/ \E a \in Addrs : DialUp(a) \/ DialFail(a) \/ Win(a) \/ CloseLoser(a)
    \/ Settle
    \/ Tick
    \/ Return

\* Fair: the client reads its probes, the punch's context ends its dials,
\* the clock runs, a working path answers. Not fair: the agent's probes
\* and the other dials' answers (a NAT may drop every packet of either).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ \A p \in [src : Addrs, tagged : BOOLEAN] : WF_vars(Learn(p))
    /\ \A a \in Addrs : WF_vars(DialFail(a)) /\ WF_vars(Win(a)) /\ WF_vars(CloseLoser(a))
    /\ \A a \in Reach : WF_vars(DialUp(a))
    /\ WF_vars(Settle) /\ WF_vars(Tick) /\ WF_vars(Return)

TypeOK ==
    /\ dial \in [Addrs -> {"idle", "dialing", "up", "failed", "closed"}]
    /\ probes \subseteq [src : Addrs, tagged : BOOLEAN]
    /\ won \in Addrs \cup {None}
    /\ t \in 0..Bound
    /\ state \in {"punching", "returned"}
    /\ settled \in BOOLEAN
    /\ qad \in BOOLEAN

\* A dialled address is an offered one, a tagged probe's source or a
\* trickled one.
OnlyTagged == Dialled \subseteq Offered \cup Prflx \cup Trickled

\* No dial waits for the address check: every offered candidate is
\* dialled from the punch's start (trickle).
NoWait == \A a \in Offered : dial[a] # "idle"

DialBound == Cardinality(Dialled) <= MaxCands

\* The kept connection is the peer's.
OnlyPeer == won # None => won \in Peer

\* Once the punch returned, the only connection of it is the kept one.
OneConnection == state = "returned" => Up \subseteq {won}

\* Direct whenever a path works: a punch that returned relayed dialled
\* no working candidate and closed no connection.
DirectIfWorks == state = "returned" /\ won = None =>
    \A a \in Addrs : dial[a] # "closed" /\ (a \in Reach => dial[a] = "idle")

\* A LAN path first: a punch that returned on a non-LAN connection never
\* dialled a working LAN candidate.
PreferLan == state = "returned" /\ won # None /\ won \notin Lan =>
    \A a \in Lan \cap Reach : dial[a] = "idle"

\* Every punch returns, and with no winner none of its connections is up.
Ends == <>(state = "returned")

\* Witnesses (scripts/spec.sh mutants: each must be violated).
W_PrflxWon == ~(state = "returned" /\ won \in Prflx \ Offered)
W_OfferedWon == ~(state = "returned" /\ won \in Offered)
W_Relayed == ~(state = "returned" /\ won = None)
W_RogueRefused == ~(\E a \in Rogue : dial[a] = "failed")
W_LoserClosed == ~(\E a \in Addrs : dial[a] = "closed")
W_LanReplaced == ~(state = "returned" /\ won \in Lan /\ \E a \in Addrs \ Lan : dial[a] = "closed")
W_NonLanWon == ~(state = "returned" /\ won \in Peer \ Lan)
W_TrickledWon == ~(state = "returned" /\ won \in Trickled)
W_LanBeforeQAD == ~(state = "returned" /\ won \in Lan /\ ~qad)
=============================================================================
