----------------------------- MODULE Birthday -----------------------------
(* Birthday probing for a pair with exactly one endpoint-dependent
   (symmetric) NAT (design: nfltr docs/decisions/hardnat-2026-11-25.md
   "birthday probing"; spec/README.md "Birthday.tla"; code: the next lane).
   Prior art: Tailscale "How NAT traversal works" (the birthday paradox,
   256 sockets x 1024 probes), RFC 4787 (EIM, EDM), RFC 5780 4.3 (mapping
   behaviour from a second observer).

   The hard side H opens K auxiliary sockets, each sending one tagged probe
   to the easy side E's reflexive address: its NAT gives each a port of its
   own, unknown to E. E sends tagged probes from its endpoint to H's
   offered address at guessed ports, at most N, at most Rate per tick. A
   guess that is one of H's ports passes H's NAT (the mapping toward E's
   address); H's auxiliary socket answers it tagged, E learns that address
   (peer-reflexive, as DirectPunch.tla's Learn) and dials it; the QUIC
   connection runs on that auxiliary socket.

   What this module checks, one spray attempt of one pair:
   - only an easy/hard pair sprays, and only after an attempt ended
     no_answer (SprayOnlyEasyHard);
   - at most N probes, at most Rate per tick, only to the peer's offered
     address (SprayBound, SprayOnlyPeer): no storm, no third party;
   - one connection (OneConnection), and at the return no auxiliary
     socket but the won one is open (AuxClosed);
   - relayed only when no guess was answered (DirectIfHit); an answered
     guess goes direct (HitGoesDirect); every attempt ends (Ends).

   Below this module (assumed): the punch's certificate check and the
   session's switch onto the won connection (DirectPunch.tla, link
   spec/DirectPath.tla) are unchanged. Abstracted: the NAT's port choice
   (any K ports), time (Tick), packet loss (a probe may never arrive). *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ports,      \* the hard side NAT's possible external ports
    K,          \* auxiliary sockets the hard side opens
    N,          \* the most probes the easy side sends
    Rate,       \* the most probes per tick
    Bound,      \* the attempt's bound, in ticks
    EdmE, EdmH, \* each side's mapping is endpoint-dependent (from two QAD observers)
    FirstFailed,\* the pair's previous attempt ended no_answer
    Mutant      \* "none" or the failure put back (scripts/spec.sh mutants)

Ips == {"peer", "third"}
None == 0
ASSUME None \notin Ports

VARIABLES
    aux,      \* the ports H's auxiliary sockets got (its NAT's choice)
    auxOpen,  \* those still open
    sent,     \* probes E sent
    tickSent, \* probes E sent this tick
    targets,  \* where E's probes went: <<ip, port>>
    arrived,  \* H's ports an E probe reached
    learned,  \* H's ports whose tagged answer E read
    up,       \* connections that came up (H's port)
    won,      \* the kept connection's port, or None
    t,
    state     \* "idle" | "spraying" | "returned"

vars == <<aux, auxOpen, sent, tickSent, targets, arrived, learned, up, won, t, state>>

Allowed == (EdmE # EdmH) /\ FirstFailed

Init ==
    /\ aux = {} /\ auxOpen = {}
    /\ sent = 0 /\ tickSent = 0 /\ targets = {}
    /\ arrived = {} /\ learned = {} /\ up = {}
    /\ won = None /\ t = 0
    /\ state = "idle"

\* The attempt starts: H opens its sockets and its NAT picks their ports
\* (mutant spray-hard-hard: any pair; spray-first: before an attempt failed).
Start ==
    /\ state = "idle"
    /\ \/ Allowed
       \/ Mutant = "spray-hard-hard" /\ FirstFailed
       \/ Mutant = "spray-first" /\ EdmE # EdmH
    /\ \E S \in SUBSET Ports : Cardinality(S) = K /\ aux' = S /\ auxOpen' = S
    /\ state' = "spraying"
    /\ UNCHANGED <<sent, tickSent, targets, arrived, learned, up, won, t>>

\* E sends one probe to ip:p (mutant any-target: an address no offer
\* named; no-cap: past N; no-pace: past Rate). It reaches H when p is one
\* of H's open ports, or not at all (lost).
Spray(ip, p) ==
    /\ state = "spraying" /\ won = None /\ t < Bound
    /\ (ip = "peer" \/ Mutant = "any-target")
    /\ (sent < N \/ Mutant = "no-cap")
    /\ (tickSent < Rate \/ Mutant = "no-pace")
    /\ sent' = sent + 1 /\ tickSent' = tickSent + 1
    /\ targets' = targets \cup {<<ip, p>>}
    /\ \/ (ip = "peer" /\ p \in auxOpen /\ arrived' = arrived \cup {p})
       \/ UNCHANGED arrived
    /\ UNCHANGED <<aux, auxOpen, learned, up, won, t, state>>

\* H's auxiliary socket answers the probe tagged; E reads the answer and
\* learns H's address at p.
Answer(p) ==
    /\ state = "spraying" /\ p \in arrived /\ p \in auxOpen /\ p \notin learned
    /\ learned' = learned \cup {p}
    /\ UNCHANGED <<aux, auxOpen, sent, tickSent, targets, arrived, up, won, t, state>>

\* E's dial of a learned address comes up; the first is kept (mutant
\* keep-all: every one; no-dial: E never dials what it learned).
Win(p) ==
    /\ state = "spraying" /\ p \in learned /\ p \in auxOpen /\ p \notin up
    /\ Mutant # "no-dial"
    /\ (won = None \/ Mutant = "keep-all")
    /\ up' = up \cup {p}
    /\ won' = IF won = None THEN p ELSE won
    /\ UNCHANGED <<aux, auxOpen, sent, tickSent, targets, arrived, learned, t, state>>

\* H closes an auxiliary socket the attempt no longer needs: once one won,
\* or at the bound one E did not learn (mutant keep-aux: never).
CloseAux(p) ==
    /\ p \in auxOpen /\ p # won
    /\ (won # None \/ (t = Bound /\ (p \notin learned \/ Mutant = "no-dial")))
    /\ Mutant # "keep-aux"
    /\ auxOpen' = auxOpen \ {p}
    /\ UNCHANGED <<aux, sent, tickSent, targets, arrived, learned, up, won, t, state>>

Tick ==
    /\ state = "spraying" /\ won = None /\ t < Bound
    /\ t' = t + 1 /\ tickSent' = 0
    /\ UNCHANGED <<aux, auxOpen, sent, targets, arrived, learned, up, won, state>>

\* The attempt returns: won, or at the bound; once only the won socket is
\* open (mutant return-early: at once). A learned address not yet dialled
\* keeps it running (DirectIfHit; mutant no-dial: it does not).
Return ==
    /\ state = "spraying"
    /\ won # None \/ (t = Bound /\ (learned = {} \/ Mutant = "no-dial"))
    /\ (auxOpen \subseteq {won} \/ Mutant = "return-early")
    /\ state' = "returned"
    /\ UNCHANGED <<aux, auxOpen, sent, tickSent, targets, arrived, learned, up, won, t>>

Next ==
    \/ Start
    \/ \E ip \in Ips, p \in Ports : Spray(ip, p)
    \/ \E p \in Ports : Answer(p) \/ Win(p) \/ CloseAux(p)
    \/ Tick \/ Return

\* Fair: an allowed attempt starts, H answers what reached it, E dials what
\* it learned, sockets close, the clock runs. Not fair: Spray's delivery (a
\* probe may be lost).
Spec ==
    /\ Init /\ [][Next]_vars /\ WF_vars(Start)
    /\ \A p \in Ports : WF_vars(Answer(p)) /\ WF_vars(Win(p)) /\ WF_vars(CloseAux(p))
    /\ WF_vars(Tick) /\ WF_vars(Return)

TypeOK ==
    /\ aux \subseteq Ports /\ auxOpen \subseteq aux
    /\ sent \in Nat /\ tickSent \in Nat
    /\ targets \subseteq Ips \X Ports
    /\ arrived \subseteq Ports /\ learned \subseteq Ports /\ up \subseteq Ports
    /\ won \in Ports \cup {None}
    /\ t \in 0..Bound
    /\ state \in {"idle", "spraying", "returned"}

SprayOnlyEasyHard == state # "idle" => Allowed
SprayBound == sent <= N /\ tickSent <= Rate
SprayOnlyPeer == \A x \in targets : x[1] = "peer"
OneConnection == Cardinality(up) <= 1
AuxClosed == state = "returned" => auxOpen \subseteq {won}
DirectIfHit == state = "returned" /\ won = None => learned = {}

Ends == Allowed => <>(state = "returned")
HitGoesDirect == (learned # {}) ~> (won # None)

\* Witnesses (scripts/spec.sh mutants: each must be violated).
W_Hit == ~(state = "returned" /\ won # None)
W_Miss == ~(state = "returned" /\ won = None /\ sent = N)
W_LostHit == ~(state = "returned" /\ won = None /\ \E p \in aux : <<"peer", p>> \in targets)
W_OthersClosed == ~(state = "returned" /\ won # None /\ aux # {won})
=============================================================================
