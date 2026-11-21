----------------------------- MODULE PunchRound -----------------------------
(* One punch round of a direct path: the control exchanges over the relay,
   the timing of the client's dial and the retries (design: nfltr
   docs/decisions/direct-punch-timing-2026-11-21.md; spec/README.md
   "PunchRound.tla"). Prior art: a simultaneous open timed from an RTT
   measured over the relayed control channel, the dial at RTT/2 after the
   sync, up to three attempts each with its own exchange and measurement
   (a coordinated hole punch: Ford, Srisuresh and Kegel, "Peer-to-Peer
   Communication Across Network Address Translators", USENIX 2005; the
   synchronisation rule of the decision doc's prior-art section).

   One attempt: the client sends its request on the control session and
   times it; the agent's offer comes back after the relay's round trip
   (rtt); the client sends its candidates (the sync) and dials them rtt/2
   later; the agent probes the client's candidates as soon as it reads
   them, which is about rtt/2 after the sync. So the agent's first probe
   leaves its NAT before the client's first QUIC Initial reaches it: the
   first Initial passes, not a retransmit one PTO later. The attempt's
   dials themselves are DirectPunch.tla: here only its end (won, no
   answer at its bound, a refused certificate) and its first Initial.

   What this module checks, for one pair's round:
   - at most MaxAttempts attempts, each with its own exchange and RTT;
   - a new attempt only after one that no candidate answered (never after
     a refused certificate or a withheld exchange);
   - the client dials no sooner than rtt/2 after its sync, so (under the
     relay's bounded asymmetry, below) its first Initial reaches the
     agent's NAT once the agent's first probe left it;
   - the round ends, direct or relayed, whatever the peer and the network
     do: a peer that vanishes mid-exchange ends it at the control bound,
     mid-punch at the punch bound;
   - the session is never held by the round: it runs relayed until the
     round returns direct.

   Environment (assumed; spec/README.md "PunchRound.tla" table): the
   relay's one-way delays are each in Delays and may change between
   attempts; their difference is at most twice the direct one-way delay
   Dd (the bounded asymmetry); the agent answers the request and probes
   on reading the sync at once (no processing time); a NAT either lets a
   punch through (Kind "cone") or never (Kind "symmetric"), and the
   network may drop every packet of an attempt (Lose). Time is ticks. *)
EXTENDS Naturals

CONSTANTS
    Delays,       \* the relay's possible one-way delays, in ticks
    Dd,           \* the direct path's one-way delay
    PTO,          \* the client's QUIC Initial retransmit interval
    PunchBound,   \* one attempt's dial bound (the design's 5 s)
    CtlBound,     \* one exchange's bound (directControlBound)
    MaxAttempts,  \* attempts per round (3)
    Kind,         \* "cone": a punch can pass; "symmetric": never
    Mutant        \* "none" or the failure put back (scripts/spec.sh mutants)

Never == 1000
Finals == {"direct", "relayed"}
Horizon == (MaxAttempts + 1) * (CtlBound + PunchBound + 2 * Dd + 2 * PTO)

VARIABLES
    att,      \* attempts begun
    phase,    \* "idle" | "exchange" | "sync" | "dialing" | "retry" | "direct" | "relayed" | "stuck"
    t,        \* ticks since the round began
    sent,     \* when this attempt's request left
    dca, dac, \* this attempt's relay delays, client to agent and back
    offerAt,  \* when the agent's offer reaches the client (Never: it never does)
    rtt,      \* the round trip this attempt measured
    rtt1,     \* the first attempt's (mutant stale-rtt reuses it)
    syncAt,   \* when the client sent its candidates
    probeAt,  \* when the agent's first probe leaves its NAT (Never: none)
    dialAt,   \* when the client's first Initial left
    reason,   \* the last attempt's end: "" | "no_answer" | "refused" | "withheld"
    began,    \* the reason the current attempt followed ("" for the first)
    gone,     \* the agent vanished
    lost,     \* the network drops this attempt's packets
    path      \* the session's path: "relayed" | "direct" | "held"

vars == <<att, phase, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, reason, began, gone, lost, path>>

\* The client's wait after its sync before it dials.
Wait == CASE Mutant = "dial-before-sync" -> 0
          [] Mutant = "stale-rtt" -> rtt1 \div 2
          [] OTHER -> rtt \div 2

\* The first Initial at or after the probe left (k retransmits), or Never.
PassAt == IF Kind = "cone" /\ probeAt # Never /\ ~lost
          THEN LET ks == {k \in 0..(PunchBound \div PTO) : dialAt + k * PTO + Dd >= probeAt}
               IN IF ks = {} THEN Never ELSE dialAt + (CHOOSE k \in ks : \A j \in ks : k <= j) * PTO
          ELSE Never

Init ==
    /\ att = 0 /\ phase = "idle" /\ t = 0 /\ sent = 0
    /\ dca = 0 /\ dac = 0 /\ offerAt = Never /\ rtt = 0 /\ rtt1 = 0
    /\ syncAt = 0 /\ probeAt = Never /\ dialAt = 0
    /\ reason = "" /\ began = "" /\ gone = FALSE /\ lost = FALSE
    /\ path = "relayed"

\* The client begins an attempt: its request leaves (the relay's delays
\* for this attempt are the network's choice). A retry only after no
\* answer (mutant retry-refused: after any failure), and at most
\* MaxAttempts (mutant unbounded: no cap).
Start ==
    /\ \/ phase = "idle"
       \/ /\ phase = "retry"
          /\ att < MaxAttempts \/ Mutant = "unbounded"
    /\ t < Horizon
    /\ \E x, y \in Delays :
        /\ dca' = x /\ dac' = y
        /\ offerAt' = IF gone THEN Never ELSE t + x + y
    /\ att' = att + 1
    /\ phase' = "exchange"
    /\ sent' = t
    /\ began' = reason
    /\ lost' = FALSE
    /\ path' = IF Mutant = "block-during-punch" THEN "held" ELSE path
    /\ UNCHANGED <<t, rtt, rtt1, syncAt, probeAt, dialAt, reason, gone>>

\* The offer arrives: the client has its RTT and sends its candidates
\* (the sync) at once; the agent reads them dca later and probes.
Sync ==
    /\ phase = "exchange" /\ t = offerAt
    /\ rtt' = t - sent
    /\ rtt1' = IF att = 1 THEN t - sent ELSE rtt1
    /\ syncAt' = t
    /\ probeAt' = IF gone THEN Never ELSE t + dca
    /\ phase' = "sync"
    /\ UNCHANGED <<att, t, sent, dca, dac, offerAt, dialAt, reason, began, gone, lost, path>>

\* The exchange's bound passes with no offer (the agent vanished, the
\* relay withholds it): the round ends relayed (mutant wait-vanished:
\* the exchange has no bound).
Withheld ==
    /\ phase = "exchange" /\ offerAt = Never
    /\ t >= sent + CtlBound
    /\ Mutant # "wait-vanished"
    /\ reason' = "withheld"
    /\ phase' = "relayed"
    /\ path' = "relayed"
    /\ UNCHANGED <<att, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, began, gone, lost>>

\* rtt/2 after the sync the client dials its candidates.
Dial ==
    /\ phase = "sync" /\ t = syncAt + Wait
    /\ dialAt' = t
    /\ phase' = "dialing"
    /\ UNCHANGED <<att, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, reason, began, gone, lost, path>>

\* A handshake completes: an Initial that passed the agent's NAT and its
\* answer (two one-way trips), within the attempt's bound.
Win ==
    /\ phase = "dialing"
    /\ PassAt # Never
    /\ t = PassAt + 2 * Dd
    /\ t <= dialAt + PunchBound
    /\ phase' = "direct"
    /\ path' = "direct"
    /\ reason' = ""
    /\ UNCHANGED <<att, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, began, gone, lost>>

\* The attempt's bound passes with no winner: retried, or relayed after
\* the last (mutant no-fallback: the round never returns).
NoAnswer ==
    /\ phase = "dialing"
    /\ t = dialAt + PunchBound
    /\ reason' = "no_answer"
    /\ phase' = IF att < MaxAttempts \/ Mutant = "unbounded" THEN "retry"
                ELSE IF Mutant = "no-fallback" THEN "stuck" ELSE "relayed"
    /\ path' = IF phase' = "relayed" THEN "relayed" ELSE path
    /\ UNCHANGED <<att, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, began, gone, lost>>

\* Someone else answered (the certificate check refused it): relayed, no
\* retry (the relay chose the addresses).
Refused ==
    /\ phase = "dialing"
    /\ reason' = "refused"
    /\ phase' = IF Mutant = "retry-refused" /\ att < MaxAttempts THEN "retry" ELSE "relayed"
    /\ path' = IF phase' = "relayed" THEN "relayed" ELSE path
    /\ UNCHANGED <<att, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, began, gone, lost>>

\* The agent vanishes: an offer not yet sent never comes, a probe not yet
\* sent never leaves.
Vanish ==
    /\ ~gone /\ phase \notin Finals
    /\ gone' = TRUE
    /\ offerAt' = IF phase = "exchange" /\ t < sent + dca THEN Never ELSE offerAt
    /\ probeAt' = IF probeAt > t THEN Never ELSE probeAt
    /\ UNCHANGED <<att, phase, t, sent, dca, dac, rtt, rtt1, syncAt, dialAt, reason, began, lost, path>>

\* The network drops the attempt's packets.
Lose ==
    /\ phase \in {"sync", "dialing"} /\ ~lost
    /\ lost' = TRUE
    /\ UNCHANGED <<att, phase, t, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, reason, began, gone, path>>

\* The next instant a timed action is due.
Due == CASE phase = "exchange" -> IF offerAt # Never THEN offerAt
                                  ELSE IF Mutant = "wait-vanished" THEN Never ELSE sent + CtlBound
         [] phase = "sync" -> syncAt + Wait
         [] phase = "dialing" -> IF PassAt # Never /\ PassAt + 2 * Dd <= dialAt + PunchBound
                                 THEN PassAt + 2 * Dd ELSE dialAt + PunchBound
         [] OTHER -> Never

Tick ==
    /\ phase \in {"exchange", "sync", "dialing"}
    /\ t < Due /\ t < Horizon
    /\ t' = t + 1
    /\ UNCHANGED <<att, phase, sent, dca, dac, offerAt, rtt, rtt1, syncAt, probeAt, dialAt, reason, began, gone, lost, path>>

Next == Start \/ Sync \/ Withheld \/ Dial \/ Win \/ NoAnswer \/ Refused \/ Vanish \/ Lose \/ Tick

\* Fair: the client and the clock. Not fair: the agent's vanishing, the
\* network's losses, a rogue's answer.
Spec == Init /\ [][Next]_vars
        /\ WF_vars(Start) /\ WF_vars(Sync) /\ WF_vars(Withheld) /\ WF_vars(Dial)
        /\ WF_vars(Win) /\ WF_vars(NoAnswer) /\ WF_vars(Tick)

TypeOK ==
    /\ att \in 0..(MaxAttempts + 1)
    /\ phase \in {"idle", "exchange", "sync", "dialing", "retry", "direct", "relayed", "stuck"}
    /\ t \in 0..Horizon
    /\ reason \in {"", "no_answer", "refused", "withheld"}
    /\ began \in {"", "no_answer", "refused", "withheld"}
    /\ gone \in BOOLEAN /\ lost \in BOOLEAN
    /\ path \in {"relayed", "direct", "held"}

\* At most MaxAttempts attempts per round.
RetryBound == att <= MaxAttempts

\* A retry follows only an attempt no candidate answered.
RetryOnlyNoAnswer == att > 1 => began = "no_answer"

\* The client's first Initial reaches the agent's NAT once the agent's
\* first probe left it (the RTT-timed sync).
InitialAfterProbe == phase = "dialing" /\ probeAt # Never => dialAt + Dd >= probeAt

\* The session runs relayed until the round moves it, never held.
NeverHeld == path \in {"relayed", "direct"}
DirectOnlyWon == path = "direct" <=> phase = "direct"

\* A won attempt won on its first Initial (no retransmit was needed).
FirstInitialWins == phase = "direct" => PassAt = dialAt

\* Every round ends, direct or relayed.
Ends == <>(phase \in Finals)

\* Witnesses (scripts/spec.sh mutants: each must be violated).
W_DirectFirst == ~(phase = "direct" /\ att = 1)
W_DirectRetry == ~(phase = "direct" /\ att > 1)
W_RelayedAfterRetries == ~(phase = "relayed" /\ att = MaxAttempts /\ reason = "no_answer")
W_VanishedRelayed == ~(phase = "relayed" /\ gone /\ reason = "withheld")
W_Refused == ~(phase = "relayed" /\ reason = "refused")
=============================================================================
