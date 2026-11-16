------------------------- MODULE BrowserPeer -------------------------
(* An nf1 address opened in a browser (lane BROWSERPEER, design, no code
   yet; nfltr docs/decisions/browser-peer-2026-11-16.md). One visitor tab,
   one address, N streams (each an app stream or one HTTP request of the
   page), the serving agent's side.

   The control session is an nf1 session over the relay's WebSocket; once
   it is admitted the agent may create one RTCPeerConnection for it (the
   SDP travels inside the control session). Each stream is its own nf1
   session, opened on a data channel of that connection when the
   connection is up and the agent's data-channel cap leaves room, else on
   a WebSocket through the relay. A stream never changes path: when its
   path breaks it fails to the app, and only a new stream takes the other
   path (no replay, so a request reaches the service at most once). The
   agent closes the connection and its channels when the control session
   ends or the connection fails.

   ctl is the control session as the agent sees it, pc the connection as
   both ends see it (ICE and DTLS are the browser's and pion's), agentPC
   the agent's resources for it. Mutants (Mutant):
     "retry-other-path"   a stream whose path broke after its request was
                          written is re-sent on the other path
     "pc-before-admit"    the agent creates the connection for a control
                          session not yet admitted
     "no-dc-cap"          the agent takes data channels past MaxDC
     "pc-outlives-ctl"    the agent keeps the connection after the control
                          session ended (only its failure reaps it)
     "dc-without-pc"      the agent keeps a data channel after it reaped
                          the connection
     "no-break"           a data-channel stream whose connection is gone
                          waits instead of failing to the app *)
EXTENDS Naturals, FiniteSets

CONSTANTS N, MaxDC, MaxFail, Mutant

Streams == 1..N

VARIABLES ctl, pc, agentPC, st, path, sent, deliv, dc, fails

vars == <<ctl, pc, agentPC, st, path, sent, deliv, dc, fails>>

TypeOK ==
  /\ ctl \in {"none", "open", "admitted", "closed"}
  /\ pc \in {"none", "connecting", "up", "failed", "closed"}
  /\ agentPC \in {"none", "held", "closed"}
  /\ st \in [Streams -> {"idle", "open", "done", "failed"}]
  /\ path \in [Streams -> {"none", "ws", "dc"}]
  /\ sent \in [Streams -> BOOLEAN]
  /\ deliv \in [Streams -> 0..2]
  /\ dc \in [Streams -> BOOLEAN]
  /\ fails \in 0..MaxFail

Init ==
  /\ ctl = "none" /\ pc = "none" /\ agentPC = "none"
  /\ st = [s \in Streams |-> "idle"]
  /\ path = [s \in Streams |-> "none"]
  /\ sent = [s \in Streams |-> FALSE]
  /\ deliv = [s \in Streams |-> 0]
  /\ dc = [s \in Streams |-> FALSE]
  /\ fails = 0

DCs == {s \in Streams : dc[s]}

(* The visitor opens the control session; the agent admits it (the proof). *)
CtlOpen == ctl = "none" /\ ctl' = "open" /\ UNCHANGED <<pc, agentPC, st, path, sent, deliv, dc, fails>>
CtlAdmit == ctl = "open" /\ ctl' = "admitted" /\ UNCHANGED <<pc, agentPC, st, path, sent, deliv, dc, fails>>

(* The control session ends: the tab closed, the relay cut it, the agent
   dropped it. *)
CtlEnd ==
  /\ ctl \in {"open", "admitted"}
  /\ ctl' = "closed"
  /\ UNCHANGED <<pc, agentPC, st, path, sent, deliv, dc, fails>>

(* The agent answers the visitor's offer with its own, inside the admitted
   control session, and holds a connection for it. *)
Offer ==
  /\ IF Mutant = "pc-before-admit" THEN ctl \in {"open", "admitted"} ELSE ctl = "admitted"
  /\ pc = "none"
  /\ pc' = "connecting" /\ agentPC' = "held"
  /\ UNCHANGED <<ctl, st, path, sent, deliv, dc, fails>>

PCUp == pc = "connecting" /\ agentPC = "held" /\ pc' = "up" /\ UNCHANGED <<ctl, agentPC, st, path, sent, deliv, dc, fails>>

(* ICE or DTLS fails, or a NAT drops the binding (bounded). *)
PCFail ==
  /\ pc \in {"connecting", "up"}
  /\ fails < MaxFail
  /\ pc' = "failed" /\ fails' = fails + 1
  /\ UNCHANGED <<ctl, agentPC, st, path, sent, deliv, dc>>

(* The agent reaps the connection and its channels: its control session
   ended, or the connection failed. *)
Reap ==
  /\ agentPC = "held"
  /\ IF Mutant = "pc-outlives-ctl" THEN pc = "failed" ELSE (ctl = "closed" \/ pc = "failed")
  /\ agentPC' = "closed"
  /\ pc' = IF pc = "failed" THEN "failed" ELSE "closed"
  /\ dc' = IF Mutant = "dc-without-pc" THEN dc ELSE [s \in Streams |-> FALSE]
  /\ UNCHANGED <<ctl, st, path, sent, deliv, fails>>

(* A new stream: a data channel when the connection is up and the agent's
   cap leaves room, else a WebSocket through the relay. *)
OpenDC(s) ==
  /\ st[s] = "idle" /\ pc = "up" /\ agentPC = "held"
  /\ (Mutant = "no-dc-cap" \/ Cardinality(DCs) < MaxDC)
  /\ st' = [st EXCEPT ![s] = "open"] /\ path' = [path EXCEPT ![s] = "dc"]
  /\ dc' = [dc EXCEPT ![s] = TRUE]
  /\ UNCHANGED <<ctl, pc, agentPC, sent, deliv, fails>>

OpenWS(s) ==
  /\ st[s] = "idle"
  /\ st' = [st EXCEPT ![s] = "open"] /\ path' = [path EXCEPT ![s] = "ws"]
  /\ UNCHANGED <<ctl, pc, agentPC, sent, deliv, dc, fails>>

PathLive(s) == path[s] = "ws" \/ (path[s] = "dc" /\ dc[s] /\ pc = "up")

(* The stream's request reaches the service (its nf1 handshake done). *)
Deliver(s) ==
  /\ st[s] = "open" /\ ~sent[s] /\ PathLive(s)
  /\ sent' = [sent EXCEPT ![s] = TRUE]
  /\ deliv' = [deliv EXCEPT ![s] = deliv[s] + 1]
  /\ UNCHANGED <<ctl, pc, agentPC, st, path, dc, fails>>

Complete(s) ==
  /\ st[s] = "open" /\ sent[s] /\ PathLive(s)
  /\ st' = [st EXCEPT ![s] = "done"]
  /\ dc' = [dc EXCEPT ![s] = FALSE]
  /\ UNCHANGED <<ctl, pc, agentPC, path, sent, deliv, fails>>

(* A data channel stream whose connection is gone: an error to the app
   (or, mutant, re-sent on a WebSocket). *)
Break(s) ==
  /\ st[s] = "open" /\ path[s] = "dc" /\ ~PathLive(s)
  /\ Mutant /= "no-break"
  /\ dc' = [dc EXCEPT ![s] = FALSE]
  /\ IF Mutant = "retry-other-path"
       THEN /\ path' = [path EXCEPT ![s] = "ws"] /\ sent' = [sent EXCEPT ![s] = FALSE]
            /\ UNCHANGED st
       ELSE /\ st' = [st EXCEPT ![s] = "failed"] /\ UNCHANGED <<path, sent>>
  /\ UNCHANGED <<ctl, pc, agentPC, deliv, fails>>

Next ==
  \/ CtlOpen \/ CtlAdmit \/ CtlEnd \/ Offer \/ PCUp \/ PCFail \/ Reap
  \/ \E s \in Streams : OpenDC(s) \/ OpenWS(s) \/ Deliver(s) \/ Complete(s) \/ Break(s)

(* The agent's steps and the streams' ends are weakly fair; the visitor's
   choices (opening, ending) and the network's failures are not. *)
Spec == Init /\ [][Next]_vars /\ WF_vars(Reap)
        /\ \A s \in Streams : WF_vars(Deliver(s)) /\ WF_vars(Complete(s)) /\ WF_vars(Break(s))

(* A request reaches the service at most once. *)
AtMostOnce == \A s \in Streams : deliv[s] <= 1
(* The agent holds a connection only for an admitted control session
   (or one admitted and since ended, until it reaps). *)
PCOnlyAdmitted == agentPC = "held" => ctl \in {"admitted", "closed"}
(* No data channel without the connection; at most MaxDC at once. *)
DCOnPC == \A s \in Streams : dc[s] => agentPC = "held"
DCBounded == Cardinality(DCs) <= MaxDC
(* The agent's connection ends once its control session has. *)
Reaped == (ctl = "closed") ~> (agentPC /= "held")
(* Every opened stream ends: done or failed to the app. *)
StreamsEnd == \A s \in Streams : (st[s] = "open") ~> (st[s] \in {"done", "failed"})

(* Witnesses (each must be violated): a stream done over a data channel;
   one done over the relay after the connection failed; one failed to the
   app; the agent reaping after the control session ended. *)
W_DoneDC == ~\E s \in Streams : st[s] = "done" /\ path[s] = "dc"
W_DoneWSAfterFail == ~\E s \in Streams : st[s] = "done" /\ path[s] = "ws" /\ pc = "failed"
W_Failed == ~\E s \in Streams : st[s] = "failed"
W_ReapedAfterCtl == ~(ctl = "closed" /\ agentPC = "closed" /\ pc = "closed")
=============================================================================
