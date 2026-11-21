-------------------------- MODULE TracePunchRound --------------------------
(* Trace validation of PunchRound.tla (spec/README.md "PunchRound
   traces"): the steps the client took in one real punch round (-tags
   relaytrace, client/agent trace_round_on.go) must be a behaviour of
   PunchRound: each attempt's Start (its number), Sync (the exchange's
   measured rtt), Dial (the wait after the sync and the time since it),
   and its end: Win, NoAnswer, Refused, or Withheld (any end before a
   dial: no offer, the offer's refusal, no candidates). The relay's
   delays, the clock, the network's losses and the agent's vanishing are
   not logged: TLC takes Tick, Lose and Vanish only when the next logged
   step needs one. Each Dial must also have waited at least half its rtt
   and dialled no sooner than that wait (microseconds, rounded down).
   Accepted when TLC reaches the trace's end: TraceNotDone is then
   violated (scripts/spec.sh ptraces). *)
EXTENDS Json, PunchRound, TLC, Sequences

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Start" -> Start /\ att' = E.att
      [] E.ev = "Sync" -> Sync
      [] E.ev = "Dial" -> /\ Dial
                          /\ 2 * E.wait_us + 2 >= E.rtt_us
                          /\ E.since_us >= E.wait_us
      [] E.ev = "Win" -> Win
      [] E.ev = "NoAnswer" -> NoAnswer
      [] E.ev = "Refused" -> Refused
      [] E.ev = "Withheld" -> Withheld
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ /\ ~ENABLED Step
          /\ Tick \/ Lose \/ Vanish
          /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
