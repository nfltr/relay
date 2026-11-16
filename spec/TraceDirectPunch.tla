-------------------------- MODULE TraceDirectPunch --------------------------
(* Trace validation of DirectPunch.tla (spec/README.md "DirectPunch
   traces"): the steps the client took in one real punch (-tags
   relaytrace, client/agent trace_punch_on.go) must be a behaviour of
   DirectPunch: the offered candidates (Init), each probe the punch read
   (Learn: dialled or ignored, as the model would), each dial's end
   (DialUp then Win or CloseLoser, or DialFail), a LAN connection
   replacing a non-LAN winner (Win, then the old winner's CloseLoser), the
   LAN grace's end (Settle) and the return with the kept address
   (Return). The agent's probes and the clock are not
   logged: TLC takes AgentProbe, SpoofProbe and Tick only when the next
   logged step needs one. Constants from the trace: the addresses that
   came up are the peer's (the certificate check passed), no rogue (a
   failure maps to the bound or a win), the LAN addresses the code
   classified (each line's lan), no Reach (which address would have
   answered is not in a trace), MaxCands the code's 8. Accepted
   when TLC reaches the trace's end: TraceNotDone is then violated
   (scripts/spec.sh ptraces). *)
EXTENDS Json, DirectPunch, TLC, Sequences

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)
Lines(ev) == SelectSeq(Log, LAMBDA e : e.ev = ev)
TraceOffered == {Log[1].offered[i] : i \in 1..Len(Log[1].offered)}
TracePrflx == {Lines("Learn")[i].s : i \in {j \in 1..Len(Lines("Learn")) : Lines("Learn")[j].tagged}}
TraceSpoofed == {Lines("Learn")[i].s : i \in {j \in 1..Len(Lines("Learn")) : ~Lines("Learn")[j].tagged}}
TracePeer == {Lines("DialUp")[i].a : i \in 1..Len(Lines("DialUp"))}
IsLan(e) == "lan" \in DOMAIN e /\ e.lan = TRUE
TraceLan == (IF "lan" \in DOMAIN Log[1] THEN {Log[1].lan[i] : i \in 1..Len(Log[1].lan)} ELSE {})
    \cup {Lines("Learn")[i].s : i \in {j \in 1..Len(Lines("Learn")) : IsLan(Lines("Learn")[j])}}

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Init" -> UNCHANGED vars
      [] E.ev = "Learn" -> LET p == [src |-> E.s, tagged |-> E.tagged] IN
                           /\ p \in probes
                           /\ Learn(p)
                           /\ (E.out = "dial") = (dial[E.s] = "idle" /\ dial'[E.s] = "dialing")
      [] E.ev = "DialUp" -> DialUp(E.a)
      [] E.ev = "Win" -> Win(E.a)
      [] E.ev = "CloseLoser" -> CloseLoser(E.a)
      [] E.ev = "DialFail" -> DialFail(E.a)
      [] E.ev = "Settle" -> Settle
      [] E.ev = "Return" -> /\ Return
                            /\ won = IF E.won = "" THEN None ELSE E.won
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ /\ ~ENABLED Step
          /\ \/ Tick
             \/ \E a \in Prflx : AgentProbe(a)
             \/ \E a \in Spoofed : SpoofProbe(a)
          /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
