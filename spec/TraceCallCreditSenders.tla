--------------------- MODULE TraceCallCreditSenders ---------------------
(* Trace validation of CallCreditSenders.tla (spec/README.md "CallCredit
   traces"): the response steps a real run recorded (-tags relaytrace,
   client/rpcclient trace_callcredit_on.go) for one call (Call) served by
   several goroutines must be a behaviour of CallCreditSenders: a sender
   about to take credit (Start: serverStream.Send before Credit.Acquire), a
   sender that took it (Send: Try with credit there), the caller's Read and
   the handler taking a window update (Grant, its count n). A line's s is
   the logging goroutine: Senders are the goroutines that logged a Start,
   M the most Starts one logged (scripts/spec.sh writes both into the
   config: a definition substituted for a constant is evaluated on every
   use).
   Not logged: a check that found no credit and the wake (Try without
   credit, Wake: link.Credit's, link's own CreditWaiters traces record
   them), the caller's Reads when the run has no caller agent (a test that
   grants by hand), and the caller's receive loop (Deliver: wire covers the
   frames on their way and in its buffer); TLC takes the steps not logged
   only when the next logged one needs them. Accepted when TLC reaches the
   trace's end: TraceNotDone is then violated (scripts/spec.sh). *)
EXTENDS Json, CallCreditSenders, TLC

CONSTANTS TraceFile, Call

\* The caller's request steps, its Deliver, Eom and Cancel are
\* CallCredit's and CallCreditBoth's (TraceCallCredit, TraceCallCreditBoth).
Log == SelectSeq(ndJsonDeserialize(TraceFile),
    LAMBDA e : e.c = Call /\ e.d = "resp" /\ e.ev \notin {"Deliver", "Eom", "Cancel"})
ReadsLogged == \E i \in DOMAIN Log : Log[i].ev = "Read"

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Start" -> E.s \in Senders /\ Start(E.s)
      [] E.ev = "Send" -> E.s \in Senders /\ pc[E.s] = "try" /\ cr > 0 /\ Try(E.s)
      [] E.ev = "Read" -> Read
      [] E.ev = "Grant" -> grants # <<>> /\ Head(grants) = E.n /\ Grant
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

Hidden ==
    \/ ~ReadsLogged /\ Read
    \/ \E s \in Senders : (pc[s] = "try" /\ cr = 0 /\ Try(s)) \/ Wake(s)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ Hidden /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
