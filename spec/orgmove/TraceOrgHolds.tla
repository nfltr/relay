---------------------------- MODULE TraceOrgHolds ----------------------------
(* Trace validation of OrgHolds.tla (spec/orgmove/README.md "Traces"): the   *)
(* issuer's steps org/orgenrol recorded (-tags enroltrace, ORGMOVETRACE:    *)
(* trace_on.go, <pid>.holds) for one organisation (Org) must be a behaviour *)
(* of OrgHolds: start (SvcStart), read (SvcRead), write (the round's end:   *)
(* SvcWrite when it published, n > 0), stop (SvcStop, at the fence), lock   *)
(* (Lock), release (Release). Its first directory is A, the other B (a      *)
(* trace of more is outside the model: scripts/spec-orgmove.sh skips it).  *)
(* Two steps are the trace's, not the model's: a round that published      *)
(* nothing (its read changed no hold), and exit (a service that returned   *)
(* other than at the fence: the test ended it; its serve lock is free). The *)
(* steps no recorder sees (Fence, Import: orgissuer's, in TraceOrgMove's    *)
(* lines; Finish: nfltr's orgcli; XTake, Revoke: the relay's) are TLC's,    *)
(* taken only when the next logged step needs them. A logged step that maps *)
(* to no action stops the trace. Accepted when TLC reaches the trace's end: *)
(* TraceNotDone is then violated (scripts/spec-orgmove.sh holds-traces).    *)
EXTENDS OrgHolds, Json, Sequences, FiniteSets, TLC

CONSTANTS TraceFile, Org

All == ndJsonDeserialize(TraceFile)
\* The organisation's directories; a lock line names its directory only.
OrgDirs == {All[i].d : i \in {j \in DOMAIN All : All[j].o = Org}} \ {""}
Log == SelectSeq(All, LAMBDA e : e.o = Org \/ (e.o = "" /\ e.d \in OrgDirs))
FirstDir == Log[CHOOSE i \in DOMAIN Log : Log[i].d # "" /\ \A j \in 1..(i - 1) : Log[j].d = ""].d
HostOf(d) == IF d = FirstDir THEN A ELSE B
ASSUME Cardinality(OrgDirs) <= 2

VARIABLE l
E == Log[l]
H == HostOf(E.d)

\* A round whose read changed nothing it published.
NoWrite(h) ==
    /\ svc[h] = "pending"
    /\ svc' = [svc EXCEPT ![h] = "on"]
    /\ UNCHANGED <<kind, org, step, hold, bundle, moves, wrote, early, bad>>

\* The service returned between rounds (its context ended).
Exit(h) ==
    /\ svc[h] = "on"
    /\ svc' = [svc EXCEPT ![h] = "off"]
    /\ UNCHANGED <<kind, org, step, hold, bundle, moves, wrote, early, bad>>

Step ==
    CASE E.ev = "start" -> SvcStart(H)
      [] E.ev = "read" -> SvcRead(H)
      [] E.ev = "write" -> IF E.n > 0 THEN SvcWrite(H) ELSE NoWrite(H)
      [] E.ev = "stop" -> SvcStop(H)
      [] E.ev = "exit" -> Exit(H)
      [] E.ev = "lock" -> Lock(H)
      [] E.ev = "release" -> \E h \in Iss : Release(h)
      [] OTHER -> Print(<<"unmapped step", E>>, FALSE)

\* The steps no line records, taken only when the next logged one waits.
Hidden ==
    \/ \E h \in Iss : Fence(h) \/ Import(h) \/ Finish(h)
    \/ XTake \/ Revoke

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ Hidden /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
