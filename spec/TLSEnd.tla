------------------------------- MODULE TLSEnd -------------------------------
(* A session's end under end-to-end TLS on a link session (client/tlsend, *)
(* spec/README.md "TLSEnd.tla", lanes PIPERESET, ENDACK). X ends its      *)
(* stream: close_notify, then the transport's FIN (tlsend CloseWriteSync), *)
(* and waits for Y's ENDACK (link FeatureEndAck). A whole close that      *)
(* reaches X before the ENDACK ends X's wait with a reset (link           *)
(* ENDACKTRUTH: the end is not known delivered), as does Y's reset.       *)
(*                                                                         *)
(* Link acknowledges the FIN only once Y's program read the transport's   *)
(* end (lane ENDACK: a far end's ENDACK at its reader's io.EOF, or at a   *)
(* Close after every byte read), never at its Mux's receipt (mutant       *)
(* ack-on-receipt: Y's program could still fail; pipe                     *)
(* TestReceiverStopsAfterArrival). crypto/tls reads nothing past the      *)
(* close_notify, so tlsend's Read takes the FIN behind it before it       *)
(* returns io.EOF (YTake), within EndBound when X keeps the transport (a  *)
(* peer that ended only its TLS stream). Mutant stop-at-notify: Read      *)
(* returns at the close_notify and only Close takes the FIN; Y's program  *)
(* that half-closes its own direction first (YCloseWrite: nfltr-pipe      *)
(* closes after both directions ended) then waits for X to take Y's end,  *)
(* which X does by the same rule (XTakes: only at its Close, after its own *)
(* wait), and both waits hold each other until the idle bound (lane       *)
(* PIPERACE's prototype: every relayed TLS session 30 s, exit 6). Y's     *)
(* Close takes the FIN too if its Read did not (a reader that knows its   *)
(* stream's length); mutant close-at-notify (the code before lane         *)
(* PIPERESET) closes at once.                                             *)
EXTENDS Naturals, Sequences

CONSTANTS
    Mutant   \* "none"; "close-at-notify": Y's Close closes at once (the
             \* code before lane PIPERESET); "unbounded": it waits for the
             \* FIN with no bound; "ack-on-receipt": Y's Mux acknowledges
             \* the FIN it received (link before lane ENDACK);
             \* "stop-at-notify": Y's Read takes no FIN (lane PIPERACE's
             \* prototype)

VARIABLES
    xs,      \* X: "open", "notified" (close_notify sent), "wait" (its FIN
             \* sent, the ENDACK awaited), "clean", "reset"
    keep,    \* X ends only its TLS stream and keeps the transport (no FIN)
    x2y,     \* frames X -> Y: "cn" (the close_notify record), "fin"
    y2x,     \* frames Y -> X: "eack", "close", "abort"
    yeof,    \* Y's Mux took the close_notify (Y's reads end there)
    yfin,    \* Y's Mux read the FIN
    ys,      \* Y's Close: "no", "closing" (taking the end), "closed"
    ytook,   \* Y's program read the transport's end (Read, or Close's take)
    yw,      \* Y's own half close: "none" (it never half-closes), "no",
             \* "wait" (its CloseWriteSync waits for X to take Y's end), "clean"
    yfail    \* Y's program failed and reset the session

vars == <<xs, keep, x2y, y2x, yeof, yfin, ys, ytook, yw, yfail>>

Init ==
    /\ xs = "open" /\ keep \in BOOLEAN /\ x2y = <<>> /\ y2x = <<>>
    /\ yeof = FALSE /\ yfin = FALSE /\ ys = "no"
    /\ ytook = FALSE /\ yw \in {"none", "no"} /\ yfail = FALSE

\* X's close_notify, then (unless it keeps the transport) its FIN.
XNotify ==
    /\ xs = "open" /\ xs' = "notified" /\ x2y' = Append(x2y, "cn")
    /\ UNCHANGED <<keep, y2x, yeof, yfin, ys, ytook, yw, yfail>>

XFin ==
    /\ xs = "notified" /\ ~keep /\ xs' = "wait" /\ x2y' = Append(x2y, "fin")
    /\ UNCHANGED <<keep, y2x, yeof, yfin, ys, ytook, yw, yfail>>

\* Y's Mux reads the head frame: the close_notify for its reader, the FIN
\* (acknowledged here only with the mutant; nothing once Y closed).
YRecv ==
    /\ x2y # <<>> /\ x2y' = Tail(x2y)
    /\ IF Head(x2y) = "cn"
       THEN /\ yeof' = TRUE /\ UNCHANGED <<y2x, yfin>>
       ELSE /\ yfin' = TRUE /\ UNCHANGED yeof
            /\ y2x' = IF ys = "closed" \/ Mutant # "ack-on-receipt" THEN y2x ELSE Append(y2x, "eack")
    /\ UNCHANGED <<xs, keep, ys, ytook, yw, yfail>>

\* Y's Read after the close_notify takes the transport's end (the FIN, or
\* EndBound when X keeps the transport), then returns io.EOF: link
\* acknowledges the FIN now.
YTake ==
    /\ yeof /\ ~ytook /\ ys = "no" /\ Mutant # "stop-at-notify"
    /\ (yfin \/ (keep /\ Mutant # "unbounded"))
    /\ ytook' = TRUE
    /\ y2x' = IF yfin /\ Mutant # "ack-on-receipt" THEN Append(y2x, "eack") ELSE y2x
    /\ UNCHANGED <<xs, keep, x2y, yeof, yfin, ys, yw, yfail>>

\* Y's own direction's end: its CloseWriteSync, which returns once X took
\* Y's end. X does so by Y's rule (the same code): at its Read, or with
\* stop-at-notify only at X's Close, after X's own wait.
YCloseWrite ==
    /\ yw = "no" /\ ~yfail /\ yw' = "wait"
    /\ UNCHANGED <<xs, keep, x2y, y2x, yeof, yfin, ys, ytook, yfail>>
XTakes ==
    /\ yw = "wait" /\ (Mutant = "stop-at-notify" => xs \in {"clean", "reset"})
    /\ yw' = "clean"
    /\ UNCHANGED <<xs, keep, x2y, y2x, yeof, yfin, ys, ytook, yfail>>

\* Y's Close once its reads ended and its own half close returned.
YClose ==
    /\ yeof /\ ys = "no" /\ yw \in {"none", "clean"} /\ ~yfail
    /\ ys' = IF Mutant = "close-at-notify" THEN "closed" ELSE "closing"
    /\ y2x' = IF Mutant = "close-at-notify" THEN Append(y2x, "close") ELSE y2x
    /\ UNCHANGED <<xs, keep, x2y, yeof, yfin, ytook, yw, yfail>>

\* Y's Close took the FIN (or, X keeping the transport, waited out
\* EndBound): an end its Read did not take is acknowledged first, then
\* its whole close goes.
YClosed ==
    /\ ys = "closing" /\ (yfin \/ (keep /\ Mutant # "unbounded"))
    /\ ys' = "closed" /\ ytook' = TRUE
    /\ y2x' = (IF yfin /\ ~ytook /\ Mutant # "ack-on-receipt" THEN y2x \o <<"eack">> ELSE y2x) \o <<"close">>
    /\ UNCHANGED <<xs, keep, x2y, yeof, yfin, yw, yfail>>

\* Y's program fails before it took the end (its stdout broke): a reset.
YFail ==
    /\ yeof /\ ys = "no" /\ ~ytook /\ ~yfail
    /\ yfail' = TRUE /\ ys' = "closed" /\ y2x' = Append(y2x, "abort")
    /\ UNCHANGED <<xs, keep, x2y, yeof, yfin, ytook, yw>>

\* X's Mux reads the head frame: the ENDACK ends its wait clean, a whole
\* close or a reset before it with a reset (before its FIN: the session
\* failed, its CloseWriteSync errs at once).
XRecv ==
    /\ y2x # <<>> /\ y2x' = Tail(y2x)
    /\ xs' = CASE xs = "wait" -> (IF Head(y2x) = "eack" THEN "clean" ELSE "reset")
               [] xs = "notified" /\ Head(y2x) = "abort" -> "reset"
               [] OTHER -> xs
    /\ UNCHANGED <<keep, x2y, yeof, yfin, ys, ytook, yw, yfail>>

Next == XNotify \/ XFin \/ YRecv \/ YTake \/ YCloseWrite \/ XTakes \/ YClose \/ YClosed \/ YFail \/ XRecv

Fairness == WF_vars(XFin) /\ WF_vars(YRecv) /\ WF_vars(YTake) /\ WF_vars(YCloseWrite) /\ WF_vars(XTakes)
            /\ WF_vars(YClose) /\ WF_vars(YClosed) /\ WF_vars(XRecv)

Spec == Init /\ [][Next]_vars /\ Fairness

TypeOK ==
    /\ xs \in {"open", "notified", "wait", "clean", "reset"} /\ keep \in BOOLEAN
    /\ yeof \in BOOLEAN /\ yfin \in BOOLEAN /\ ys \in {"no", "closing", "closed"}
    /\ ytook \in BOOLEAN /\ yw \in {"none", "no", "wait", "clean"} /\ yfail \in BOOLEAN

\* X's end is read as a reset only when Y's program failed.
NoFalseReset == xs = "reset" => yfail

\* X's wait ends clean only once Y's program read the end (lane ENDACK).
AckTruth == xs = "clean" => ytook

\* X's wait ends, and Y's Close returns (EndBound when X keeps the
\* transport); Y's own half close returns.
XEnds == xs = "wait" ~> xs \in {"clean", "reset"}
YCloses == (yeof /\ ~yfail) ~> ys = "closed"
YWEnds == yw = "wait" ~> yw = "clean"

\* Witnesses (make spec-mutants: TLC must violate each).
W_Clean == xs # "clean"
W_Bound == ~(ys = "closed" /\ keep)
\* Y half-closed too, both ends clean (the crossing ends of nfltr-pipe).
W_BothClean == ~(xs = "clean" /\ yw = "clean" /\ ys = "closed")
\* Y's program failed after its Mux held the whole stream: X reads a reset.
W_FailAfterArrival == ~(xs = "reset" /\ yfin /\ yfail)
=============================================================================
