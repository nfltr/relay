------------------------------- MODULE TLSEnd -------------------------------
(* A session's end under end-to-end TLS on a link session (client/tlsend, *)
(* spec/README.md "TLSEnd.tla", lane PIPERESET). X ends its stream:       *)
(* close_notify, then the transport's FIN (tlsend CloseWriteSync), and    *)
(* waits for Y's ENDACK (link FeatureEndAck). Y's reads end at the        *)
(* close_notify (crypto/tls reads nothing past it); Y then closes the     *)
(* session whole (tlsend Close). Y's link Mux acknowledges the FIN on     *)
(* receipt, before any later close (link: a far end's AckEnd on receipt, *)
(* ackAtClose); a whole close that reaches X before the ENDACK ends X's  *)
(* wait with a reset (link ENDACKTRUTH: the end is not known delivered).  *)
(*                                                                         *)
(* The design: Y's Close after the close_notify first takes the FIN       *)
(* behind it (reads the transport to its end), within EndBound when X     *)
(* keeps the transport (a peer that ended only its TLS stream). The       *)
(* code before (mutant close-at-notify) closed at the close_notify: with  *)
(* the FIN still in flight, X's clean end read as a reset (nfltr-pipe's   *)
(* relayed ends exited 6).                                                 *)
EXTENDS Naturals, Sequences

CONSTANTS
    Mutant   \* "none"; "close-at-notify": Y's Close closes at once (the
             \* code before lane PIPERESET); "unbounded": it waits for the
             \* FIN with no bound

VARIABLES
    xs,      \* X: "open", "notified" (close_notify sent), "wait" (its FIN
             \* sent, the ENDACK awaited), "clean", "reset"
    keep,    \* X ends only its TLS stream and keeps the transport (no FIN)
    x2y,     \* frames X -> Y: "cn" (the close_notify record), "fin"
    y2x,     \* frames Y -> X: "eack", "close"
    yeof,    \* Y's reads ended at the close_notify
    yfin,    \* Y's Mux read the FIN (and answered it)
    ys       \* Y's Close: "no", "closing" (taking the end), "closed"

vars == <<xs, keep, x2y, y2x, yeof, yfin, ys>>

Init ==
    /\ xs = "open" /\ keep \in BOOLEAN /\ x2y = <<>> /\ y2x = <<>>
    /\ yeof = FALSE /\ yfin = FALSE /\ ys = "no"

\* X's close_notify, then (unless it keeps the transport) its FIN.
XNotify ==
    /\ xs = "open" /\ xs' = "notified" /\ x2y' = Append(x2y, "cn")
    /\ UNCHANGED <<keep, y2x, yeof, yfin, ys>>

XFin ==
    /\ xs = "notified" /\ ~keep /\ xs' = "wait" /\ x2y' = Append(x2y, "fin")
    /\ UNCHANGED <<keep, y2x, yeof, yfin, ys>>

\* Y's Mux reads the head frame: the close_notify for its reader, the FIN
\* answered at once (unless Y closed: its session is gone).
YRecv ==
    /\ x2y # <<>> /\ x2y' = Tail(x2y)
    /\ IF Head(x2y) = "cn"
       THEN /\ yeof' = TRUE /\ UNCHANGED <<y2x, yfin>>
       ELSE /\ yfin' = TRUE /\ UNCHANGED yeof
            /\ y2x' = IF ys = "closed" THEN y2x ELSE Append(y2x, "eack")
    /\ UNCHANGED <<xs, keep, ys>>

\* Y's Close once its reads ended.
YClose ==
    /\ yeof /\ ys = "no"
    /\ ys' = IF Mutant = "close-at-notify" THEN "closed" ELSE "closing"
    /\ y2x' = IF Mutant = "close-at-notify" THEN Append(y2x, "close") ELSE y2x
    /\ UNCHANGED <<xs, keep, x2y, yeof, yfin>>

\* Y's Close took the FIN (or, X keeping the transport, waited out
\* EndBound): its whole close goes.
YClosed ==
    /\ ys = "closing" /\ (yfin \/ (keep /\ Mutant # "unbounded"))
    /\ ys' = "closed" /\ y2x' = Append(y2x, "close")
    /\ UNCHANGED <<xs, keep, x2y, yeof, yfin>>

\* X's Mux reads the head frame: the ENDACK ends its wait clean, a whole
\* close before it with a reset.
XRecv ==
    /\ y2x # <<>> /\ y2x' = Tail(y2x)
    /\ xs' = IF xs = "wait" THEN (IF Head(y2x) = "eack" THEN "clean" ELSE "reset") ELSE xs
    /\ UNCHANGED <<keep, x2y, yeof, yfin, ys>>

Next == XNotify \/ XFin \/ YRecv \/ YClose \/ YClosed \/ XRecv

Fairness == WF_vars(XFin) /\ WF_vars(YRecv) /\ WF_vars(YClose) /\ WF_vars(YClosed) /\ WF_vars(XRecv)

Spec == Init /\ [][Next]_vars /\ Fairness

TypeOK ==
    /\ xs \in {"open", "notified", "wait", "clean", "reset"} /\ keep \in BOOLEAN
    /\ yeof \in BOOLEAN /\ yfin \in BOOLEAN /\ ys \in {"no", "closing", "closed"}

\* Nothing fails here: X's end, every byte taken, is never read as a reset.
NoFalseReset == xs # "reset"

\* X's wait ends clean, and Y's Close returns (EndBound when X keeps the
\* transport).
XEnds == xs = "wait" ~> xs = "clean"
YCloses == yeof ~> ys = "closed"

\* Witnesses (make spec-mutants: TLC must violate each).
W_Clean == xs # "clean"
W_Bound == ~(ys = "closed" /\ keep)
=============================================================================
