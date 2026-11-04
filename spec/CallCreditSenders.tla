---------------------- MODULE CallCreditSenders ----------------------
(* Several senders on one call's credit (lane FLAKECC, 2026-11-05;
   spec/README.md "CallCreditSenders.tla"). CallCredit.tla's Send(c) is
   enabled whenever the call has credit: it assumes a sender waiting for
   credit takes it once credit is there. A handler may Send from several
   goroutines at once (serverStream.Send: a remote-exec handler's stdout
   and stderr), and link.Credit.Acquire wakes its waiters through one
   token of capacity one (sessionCredit.wake), which Grant fills and a
   waiter empties. With two waiters, one grant wakes one of them: it takes
   one credit and sends on; when it has no more to send, the other still
   waits with credit there and no token, and no grant comes, since the
   receiver grants only for frames it read (TestConcurrentServerStreamSend,
   relay 582038b7: 427 of 500 frames, every sender waiting).

   The design: a call's senders take its credit one at a time
   (serverStream.creditMu, held across Credit.Acquire), so at most
   one of them waits on the token, and every grant reaches it.

   One call; Senders each send M frames; a window of W frames; the
   receiver reads the frames sent (wire) and grants each quarter window it
   read back (grants, in order).

   Mutant (scripts/spec.sh mutants): "no-lock" (the code before: every
   sender waits on the token itself). *)
EXTENDS Naturals, Sequences

CONSTANTS
    Senders, \* the goroutines sending on the call
    W,       \* the call's window, in frames
    M,       \* frames each sender sends
    Mutant

ASSUME W >= 1 /\ M >= 1

None == "none"
T == IF W \div 4 > 1 THEN W \div 4 ELSE 1

VARIABLES cr, left, pc, lock, wake, wire, cons, grants
vars == <<cr, left, pc, lock, wake, wire, cons, grants>>

\* pc: "run" (sending, or done when left = 0), "try" (Acquire checks the
\* credit under its mutex), "wait" (Acquire waits on the token).
TypeOK ==
    /\ cr \in 0..W /\ left \in [Senders -> 0..M]
    /\ pc \in [Senders -> {"run", "try", "wait"}]
    /\ lock \in Senders \cup {None} /\ wake \in BOOLEAN
    /\ wire \in 0..W /\ cons \in 0..T

Init ==
    /\ cr = W /\ left = [s \in Senders |-> M] /\ pc = [s \in Senders |-> "run"]
    /\ lock = None /\ wake = FALSE /\ wire = 0 /\ cons = 0 /\ grants = <<>>

\* serverStream.Send: serverStream.creditMu, then
\* Credit.Acquire. "no-lock": straight to Acquire.
Start(s) ==
    /\ pc[s] = "run" /\ left[s] > 0
    /\ IF Mutant = "no-lock" THEN UNCHANGED lock ELSE lock = None /\ lock' = s
    /\ pc' = [pc EXCEPT ![s] = "try"]
    /\ UNCHANGED <<cr, left, wake, wire, cons, grants>>

\* Credit.acquire's check: take a credit and send (Agent.sendFrame), the
\* mutex released; or wait on the token.
Try(s) ==
    /\ pc[s] = "try"
    /\ IF cr > 0
       THEN /\ cr' = cr - 1 /\ wire' = wire + 1
            /\ left' = [left EXCEPT ![s] = @ - 1]
            /\ pc' = [pc EXCEPT ![s] = "run"]
            /\ lock' = IF Mutant = "no-lock" THEN lock ELSE None
       ELSE /\ pc' = [pc EXCEPT ![s] = "wait"]
            /\ UNCHANGED <<cr, wire, left, lock>>
    /\ UNCHANGED <<wake, cons, grants>>

\* The token wakes a waiter, which checks again.
Wake(s) ==
    /\ pc[s] = "wait" /\ wake
    /\ wake' = FALSE /\ pc' = [pc EXCEPT ![s] = "try"]
    /\ UNCHANGED <<cr, left, lock, wire, cons, grants>>

\* The caller reads a frame (clientStream.Recv: Credit.Consumed) and grants
\* a quarter window back once it read one.
Read ==
    /\ wire > 0
    /\ wire' = wire - 1
    /\ IF cons + 1 >= T
       THEN grants' = Append(grants, cons + 1) /\ cons' = 0
       ELSE cons' = cons + 1 /\ UNCHANGED grants
    /\ UNCHANGED <<cr, left, pc, lock, wake>>

\* handleWindow: Credit.Grant adds the credit and fills the token.
Grant ==
    /\ grants # <<>>
    /\ cr' = cr + Head(grants) /\ grants' = Tail(grants) /\ wake' = TRUE
    /\ UNCHANGED <<left, pc, lock, wire, cons>>

Next == \/ \E s \in Senders : Start(s) \/ Try(s) \/ Wake(s)
        \/ Read \/ Grant

Spec == Init /\ [][Next]_vars
    /\ \A s \in Senders : WF_vars(Start(s)) /\ WF_vars(Try(s)) /\ WF_vars(Wake(s))
    /\ WF_vars(Read) /\ WF_vars(Grant)

----------------------------------------------------------------------------
Sum(s) == LET f[k \in 0..Len(s)] == IF k = 0 THEN 0 ELSE f[k-1] + s[k] IN f[Len(s)]

\* Conservation: credit, frames on the wire, read and not yet granted, and
\* grants on the way make up the window.
Conservation == cr + wire + cons + Sum(grants) = W

\* NoStrandedWaiter: a sender that waits while the call has credit has the
\* token to wake it, or another sender is checking (and will hand it on).
NoStrandedWaiter ==
    (\E s \in Senders : pc[s] = "wait") /\ cr > 0 =>
        wake \/ \E s \in Senders : pc[s] = "try"

\* AllSent (liveness): every sender sends all its frames.
AllSent == <>(\A s \in Senders : left[s] = 0)

\* Witnesses (each must be violated: scripts/spec.sh mutants).
W_BothWant == ~(cr = 0 /\ \E s, t \in Senders :
    s # t /\ pc[s] = "wait" /\ left[t] > 0 /\ pc[t] # "wait")
W_GrantToWaiter == ~(\E s \in Senders : pc[s] = "wait" /\ wake /\ cr > 0)
=============================================================================
