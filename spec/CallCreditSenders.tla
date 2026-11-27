---------------------- MODULE CallCreditSenders ----------------------
(* Several senders on one call's credit (lane FLAKECC, 2026-11-05; lane
   CREDITMU; spec/README.md "CallCreditSenders.tla"). CallCredit.tla's
   Send(c) is enabled whenever the call has credit: it assumes a sender
   waiting for credit takes it once credit is there. A handler may Send
   from several goroutines at once (serverStream.Send: a remote-exec
   handler's stdout and stderr), each waiting in link.Credit.Acquire.

   link.Credit before link v0.12.3 woke its waiters through one token of
   capacity one, which Grant filled and a waiter emptied. With two
   waiters, one grant woke one of them: it took one credit and sent on;
   when it had no more to send, the other still waited with credit there
   and no token, and no grant came, since the receiver grants only for
   frames it read (TestConcurrentServerStreamSend, relay 582038b7: 427 of
   500 frames, every sender waiting). Relay worked around it with a lock
   per call (serverStream.creditMu, lane FLAKECC; deleted, lane CREDITMU).

   The design: link.Credit guarantees (link v0.12.3, link's
   spec/CreditWaiters.tla) that a grant wakes every waiter, each checking
   again under Credit's lock. So the call's senders Acquire with no lock
   of their own.

   One call; Senders each send M frames; a window of W frames; the
   receiver reads the frames sent (wire) and grants each quarter window it
   read back (grants, in order).

   Mutant (scripts/spec.sh mutants): "one-slot" (link before v0.12.3 with
   no lock: one grant fills one token). *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Senders, \* the goroutines sending on the call
    W,       \* the call's window, in frames
    M,       \* frames each sender sends
    Mutant

ASSUME W >= 1 /\ M >= 1

T == IF W \div 4 > 1 THEN W \div 4 ELSE 1

VARIABLES cr, left, pc, token, woken, wire, cons, grants
vars == <<cr, left, pc, token, woken, wire, cons, grants>>

OneSlot == Mutant = "one-slot"

\* pc: "run" (sending, or done when left = 0), "try" (Acquire checks the
\* credit under Credit's lock), "wait" (Acquire waits to be woken).
\* woken[s]: the channel s waits on is closed (the design); token: the
\* one-slot channel is full (the mutant).
TypeOK ==
    /\ cr \in 0..W /\ left \in [Senders -> 0..M]
    /\ pc \in [Senders -> {"run", "try", "wait"}]
    /\ token \in BOOLEAN /\ woken \in [Senders -> BOOLEAN]
    /\ wire \in 0..W /\ cons \in 0..T

Init ==
    /\ cr = W /\ left = [s \in Senders |-> M] /\ pc = [s \in Senders |-> "run"]
    /\ token = FALSE /\ woken = [s \in Senders |-> FALSE]
    /\ wire = 0 /\ cons = 0 /\ grants = <<>>

\* serverStream.Send: Credit.Acquire.
Start(s) ==
    /\ pc[s] = "run" /\ left[s] > 0
    /\ pc' = [pc EXCEPT ![s] = "try"]
    /\ UNCHANGED <<cr, left, token, woken, wire, cons, grants>>

\* Credit.acquire's check: take a credit and send (Agent.sendFrame); or
\* wait.
Try(s) ==
    /\ pc[s] = "try"
    /\ IF cr > 0
       THEN /\ cr' = cr - 1 /\ wire' = wire + 1
            /\ left' = [left EXCEPT ![s] = @ - 1]
            /\ pc' = [pc EXCEPT ![s] = "run"]
       ELSE /\ pc' = [pc EXCEPT ![s] = "wait"]
            /\ UNCHANGED <<cr, wire, left>>
    /\ UNCHANGED <<token, woken, cons, grants>>

Woken(s) == IF OneSlot THEN token ELSE woken[s]

\* A woken waiter checks again (the mutant: it empties the token).
Wake(s) ==
    /\ pc[s] = "wait" /\ Woken(s)
    /\ pc' = [pc EXCEPT ![s] = "try"]
    /\ token' = IF OneSlot THEN FALSE ELSE token
    /\ woken' = [woken EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<cr, left, wire, cons, grants>>

\* The caller reads a frame (clientStream.Recv: Credit.Consumed) and grants
\* a quarter window back once it read one.
Read ==
    /\ wire > 0
    /\ wire' = wire - 1
    /\ IF cons + 1 >= T
       THEN grants' = Append(grants, cons + 1) /\ cons' = 0
       ELSE cons' = cons + 1 /\ UNCHANGED grants
    /\ UNCHANGED <<cr, left, pc, token, woken>>

\* handleWindow: Credit.Grant adds the credit and wakes every waiter (the
\* mutant: fills the token).
Grant ==
    /\ grants # <<>>
    /\ cr' = cr + Head(grants) /\ grants' = Tail(grants)
    /\ IF OneSlot
       THEN token' = TRUE /\ UNCHANGED woken
       ELSE woken' = [s \in Senders |-> woken[s] \/ pc[s] = "wait"] /\ UNCHANGED token
    /\ UNCHANGED <<left, pc, wire, cons>>

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

\* NoStrandedWaiter: no sender waits while the call has credit unless it
\* is woken (its check comes).
NoStrandedWaiter ==
    \A s \in Senders : pc[s] = "wait" /\ cr > 0 => Woken(s)

\* AllSent (liveness): every sender sends all its frames.
AllSent == <>(\A s \in Senders : left[s] = 0)

\* Witnesses (each must be violated: scripts/spec.sh mutants).
W_BothWant == ~(cr = 0 /\ \E s, t \in Senders :
    s # t /\ pc[s] = "wait" /\ left[t] > 0 /\ pc[t] # "wait")
W_GrantToWaiter == ~(\E s \in Senders : pc[s] = "wait" /\ Woken(s) /\ cr > 0)
\* One grant wakes both senders.
W_WakeAll == ~(Cardinality({s \in Senders : woken[s]}) >= 2)
=============================================================================
