---------------------------- MODULE MachinePair ----------------------------
(* A machine's key and certificate replaced as one pair (lane CERTATOMIC,  *)
(* spec/pair/README.md): the organisation identity (org/machine/           *)
(* machine.key + machine.pem) and the relay credential (machine.key +      *)
(* machine.json), each a key file and a certificate file. A writer holds   *)
(* the pair's lock (released when it dies), rolls a crashed predecessor's  *)
(* swap forward, writes the new key beside the old one (machine.key.next), *)
(* then the certificate, then renames the new key over the old: each file  *)
(* replaced by one rename (client/pairfile). It may crash after any step.  *)
(* A reader reads the certificate, then the new key, then the key, and     *)
(* takes whichever key the certificate certifies, else reads again.        *)
(* A version v is a key and the certificates of that key: cert = v means   *)
(* the certificate file certifies key v. 0 is no file.                     *)
EXTENDS Naturals

CONSTANTS
    MaxWrites,  \* replacements started (crashed or not)
    Mutant      \* "none", or a planted bug (mutants.txt)

None == 0

VARIABLES
    key, cert, next,   \* the files: machine.key, the certificate, machine.key.next
    pc, wv,            \* the writer holding the lock: its step, the version it writes
    issued,            \* the newest version made so far
    rolled,            \* a writer rolled a crashed swap forward
    rpc, rc, rn, rk,   \* a reader: its step and what it read
    got                \* the key version the reader took (None: not yet)

vars == <<key, cert, next, pc, wv, issued, rolled, rpc, rc, rn, rk, got>>
files == <<key, cert, next>>
reader == <<rpc, rc, rn, rk, got>>

Versions == 0..(MaxWrites + 1)

TypeOK ==
    /\ key \in Versions /\ cert \in Versions /\ next \in Versions
    /\ pc \in {"idle", "locked", "ready", "nexted", "certed", "keyed"}
    /\ wv \in Versions /\ issued \in Versions /\ rolled \in BOOLEAN
    /\ rpc \in {"idle", "cert", "next", "key", "check", "done"}
    /\ rc \in Versions /\ rn \in Versions /\ rk \in Versions /\ got \in Versions

Init ==
    /\ key = 1 /\ cert = 1 /\ next = None   \* an enrolled machine
    /\ pc = "idle" /\ wv = None /\ issued = 1 /\ rolled = FALSE
    /\ rpc = "idle" /\ rc = None /\ rn = None /\ rk = None /\ got = None

(* The writer (pairfile.Pair.Write). *)
Lock ==
    /\ pc = "idle" /\ issued <= MaxWrites
    /\ issued' = issued + 1 /\ wv' = issued + 1
    /\ pc' = IF Mutant = "no-recovery" THEN "ready" ELSE "locked"
    /\ UNCHANGED <<files, rolled, reader>>

\* A crashed predecessor left the new certificate with the new key beside the
\* old: finish its swap (rename machine.key.next over machine.key).
Recover ==
    /\ pc = "locked" /\ pc' = "ready"
    /\ IF next # None /\ cert = next /\ cert # key
       THEN key' = next /\ next' = None /\ rolled' = TRUE
       ELSE UNCHANGED <<key, next, rolled>>
    /\ UNCHANGED <<cert, wv, issued, reader>>

WriteNext ==
    /\ \/ pc = "ready" /\ Mutant \notin {"cert-first", "key-first"}
       \/ pc = "certed" /\ Mutant = "cert-first"
    /\ next' = wv
    /\ pc' = "nexted"
    /\ UNCHANGED <<key, cert, wv, issued, rolled, reader>>

\* key-first: CERTPAIR's writer (machine.key by rename, then the certificate).
WriteKey ==
    /\ pc = "ready" /\ Mutant = "key-first"
    /\ key' = wv /\ pc' = "keyed"
    /\ UNCHANGED <<cert, next, wv, issued, rolled, reader>>

WriteCert ==
    /\ \/ pc = "nexted" /\ Mutant \notin {"cert-first", "key-first"}
       \/ pc = "ready" /\ Mutant = "cert-first"
       \/ pc = "keyed" /\ Mutant = "key-first"
    /\ cert' = wv
    /\ pc' = CASE Mutant = "cert-first" -> "certed"
               [] Mutant = "key-first" -> "idle"
               [] OTHER -> "certed"
    /\ wv' = IF Mutant = "key-first" THEN None ELSE wv
    /\ UNCHANGED <<key, next, issued, rolled, reader>>

Swap ==
    /\ \/ pc = "certed" /\ Mutant \notin {"cert-first", "key-first"}
       \/ pc = "nexted" /\ Mutant = "cert-first"
    /\ key' = next /\ next' = None
    /\ pc' = "idle" /\ wv' = None
    /\ UNCHANGED <<cert, issued, rolled, reader>>

\* The writer dies after any step (or a step fails and it returns): its lock
\* is released, the files stay as they are.
Crash ==
    /\ pc # "idle" /\ pc' = "idle" /\ wv' = None
    /\ UNCHANGED <<files, issued, rolled, reader>>

(* A reader (pairfile.Pair.Read), concurrent with the writer. *)
RStart == rpc = "idle" /\ rpc' = "cert" /\ UNCHANGED <<rc, rn, rk, got, files, pc, wv, issued, rolled>>
RCert == rpc = "cert" /\ rc' = cert /\ rpc' = "next" /\ UNCHANGED <<rn, rk, got, files, pc, wv, issued, rolled>>
RNext ==
    /\ rpc = "next" /\ rpc' = "key"
    /\ rn' = IF Mutant = "no-next-read" THEN None ELSE next
    /\ UNCHANGED <<rc, rk, got, files, pc, wv, issued, rolled>>
RKey == rpc = "key" /\ rk' = key /\ rpc' = "check" /\ UNCHANGED <<rc, rn, got, files, pc, wv, issued, rolled>>
\* The certificate certifies the new key or the key: take it; else read again.
RCheck ==
    /\ rpc = "check"
    /\ IF rc # None /\ (rc = rn \/ rc = rk)
       THEN got' = rc /\ rpc' = "done"
       ELSE got' = got /\ rpc' = "cert"
    /\ UNCHANGED <<rc, rn, rk, files, pc, wv, issued, rolled>>

Writer == Lock \/ Recover \/ WriteNext \/ WriteKey \/ WriteCert \/ Swap \/ Crash
Reader == RStart \/ RCert \/ RNext \/ RKey \/ RCheck

Next == Writer \/ Reader

Spec == Init /\ [][Next]_vars
\* Writers stop (MaxWrites, a crash any time); the reader is not starved.
LiveSpec == Spec /\ WF_vars(Reader) /\ WF_vars(Lock \/ Recover \/ WriteNext \/ WriteKey \/ WriteCert \/ Swap)

(* Properties. *)
\* The reader's rule finds a key the certificate certifies.
Takes(c, n, k) == c # None /\ (c = k \/ (Mutant # "no-next-read" /\ c = n))

\* Whatever step a writer stopped at (crashed, or still running), the files
\* hold a usable pair: the certificate's key is machine.key or
\* machine.key.next. No user action after a crash.
Usable == Takes(cert, next, key)

\* Every reader ends with a pair, once writers stop.
ReaderCompletes == <>(rpc = "done")

(* Witnesses: each must be violated (the state is reached). *)
\* A writer crashed between the certificate and the swap: still usable.
WitnessCrashMidSwap == ~(pc = "idle" /\ next # None /\ cert = next /\ cert # key)
\* The next writer rolled it forward.
WitnessRolledForward == ~rolled
\* A reader took the new key from machine.key.next.
WitnessReadNext == ~(rpc = "done" /\ got = rn /\ rn # rk)
\* A reader read across a replacement and read again.
WitnessReplaced == ~(rpc = "done" /\ got > 1)
=============================================================================
