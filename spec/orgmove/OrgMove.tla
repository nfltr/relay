---------------------------- MODULE OrgMove ----------------------------
\* Moving an organisation's issuer from one machine to another
\* (spec/orgmove/README.md): the
\* recommended design, an encrypted move bundle plus a fence.
\*
\* The issuer directory (<config dir>/org: the hash-chained audit log, the
\* issuer key, the CRL, the answers spool) is the issuer's whole state; the
\* root primary (a file root's root-<label>.key, a Secure Enclave key) stays
\* with its owner and renews the issuer from there (not state here,
\* spec/proverif/orgmove.pv), and the machine-key root and store beside it
\* (a2a-root.key, a2a-machines.json) are not the organisation's and stay.
\* A host acts (makes and redeems tokens, revokes, signs CRLs) only
\* while it holds a directory whose log does not end in a fence. To move,
\* the old host appends a fence line naming the recipient's receive key
\* under the directory's lock (after it no act of the old host can commit),
\* then sends the bundle (the log, fence included, and the keys) sealed to
\* that key; the relay carries it and may lose, withhold or replay it. The
\* recipient imports only a bundle whose last line is a fence naming its
\* own receive key, appends an arrival and serves. The issuer key moves
\* with the log, so the fleet's certificates and their CRLs stay under the
\* same issuer: no machine notices.
\*
\* Copies of a directory that are not a move (a backup, a disk image, a
\* bundle made before the fence) exist too (Backup): import must refuse
\* them. The old host may die at any point (LoseHost); the recipient may
\* crash before it imports (Crash): its receive key is on disk.
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    NH,          \* hosts 1..NH; host 1 holds the organisation at first
    Tokens,      \* token ids
    Names,       \* machine names
    MaxLog,      \* the issuer's ordinary acts in the history (state bound)
    MaxMoves,    \* moves started (fences: state bound)
    MaxCrl,      \* CRLs signed (state bound)
    MaxSend,     \* sends of a fenced bundle without a loss
    MaxLostB,    \* bundles the relay loses
    MaxBackup,   \* stale copies made (backups, early exports)
    MaxLostH,    \* hosts lost (disk gone)
    MaxCrash,    \* recipient crashes before import
    Mutant

Hosts == 1..NH
None == [none |-> TRUE]
FleetKey == 1   \* the issuer key the fleet's certificates chain through

VARIABLES
    dir,      \* dir[h]: None, or [log, key]: the issuer directory on h
    hist,     \* every act any host committed, in order (the audit truth)
    pub,      \* every CRL signed: [num, rev]; the relay holds them all
    bundles,  \* bundles the relay (or a USB stick) carries: [to, log, key]
    rkey,     \* rkey[h]: h still holds its receive key's private half
    redeem,   \* redeem[t]: how many times token t was redeemed, by anyone
    vnum,     \* the fleet verifier's CRL number
    vrev,     \* ... and the names that CRL lists
    vseen,    \* history: every name a CRL the verifier took listed
    sent,     \* sent[h]: bundles h sent
    lostB, backups, lostH, crashes

vars == <<dir, hist, pub, bundles, rkey, redeem, vnum, vrev, vseen, sent, lostB, backups, lostH, crashes>>
cnt == <<sent, lostB, backups, lostH, crashes>>

Last(s) == s[Len(s)]
Has(h) == dir[h] # None
LogOf(h) == dir[h].log
Acts(l, k) == {i \in 1..Len(l) : l[i].k = k}
Made(l) == {l[i].x : i \in Acts(l, "tok")}
Redeemed(l) == {l[i].x : i \in Acts(l, "red")}
Revoked(l) == {l[i].x : i \in Acts(l, "rev")}
CrlNum(l) == Cardinality(Acts(l, "crl"))
Fenced(l) == Len(l) > 0 /\ Last(l).k = "fence"
FenceTo(l) == Last(l).x
IsPrefix(s, t) == Len(s) <= Len(t) /\ s = SubSeq(t, 1, Len(s))

\* h may act: it holds a directory whose log does not end in a fence.
\* (serve-after-fence: the old host's issuer ignores its own fence.)
Serving(h) == Has(h) /\ (~Fenced(LogOf(h)) \/ Mutant = "serve-after-fence")

TypeOK ==
    /\ \A h \in Hosts : dir[h] = None \/ (dir[h].key \in 1..2 /\ Len(dir[h].log) \in 1..1 + MaxLog + MaxMoves + NH + MaxLostH)
    /\ Len(hist) \in 1..1 + MaxLog + MaxMoves + NH + MaxLostH
    /\ \A c \in pub : c.num \in 0..MaxCrl /\ c.rev \subseteq Names
    /\ \A b \in bundles : b.to \in Hosts
    /\ rkey \in [Hosts -> BOOLEAN]
    /\ redeem \in [Tokens -> 0..NH]
    /\ vnum \in 0..MaxCrl /\ vrev \subseteq Names /\ vseen \subseteq Names
    /\ sent \in [Hosts -> 0..MaxSend + MaxLostB]

Init ==
    /\ dir = [h \in Hosts |-> IF h = 1 THEN [log |-> <<[k |-> "init", x |-> 0]>>, key |-> FleetKey] ELSE None]
    /\ hist = <<[k |-> "init", x |-> 0]>>
    /\ pub = {[num |-> 0, rev |-> {}]}
    /\ bundles = {}
    /\ rkey = [h \in Hosts |-> TRUE]
    /\ redeem = [t \in Tokens |-> 0]
    /\ vnum = 0 /\ vrev = {} /\ vseen = {}
    /\ sent = [h \in Hosts |-> 0] /\ lostB = 0 /\ backups = 0 /\ lostH = 0 /\ crashes = 0

\* h commits act a: to its log (synced) and so to the history. MaxLog
\* bounds the issuer's ordinary acts (Room), not the move's own lines.
Room == Cardinality({i \in 1..Len(hist) : hist[i].k \in {"tok", "red", "rev", "crl"}}) < MaxLog
Moves == Cardinality(Acts(hist, "fence"))
Commit(h, a) ==
    /\ dir' = [dir EXCEPT ![h].log = Append(@, a)]
    /\ hist' = Append(hist, a)

\* nfltr org token: a single-use token for a name.
MakeToken(h, t) ==
    /\ Serving(h) /\ t \notin Made(LogOf(h)) /\ Room
    /\ Commit(h, [k |-> "tok", x |-> t])
    /\ UNCHANGED <<pub, bundles, rkey, redeem, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* The issuer redeems a token (an enrolment the relay delivered to it, or
\* replayed to it): once per log. Its MAC is under the issuer key, so a
\* host whose key is not the token's cannot redeem it.
Redeem(h, t) ==
    /\ Serving(h)
    /\ t \in Made(LogOf(h)) /\ t \notin Redeemed(LogOf(h)) /\ Room
    /\ dir[h].key = FleetKey
    /\ Commit(h, [k |-> "red", x |-> t])
    /\ redeem' = [redeem EXCEPT ![t] = @ + 1]
    /\ UNCHANGED <<pub, bundles, rkey, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* nfltr org revoke.
Revoke(h, n) ==
    /\ Serving(h) /\ n \notin Revoked(LogOf(h)) /\ Room
    /\ Commit(h, [k |-> "rev", x |-> n])
    /\ UNCHANGED <<pub, bundles, rkey, redeem, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* The issuer signs its next CRL (Number = its log's last + 1) and
\* publishes it.
SignCRL(h) ==
    /\ Serving(h)
    /\ CrlNum(LogOf(h)) < MaxCrl /\ Room
    /\ Commit(h, [k |-> "crl", x |-> CrlNum(LogOf(h)) + 1])
    /\ pub' = pub \cup {[num |-> CrlNum(LogOf(h)) + 1, rev |-> Revoked(LogOf(h))]}
    /\ UNCHANGED <<bundles, rkey, redeem, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* nfltr org move send, its first half: under the directory's lock the old
\* host appends the fence naming r's receive key. From now its issuer
\* commits nothing (Serving).
Fence(h, r) ==
    /\ Serving(h) /\ ~Fenced(LogOf(h))
    /\ r # h /\ ~Has(r) /\ Moves < MaxMoves
    /\ Commit(h, [k |-> "fence", x |-> r])
    /\ UNCHANGED <<pub, bundles, rkey, redeem, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* ... its second half, repeated until the recipient serves: the fenced
\* log and the keys, sealed to the receive key the fence names. A loss
\* grants one send more. Mutants: no-resend (one send only),
\* fence-names-no-recipient (the fence binds no key: sealed to any key,
\* and import takes any fenced log), no-fence (an export that
\* copies the directory and leaves the old host serving: the bundle's log
\* ends in a fence the old host never wrote).
Send(h, r) ==
    /\ Has(h) /\ r # h
    /\ sent[h] < MaxSend + lostB
    /\ Mutant # "no-resend" \/ sent[h] = 0
    /\ IF Mutant = "no-fence"
       THEN /\ ~Fenced(LogOf(h)) /\ ~Has(r) /\ Moves < MaxMoves
            /\ bundles' = bundles \cup {[to |-> r, log |-> Append(LogOf(h), [k |-> "fence", x |-> r]), key |-> dir[h].key]}
       ELSE /\ Fenced(LogOf(h))
            /\ Mutant = "fence-names-no-recipient" \/ r = FenceTo(LogOf(h))
            /\ bundles' = bundles \cup {[to |-> r, log |-> LogOf(h), key |-> dir[h].key]}
    /\ sent' = [sent EXCEPT ![h] = @ + 1]
    /\ UNCHANGED <<dir, hist, pub, rkey, redeem, vnum, vrev, vseen, lostB, backups, lostH, crashes>>

\* A copy that is not a move: a backup, a disk image, a bundle made before
\* the fence. Whoever holds it can hand it to any host.
Backup(h, r) ==
    /\ Has(h) /\ backups < MaxBackup /\ r # h
    /\ bundles' = bundles \cup {[to |-> r, log |-> LogOf(h), key |-> dir[h].key]}
    /\ backups' = backups + 1
    /\ UNCHANGED <<dir, hist, pub, rkey, redeem, vnum, vrev, vseen, sent, lostB, lostH, crashes>>

\* The relay loses (or withholds for good) a bundle.
LoseBundle(b) ==
    /\ lostB < MaxLostB
    /\ bundles' = bundles \ {b}
    /\ lostB' = lostB + 1
    /\ UNCHANGED <<dir, hist, pub, rkey, redeem, vnum, vrev, vseen, sent, backups, lostH, crashes>>

\* nfltr org move receive: r opens a bundle sealed to its receive key and
\* imports it only when the log's last line is the fence naming r (the
\* chain and the root pin are checked too: OrgMove.pv); it appends its
\* arrival and serves under the same issuer key. Mutants: import-unfenced
\* (any copy is imported), rekey-on-import (a new issuer key on arrival),
\* reusable-receive-key (the receive key kept after the import).
Import(r, b) ==
    /\ b \in bundles /\ b.to = r /\ ~Has(r) /\ rkey[r]
    /\ \/ Mutant = "import-unfenced"
       \/ Fenced(b.log) /\ (FenceTo(b.log) = r \/ Mutant = "fence-names-no-recipient")
    /\ dir' = [dir EXCEPT ![r] = [log |-> Append(b.log, [k |-> "arrive", x |-> r]),
                                  key |-> IF Mutant = "rekey-on-import" THEN 2 ELSE b.key]]
    /\ hist' = Append(hist, [k |-> "arrive", x |-> r])
    \* The receive key is single use: deleted as the arrival commits, so the
    \* bundle (which the relay or a file still holds) never opens again; a
    \* later re-import, after this disk is lost, would be a stale copy.
    /\ rkey' = [rkey EXCEPT ![r] = Mutant = "reusable-receive-key"]
    /\ UNCHANGED <<pub, bundles, redeem, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* Once the owner sees the recipient serving (nfltr org status there), the
\* old host deletes its issuer key (nfltr org move finish; the fenced log
\* and the root stay, and neither acts as an issuer).
Wipe(h) ==
    /\ Has(h) /\ Fenced(LogOf(h))
    /\ \E x \in Hosts : x # h /\ Serving(x)
    /\ dir' = [dir EXCEPT ![h] = None]
    /\ UNCHANGED <<hist, pub, bundles, rkey, redeem, vnum, vrev, vseen>> /\ UNCHANGED cnt

\* A host's disk is gone, at any point.
LoseHost(h) ==
    /\ Has(h) /\ lostH < MaxLostH
    /\ dir' = [dir EXCEPT ![h] = None]
    /\ lostH' = lostH + 1
    /\ UNCHANGED <<hist, pub, bundles, rkey, redeem, vnum, vrev, vseen, sent, lostB, backups, crashes>>

\* The recipient crashes before it imports: its receive key is a 0600 file
\* and survives (ephemeral-receive-key: kept in memory only, lost).
Crash(r) ==
    /\ ~Has(r) /\ crashes < MaxCrash
    /\ rkey' = [rkey EXCEPT ![r] = rkey[r] /\ Mutant # "ephemeral-receive-key"]
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<dir, hist, pub, bundles, redeem, vnum, vrev, vseen, sent, lostB, backups, lostH>>

\* A fleet verifier takes a CRL the relay delivers, only a newer Number
\* (Enrol.tla Take; the relay may withhold or replay any).
Take(c) ==
    /\ c \in pub /\ c.num > vnum
    /\ vnum' = c.num /\ vrev' = c.rev /\ vseen' = vseen \cup c.rev
    /\ UNCHANGED <<dir, hist, pub, bundles, rkey, redeem>> /\ UNCHANGED cnt

Next ==
    \/ \E h \in Hosts, t \in Tokens : MakeToken(h, t)
    \/ \E h \in Hosts, t \in Tokens : Redeem(h, t)
    \/ \E h \in Hosts, n \in Names : Revoke(h, n)
    \/ \E h \in Hosts : SignCRL(h)
    \/ \E h, r \in Hosts : Fence(h, r)
    \/ \E h, r \in Hosts : Send(h, r)
    \/ \E h, r \in Hosts : Backup(h, r)
    \/ \E b \in bundles : LoseBundle(b)
    \/ \E r \in Hosts, b \in bundles : Import(r, b)
    \/ \E h \in Hosts : Wipe(h)
    \/ \E h \in Hosts : LoseHost(h)
    \/ \E h \in Hosts : Crash(h)
    \/ \E c \in pub : Take(c)

Spec == Init /\ [][Next]_vars

\* Fair: the old host sends again until the recipient serves, the relay
\* eventually delivers (the bundle file by hand otherwise), the recipient
\* imports. No host is lost (LiveMove.cfg: MaxLostH 0).
LiveSpec == Spec
    /\ \A h, r \in Hosts : WF_vars(Send(h, r))
    /\ \A x \in Hosts : WF_vars(\E b \in bundles : Import(x, b))

----------------------------------------------------------------------------
\* Safety.

\* At most one host's issuer can act at any time: no overlap at all.
AtMostOneIssuer == Cardinality({h \in Hosts : Serving(h)}) <= 1

\* A host, once it fenced, commits nothing after its fence: in every
\* log, the line after a fence is its recipient's arrival.
OldCannotIssue == \A h \in Hosts : Has(h) =>
    \A i \in Acts(LogOf(h), "fence") : i = Len(LogOf(h)) \/ LogOf(h)[i + 1] = [k |-> "arrive", x |-> LogOf(h)[i].x]

\* The audit chain is continuous: every directory's log is a prefix of
\* the one history of acts (no fork, no act lost across the move).
AuditContinuous == \A h \in Hosts : Has(h) => IsPrefix(LogOf(h), hist)

\* Each token is redeemed at most once, across every host.
TokenOnce == \A t \in Tokens : redeem[t] <= 1

\* CRLs never go backwards: one content per Number, and a higher Number
\* lists every name a lower one did.
CRLMonotone ==
    \A c1, c2 \in pub : (c1.num = c2.num => c1 = c2) /\ (c1.num < c2.num => c1.rev \subseteq c2.rev)

\* A name the fleet has seen revoked stays revoked for it.
RevokedStaysRevoked == vseen \subseteq vrev

\* The serving issuer is the one the fleet's certificates chain through:
\* machines keep their sessions and renew into it on their own.
FleetUnderServingIssuer == \A h \in Hosts : Serving(h) => dir[h].key = FleetKey

\* Liveness (LiveSpec): a fenced move ends with a host serving again
\* (before the CRL the fence signed lapses, by the design's timing).
MoveCompletes == \A h \in Hosts : (Has(h) /\ Fenced(LogOf(h))) ~> (\E x \in Hosts : Serving(x))

\* Witnesses (each must be violated: the states are reachable).
WitnessMoved == ~\E h \in Hosts : h # 1 /\ Serving(h)
WitnessTokenAcrossMove == ~\E h \in Hosts : h # 1 /\ Has(h) /\ \E i \in Acts(LogOf(h), "red") : \E j \in Acts(LogOf(h), "fence") : j < i
WitnessRevokedAcrossMove == ~\E h \in Hosts : h # 1 /\ Serving(h) /\ \E i \in Acts(LogOf(h), "rev"), j \in Acts(LogOf(h), "fence"), k \in Acts(LogOf(h), "crl") : i < j /\ j < k
WitnessResentAfterLoss == ~(lostB > 0 /\ \E h \in Hosts : h # 1 /\ Serving(h))
WitnessOldWiped == ~(dir[1] = None /\ lostH = 0 /\ \E h \in Hosts : Serving(h))
WitnessCrashedThenMoved == ~(crashes > 0 /\ \E h \in Hosts : h # 1 /\ Serving(h))
WitnessBackupRefused == ~(backups > 0 /\ \E b \in bundles : ~Fenced(b.log))
=============================================================================
