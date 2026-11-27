----------------------------- MODULE OrgDash -----------------------------
\* The organisation in the dashboard (nfltr docs/decisions/org-dashboard-2026-11-21.md,
\* spec/orgmove/README.md "OrgDash.tla"): the issuer's signed status the
\* relay holds and a pinned reader shows; revoke and renew started from the
\* dashboard as wishes the relay carries, made acts only by a root-signed
\* order or answer the owner approved on the root's machine; one set of
\* groups, member certificates' groups the issuer's choice within its bound;
\* one organisation per account.
\*
\* The attacker owns the relay: it forges or replays statuses, edits the
\* unsigned wrapper the reader receives, posts any wish, and replays any
\* order (orders persist in `orders`; dropping one is the absence of
\* fairness: only LiveSpec assumes delivery). The owner approves on the
\* root's machine only the acts they asked for (`intent`): the prompt names
\* the act, so a relay's wish is declined. The issuer's machine and the
\* root's machine are honest.
\*
\* A member's enrolment is `ser[n]` (0: never enrolled): a re-enrolment
\* after a revocation is a new one; renewals of a certificate stay in its
\* enrolment, so an order names the enrolment, not the daily serial.
EXTENDS Naturals, FiniteSets

CONSTANTS
    Names,      \* member names
    Groups,     \* the account's groups (the one set, decision (a))
    Bound,      \* the issuer certificate's groups: a subset of Groups
    MaxSerial,  \* enrolments per name (state bound)
    MaxTime,    \* time steps (state bound)
    Life,       \* an issuer certificate's life from the root's signature (30 days)
    Mutant      \* "none" or a bug put back (scripts/spec-orgmove.sh dash)

None == "none"
Forged == MaxTime + Life + 1   \* a NotAfter no issuer certificate carries
NoBody == 0   \* no status (no certificate ends at 0)
Max(S) == CHOOSE x \in S : \A y \in S : y <= x
RevokeWishes == {<<"revoke", n, s>> : n \in Names, s \in 1..MaxSerial}
RenewWishes == {<<"renew", t>> : t \in 0..MaxTime}
Wishes == RevokeWishes \cup RenewWishes

VARIABLES
    now,       \* the clock
    na,        \* the NotAfter of the issuer's current certificate
    installed, \* every NotAfter the issuer installed (genesis included)
    rootNA,    \* every NotAfter the root signed for the issuer
    ser,       \* ser[n]: n's current enrolment (0: none)
    revoked,   \* the enrolments <<n, s>> revoked
    tok,       \* tok[n]: the group of the unused token the issuer made for n, or None
    certG,     \* certG[n]: the group n's certificate carries, or None
    chose,     \* chose[n]: the group the issuer's own token chose for n's enrolment
    acctG,     \* acctG[n]: the account's (relay's) group record for n's machine
    issued,    \* every status the issuer signed, by its certificate's NotAfter (the
               \* member list is signed with it: one signature, abstracted away)
    copy,      \* the relay's copy: [signer, body, wrap] (wrap: the unsigned wrapper's NotAfter)
    shown,     \* the days-left NotAfter a pinned reader shows (NoBody: nothing yet)
    wishes,    \* wishes in the relay's wishes box
    intent,    \* the acts the owner asked for (dashboard clicks)
    orders,    \* root-signed orders and answers in the relay's orders box
    held,      \* the organisations whose status the account holds
    tried      \* a second organisation's issuer tried to register

vars == <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
          issued, copy, shown, wishes, intent, orders, held, tried>>

Body == 0..Forged

TypeOK ==
    /\ now \in 0..MaxTime
    /\ na \in 0..(MaxTime + Life)
    /\ installed \subseteq 0..(MaxTime + Life) /\ rootNA \subseteq 0..(MaxTime + Life)
    /\ ser \in [Names -> 0..MaxSerial]
    /\ revoked \subseteq Names \X (1..MaxSerial)
    /\ tok \in [Names -> Groups \cup {None}]
    /\ certG \in [Names -> Groups \cup {None}] /\ chose \in [Names -> Groups \cup {None}]
    /\ acctG \in [Names -> Groups]
    /\ issued \subseteq Body
    /\ copy \in [signer : {"issuer", "relay", None}, body : Body, wrap : 0..Forged]
    /\ shown \in Body
    /\ wishes \subseteq Wishes /\ intent \subseteq Wishes
    /\ orders \subseteq RevokeWishes \cup {<<"renew", x>> : x \in 0..(MaxTime + Life)}
    /\ held \subseteq {"o1", "o2"} /\ tried \in BOOLEAN

Init ==
    /\ now = 0
    /\ na = Life /\ installed = {Life} /\ rootNA = {Life}   \* `nfltr org init`: the root certifies the issuer
    /\ ser = [n \in Names |-> 0]
    /\ revoked = {}
    /\ tok = [n \in Names |-> None]
    /\ certG = [n \in Names |-> None] /\ chose = [n \in Names |-> None]
    /\ acctG = [n \in Names |-> CHOOSE g \in Groups : TRUE]
    /\ issued = {}
    /\ copy = [signer |-> None, body |-> NoBody, wrap |-> 0]
    /\ shown = NoBody
    /\ wishes = {} /\ intent = {} /\ orders = {}
    /\ held = {"o1"}    \* the account's organisation
    /\ tried = FALSE

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, wishes, intent, orders, held, tried>>

\* --- the issuer's machine (orgpki.Issuer, orgenrol.Service) ---

\* `nfltr org token --groups g` on the issuer's machine: within the bound
\* (orgpki MakeToken's subset; mutant group-outside-bound).
Token(n, g) ==
    /\ tok[n] = None
    /\ g \in Bound \/ Mutant = "group-outside-bound"
    /\ tok' = [tok EXCEPT ![n] = g]
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, certG, chose, acctG,
                   issued, copy, shown, wishes, intent, orders, held, tried>>

\* A machine redeems its token: a new enrolment (the first, or after a
\* revocation). Its certificate carries the token's group, never the
\* account's record (mutant relay-chosen-group: the issuer takes the
\* relay's group for the machine).
Enrol(n) ==
    /\ tok[n] # None
    /\ ser[n] < MaxSerial
    /\ ser[n] = 0 \/ <<n, ser[n]>> \in revoked
    /\ ser' = [ser EXCEPT ![n] = ser[n] + 1]
    /\ certG' = [certG EXCEPT ![n] = IF Mutant = "relay-chosen-group" THEN acctG[n] ELSE tok[n]]
    /\ chose' = [chose EXCEPT ![n] = tok[n]]
    /\ tok' = [tok EXCEPT ![n] = None]
    /\ UNCHANGED <<now, na, installed, rootNA, revoked, acctG,
                   issued, copy, shown, wishes, intent, orders, held, tried>>

\* The service's round: sign the status of the issuer's state and put it
\* on the relay's copy (the wrapper's NotAfter equals the body's: honest).
Publish ==
    /\ copy # [signer |-> "issuer", body |-> na, wrap |-> na]
    /\ issued' = issued \cup {na}
    /\ copy' = [signer |-> "issuer", body |-> na, wrap |-> na]
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   shown, wishes, intent, orders, held, tried>>

\* The service takes a root-signed order or answer from the orders box. A
\* revoke applies only to the enrolment it names, when current (mutant
\* order-by-name: the name's current enrolment, whichever). An answer is
\* installed only when it ends after the current certificate
\* (InstallRenewal; mutant install-old). Mutant no-apply-orders: the
\* service does not read the orders box.
Apply(o) ==
    /\ o \in orders
    /\ Mutant # "no-apply-orders"
    /\ IF o[1] = "revoke"
         THEN LET n == o[2]
                  s == IF Mutant = "order-by-name" THEN ser[n] ELSE o[3] IN
              /\ s = ser[n] /\ s > 0 /\ <<n, s>> \notin revoked
              /\ revoked' = revoked \cup {<<n, s>>}
              /\ UNCHANGED <<na, installed>>
         ELSE /\ o[2] > na \/ (Mutant = "install-old" /\ o[2] # na)
              /\ na' = o[2]
              /\ installed' = installed \cup {o[2]}
              /\ UNCHANGED revoked
    /\ UNCHANGED <<now, rootNA, ser, tok, certG, chose, acctG,
                   issued, copy, shown, wishes, intent, orders, held, tried>>

\* Mutants only (coverage skips them): the issuer acts on a relay-carried
\* wish without the root's order.
WishRevoke(w) ==
    /\ Mutant = "relay-only-revoke"
    /\ w \in wishes /\ w[1] = "revoke"
    /\ ser[w[2]] = w[3] /\ w[3] > 0 /\ <<w[2], w[3]>> \notin revoked
    /\ revoked' = revoked \cup {<<w[2], w[3]>>}
    /\ UNCHANGED <<now, na, installed, rootNA, ser, tok, certG, chose, acctG,
                   issued, copy, shown, wishes, intent, orders, held, tried>>
WishRenew(w) ==
    /\ Mutant = "renew-without-root"
    /\ w \in wishes /\ w[1] = "renew"
    /\ now + Life > na
    /\ na' = now + Life
    /\ installed' = installed \cup {now + Life}
    /\ UNCHANGED <<now, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, wishes, intent, orders, held, tried>>

\* --- the dashboard and the owner ---

\* The owner presses Revoke on a member the status shows (the enrolment
\* the reader shows: here the current one), or Renew.
AskRevoke(n) ==
    /\ ser[n] > 0
    /\ intent' = intent \cup {<<"revoke", n, ser[n]>>}
    /\ wishes' = wishes \cup {<<"revoke", n, ser[n]>>}
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, orders, held, tried>>
AskRenew ==
    /\ intent' = intent \cup {<<"renew", now>>}
    /\ wishes' = wishes \cup {<<"renew", now>>}
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, orders, held, tried>>

\* `nfltr org approve` on the root's machine: one Touch ID on a prompt
\* naming the act; the owner approves only what they asked for (mutant
\* no-owner-gate: the root's machine signs every wish). A renewal's answer
\* ends Life after the root's signature (SignIssuerRenewal).
Approve(w) ==
    /\ w \in wishes
    /\ w \in intent \/ Mutant = "no-owner-gate"
    /\ IF w[1] = "revoke"
         THEN /\ orders' = orders \cup {w}
              /\ UNCHANGED rootNA
         ELSE /\ orders' = orders \cup {<<"renew", now + Life>>}
              /\ rootNA' = rootNA \cup {now + Life}
    /\ wishes' = wishes \ {w}
    /\ UNCHANGED <<now, na, installed, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, intent, held, tried>>

\* A pinned reader (`nfltr org status --relay`, the page's check) takes the
\* copy only when the issuer signed it (mutant forged-status-accepted), and
\* shows days left from the signed certificate's NotAfter (mutant
\* notafter-unsigned: from the relay's wrapper).
Read ==
    /\ copy.body # NoBody
    /\ copy.signer = "issuer" \/ Mutant = "forged-status-accepted"
    /\ shown' = IF Mutant = "notafter-unsigned" THEN copy.wrap ELSE copy.body
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, wishes, intent, orders, held, tried>>

\* --- the relay (the attacker) ---

\* It forges a status: no issuer signature (a NotAfter none carries).
Forge ==
    /\ copy' = [signer |-> "relay", body |-> Forged, wrap |-> Forged]
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, shown, wishes, intent, orders, held, tried>>

\* It replays an older signed status, and may edit the unsigned wrapper.
Replay(b) ==
    /\ b \in issued
    /\ copy' = [signer |-> "issuer", body |-> b, wrap |-> Forged]
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, shown, wishes, intent, orders, held, tried>>

\* It posts any wish.
RelayWish(w) ==
    /\ w \notin wishes
    /\ wishes' = wishes \cup {w}
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, intent, orders, held, tried>>

\* It moves a member's machine to another account group (reach: the
\* relay's own decision, as today).
Move(n, g) ==
    /\ acctG[n] # g
    /\ acctG' = [acctG EXCEPT ![n] = g]
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose,
                   issued, copy, shown, wishes, intent, orders, held, tried>>

\* A second organisation's issuer puts its status into this account: the
\* relay refuses it (one organisation per account; mutant two-orgs).
PutOther ==
    /\ ~tried
    /\ tried' = TRUE
    /\ held' = IF Mutant = "two-orgs" THEN held \cup {"o2"} ELSE held
    /\ UNCHANGED <<now, na, installed, rootNA, ser, revoked, tok, certG, chose, acctG,
                   issued, copy, shown, wishes, intent, orders>>

Next ==
    \/ Tick \/ Publish \/ Read \/ Forge \/ AskRenew \/ PutOther
    \/ \E b \in issued : Replay(b)
    \/ \E w \in Wishes : RelayWish(w) \/ Approve(w) \/ WishRevoke(w) \/ WishRenew(w)
    \/ \E o \in orders : Apply(o)
    \/ \E n \in Names :
        \/ Enrol(n) \/ AskRevoke(n)
        \/ \E g \in Groups : Token(n, g) \/ Move(n, g)

Spec == Init /\ [][Next]_vars

\* The owner approves what they asked for, and the relay carries orders in
\* the end.
LiveSpec == Spec
    /\ \A w \in Wishes : WF_vars(w \in intent /\ Approve(w))
    /\ \A o \in RevokeWishes \cup {<<"renew", x>> : x \in 0..(MaxTime + Life)} : WF_vars(Apply(o))

\* I1: a status the reader shows is one the issuer signed (the relay may
\* replay an old one).
ShownSigned == shown = NoBody \/ shown \in issued

\* I2: the days left shown are a NotAfter an issuer certificate carried.
ShownNotAfterTrue == shown = NoBody \/ shown \in installed

\* I3, I4: an enrolment is revoked only by the order of an owner's own
\* request naming that enrolment (`nfltr org revoke` on the issuer's
\* machine, unchanged, is outside this model).
RevokedOnlyApproved == \A r \in revoked : <<"revoke", r[1], r[2]>> \in intent

\* I5: the issuer's NotAfter is one the root signed, and never goes back.
RenewOnlyByRoot == na \in rootNA
NotAfterMonotone == na = Max(installed)

\* I5: the root signs a renewal only for a Renew the owner pressed (the
\* genesis certificate aside): one approval, its prompt naming the act.
RootSignsOnlyAsked == \A x \in rootNA \ {Life} :
    \E t \in 0..MaxTime : <<"renew", t>> \in intent /\ t + Life <= x

\* I7: member certificates' groups lie within the issuer's bound.
CertInBound == \A n \in Names : certG[n] \in Bound \cup {None}

\* I8: they are the issuer's own choice, never the relay's record.
CertGroupsFromIssuer == \A n \in Names : certG[n] = chose[n]

\* I9: one organisation per account, so one bound names the account's groups.
OneOrgPerAccount == Cardinality(held) <= 1
BoundOf(o) == Bound   \* each organisation's issuer bounds the same account groups
AccountGroupsOneBound == \A g \in Groups : Cardinality({o \in held : g \in BoundOf(o)}) <= 1

\* L1: an owner's revoke request takes effect.
RevokeTakesEffect == \A n \in Names, s \in 1..MaxSerial :
    (<<"revoke", n, s>> \in intent) ~> (<<n, s>> \in revoked)

\* L2: an owner's renewal is installed.
RenewCompletes == \A t \in 0..MaxTime : (<<"renew", t>> \in intent) ~> (na >= t + Life)

\* Witnesses (each must be violated: the states are reachable).
WitnessRevokedFromDashboard == ~(revoked # {})
WitnessRenewed == ~(na > Life)
WitnessForgedRefused == ~(copy.signer = "relay" /\ shown # NoBody)
WitnessReplayShown == ~(shown # NoBody /\ shown < na)
WitnessStaleOrderRefused == ~(\E n \in Names : <<"revoke", n, 1>> \in orders /\ ser[n] = 2 /\ <<n, 2>> \notin revoked)
WitnessRelayWishDeclined == ~(\E w \in wishes : w \notin intent /\ orders # {})
WitnessSecondOrgRefused == ~(tried /\ held = {"o1"})
WitnessGroupMismatch == ~(\E n \in Names : certG[n] # None /\ acctG[n] # certG[n])
=============================================================================
