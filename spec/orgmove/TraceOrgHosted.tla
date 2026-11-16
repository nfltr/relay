--------------------------- MODULE TraceOrgHosted ---------------------------
(* Trace check of OrgHosted.tla's verifier side (spec/orgmove/README.md    *)
(* "OrgHosted.tla"): the lines relay client orgid's Verifier recorded       *)
(* (-tags enroltrace: client/orgid/trace_on.go, the same NDJSON files       *)
(* spec/enrol/TraceEnrol.tla checks), read in order. Its kinds:            *)
(*   itake   verifier v took (ok) or refused the root's CRL of issuers num  *)
(*           listing the issuer certificate serials rev; why sig: not the   *)
(*           root's signature (Deliver; a replay)                           *)
(*   rotate  verifier v took a rotation: its CRL of issuers is gone         *)
(*   check   verifier v admitted (ok) or refused a leaf expiring at exp     *)
(*           under issuer certificate is, which expires at ie; an admission *)
(*           lasts until u (Admit; a held session's re-check)               *)
(* Other kinds are TraceEnrol.tla's and change nothing here. Each line's    *)
(* outcome must be OrgHosted.tla's from what the lines before it            *)
(* established: an admission ends at the chain's earliest NotAfter          *)
(* (DelegationBound: u <= exp and u <= ie; mutant until-leaf-only), and no  *)
(* chain through an issuer certificate a taken CRL of issuers lists is      *)
(* admitted (RevokedIssuerRefused; mutant ignore-root-crl); a CRL of        *)
(* issuers is taken by a higher Number only (Conforms). Times are Unix      *)
(* seconds. TraceDone is violated when every line was read: accepted.       *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, iheld, bad

vars == <<l, iheld, bad>>

Init ==
    /\ l = 1
    /\ iheld = [x \in {} |-> 0]   \* verifier -> [num, rev]: its CRL of issuers
    /\ bad = {}

E == Log[l]
Set(sq) == {sq[i] : i \in DOMAIN sq}
Held == E.v \in DOMAIN iheld

ITakeOK == ~Held \/ E.num > iheld[E.v].num
ITakeBad ==
    CASE E.ok /\ ~ITakeOK -> {"diverged"}
      [] ~E.ok /\ ITakeOK /\ E.why # "sig" -> {"diverged"}
      [] OTHER -> {}

Listed == Held /\ E.is \in iheld[E.v].rev
CheckBad ==
    IF ~E.ok THEN {}
    ELSE (IF Listed THEN {"ignore-root-crl"} ELSE {})
         \cup (IF E.u > E.exp \/ E.u > E.ie THEN {"until-leaf-only"} ELSE {})

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ iheld' = CASE E.ev = "itake" /\ E.ok -> (E.v :> [num |-> E.num, rev |-> Set(E.rev)]) @@ iheld
                  [] E.ev = "rotate" -> [x \in DOMAIN iheld \ {E.v} |-> iheld[x]]
                  [] OTHER -> iheld
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev = "itake" -> ITakeBad
                  [] E.ev = "check" -> CheckBad
                  [] OTHER -> {}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
RevokedIssuerRefused == None({"ignore-root-crl"})
DelegationBound == None({"until-leaf-only"})
TraceDone == l <= Len(Log)
=============================================================================
