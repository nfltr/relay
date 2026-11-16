# An app's device enrolled for a person, in TLA+ (2026-11-16)

An app built on the relay SDK (a desktop or mobile app, a CLI such as
nfltr-send) makes its own key on a person's device and gets an
organisation certificate that names three things: the device slot (the
certificate's name, one per app per device), the person (an rfc822Name
SAN, the IdP's verified email) and the app (URI SAN
`nfltr://<org id>.internal/app/<id>`). It enrols one of two ways: an admin
code the owner made for that person and app (an organisation token,
`enrol.pv`'s), or the person's sign-in at the organisation's IdP
(OpenID Connect authorization code + PKCE) whose ID token's nonce commits
to the device's keys. A key enrolled by sign-in renews by itself only
until its sign-in ends (`authUntil`); then the person signs in again on
the device (Reauth). Revoking a person or an app revokes every name it
holds. The design is nfltr's
`docs/decisions/app-device-identity-2026-11-16.md`; `AppEnrol.tla` is that
design, checked before any code (`make spec-appenrol-ci`). Who can forge
or replay what over the relay is `spec/proverif/app_enrol.pv`; how a CRL
reaches verifiers is `spec/enrol/Enrol.tla`'s (here a certificate whose
`rev` is set is listed, the end of that model's delivery).

## Invariants

| property | means | mutant that breaks it |
|---|---|---|
| AttrsFixed | every certificate carries the person, app and key its name was enrolled with: renewals and sign-ins never change them | `renew-takes-attrs` (a renewal takes the person and app from the request) |
| SignInBindsKey | a key enrolled by sign-in is one the person's own sign-in named, for that app: the relay cannot attach its key to a token it saw | `no-nonce-check` (the issuer ignores the nonce) |
| CodeOnce | each admin code enrols at most once | `reusable-code` |
| DisabledUserBound | once the IdP disabled a person, no certificate of a key enrolled by sign-in ends later than TokLife + AuthLife + CertLife after it | `renew-ignores-auth` (renewal past authUntil), `no-token-exp` (a sign-in taken with an expired token), `reauth-any-user` (another person's sign-in on the device extends the name's; `AppEnrolTwo.cfg`) |
| RevokedUserCut | a revoked person holds no unlisted certificate, and is refused from then on | `revoke-user-one-name` (one of the person's names revoked), `sso-skips-deny` (a sign-in enrolment ignores the deny list) |
| RevokedAppCut | the same for a revoked app | `revoke-app-sso-only` (the app's code-enrolled names are missed) |

Witnesses (each must be violated, the state reachable): `WitnessSSOEnrol`,
`WitnessCodeEnrol`, `WitnessRenewed`, `WitnessReauth`,
`WitnessDisabledStillLive` (the residual the bound states: a certificate
of a disabled person is still live), `WitnessUserRevoked`,
`WitnessAppRevoked`. `-coverage 1` shows every action taken.

## Actions

| action | the issuer (or the world) |
|---|---|
| Tick | time passes; expired certificates and tokens are dropped (nothing depends on them) |
| Login | the person signs in for an app on a device; the IdP issues an ID token whose nonce commits to that device's key |
| DisableAtIdP | the organisation disables the person at its IdP |
| MintCode | the owner makes an admin code for a person and an app |
| EnrolSSO | a request (token, key) reaches the issuer: an honest device's, or the relay's with any token it saw and any key |
| EnrolCode | a device redeems its admin code |
| Renew | renewal with the current key, while the sign-in lasts (codes: until revoked) |
| Reauth | a new sign-in for the name's key and person extends authUntil |
| RevokeUser, RevokeApp | every live name of the person (app) revoked, its certificates listed, its enrolments refused |

## Environment assumptions

| assumption | source |
|---|---|
| the IdP authenticates the person and echoes the nonce of the authorization request in the ID token | OpenID Connect Core 1.0 §3.1.2.1, §3.1.3.7 (nonce) |
| an authorization code is bound to the device that started the request | RFC 7636 (PKCE), RFC 8252 §8.1 |
| an ID token is valid until its `exp`; the IdP refuses a disabled person a new one | OpenID Connect Core 1.0 §2; the IdP's account lifecycle |
| verifiers end a session at the peer certificate's NotAfter and on a CRL listing it | `spec/enrol/Enrol.tla` (RevocationBound), TLS 1.3 (RFC 8446) does not re-authenticate |
| clocks: the issuer's clock is the one that matters (it checks `exp` and `authUntil`); skew is folded into TokLife | org/orgenrol (the issuer's `now`) |

## Code map

The admin-code path is code: `orgpki.Issuer.MakeDeviceToken` (the code
names person and app), the profile's SANs (`machineTemplate`), renewal
keeping them, `RevokePerson` and `RevokeApp` (every name, and the person's
or app's enrolments from now, a code made before included). Its Go mutants,
in `org/orgpki/testdata/mutants.txt`, are this spec's: `renew-takes-attrs`,
`revoke-user-one-name`, `sso-skips-deny` (here: a code made before the
revoke), `revoke-app-sso-only`. Not yet code (lane APPID2, nfltr's decision
doc "Lanes"): the sign-in path (`SSOEnrol`, `Renew`'s `authUntil`,
`Reauth`) and the trace recorder (TraceAppEnrol.tla, `-tags enroltrace`).

| spec | code |
|---|---|
| AppEnrol.tla | org/orgenrol/issuer.go |
| AppEnrol.tla | org/orgpki/issuer.go |
| AppEnrol.tla | org/orgpki/profile.go |
