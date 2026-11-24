# Sign in with Nathan: a parent Nathan instance as an upstream (NATH-51)

One Nathan instance (the **child**) can let people sign in with their account on another Nathan instance (the **parent**). The first use is Insure's dedicated instances, `insure-id-stg.gmac.io` and `insure-id.gmac.io`, which federate to the gmacko parent at `id.gmac.io`. The child keeps its own users, sessions, clients, admission policy, administrators and signing keys. The parent is only a sign-in method there, like Google or GitHub.

It is provider id `nathan` in the shared provider registry (`src/shared/providers.mjs`), so it has the same lifecycle as the six social providers ([providers.md](providers.md)): one credential source, encrypted storage, Studio add/rotate/enable/disable, a recorded test sign-in, isolation when its credentials can't be used, and audit events.

## Configuration

| Field | Stored | Notes |
| --- | --- | --- |
| Parent issuer | `config` (clear) | Exactly the issuer the parent publishes. For a Nathan parent this is `https://<parent host>/api/auth`, e.g. `https://id.gmac.io/api/auth`. HTTPS, no trailing slash, query or fragment. It can't be the child's own origin. |
| Client ID | `client_id` (clear) | The client registered on the parent. |
| Client secret | `secret_fields` | AES-256-GCM under `NATHAN_CONFIG_KEY`, AAD `nathan:provider:v2:nathan:clientSecret`. Never returned by any API. |
| Button name | `config` (clear, optional) | Plain text, 1 to 40 characters (`A-Z a-z 0-9 space . ' & ( ) _ -`). "gmacko ID" shows **Sign in with gmacko ID**; empty shows **Sign in with Nathan**. |
| Trust the parent's `email_verified` (same owner) | `config` (clear) | Required; the only accepted value is `true`. See below. |

The CLI equivalent is `node scripts/nathan.mjs providers add nathan --apply` (Worker secret `NATHAN_PROVIDER_NATHAN`), with the same precedence rules as the other providers.

**Discovery only.** There are no hand-entered endpoints. On save (and once per isolate every ten minutes afterwards) Nathan reads `<issuer>/.well-known/openid-configuration`, without following redirects, and requires:

- `issuer` equal to the configured issuer, character for character;
- `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` and `jwks_uri` all HTTPS on the issuer's own origin, so a discovery document can never send the client secret, the access token or the browser to another host;
- at least one asymmetric ID token algorithm (`EdDSA`, `ES*`, `RS*`, `PS*`); `none` and `HS*` are never accepted. A Nathan parent signs with EdDSA (Ed25519);
- if advertised: the `code` response type, PKCE `S256` and `client_secret_basic`.

A save that fails any of these is refused and audited (`oauth_provider_update` / `failed_validation`), with the reason code in the message. If the parent's discovery fails later, the provider is turned off on its own (`nathan_provider_health` reason `unusable_credentials`, the NATH-17 isolation rule): its button disappears and its sign-in is refused, and every other method keeps working. It comes back by itself when discovery succeeds again; a failure is retried after one minute.

## The flow

Callback to register on the parent: **`https://<child host>/api/auth/callback/nathan`**. Studio shows it with a copy button.

1. The hosted button starts Better Auth's redirect flow through its first-party `genericOAuth` plugin (`src/auth/nathan-upstream.mjs`): authorization code, PKCE S256, `state` (kept in D1 and bound to the browser by a signed `SameSite=Lax` cookie), a `nonce`, and scopes `openid email profile`.
2. The parent signs the user in (its own passkeys, providers and MFA) and redirects back. Better Auth checks the RFC 9207 `iss` parameter against the issuer.
3. The child exchanges the code at the discovered token endpoint with `client_secret_basic` and the PKCE verifier.
4. The ID token is **required and verified**: signature against the parent's JWKS, the discovered algorithms, `iss`, `aud` (and `azp` when there are several audiences), `exp` and `iat` (30 s skew), and the `nonce` stored in this authorization's state.
5. A Nathan parent puts email and profile claims in UserInfo, not in the ID token (OIDC Core 5.4 allows this for the code flow). The child reads the discovered UserInfo endpoint with the access token from the same exchange and uses it only when its `sub` equals the verified ID token's `sub` (OIDC Core 5.3.2).
6. The account key is **issuer-qualified**: `account.accountId = "<issuer>#<sub>"`. Pointing the provider at another issuer can never sign in to accounts the previous one created.

A client-submitted ID token (`/sign-in/social` or `/link-social` with `idToken`) is refused for every provider (`ID_TOKEN_SIGN_IN_DISABLED`), and the upstream's verifier also refuses any ID token that didn't come from this child's own code exchange.

## Trust, admission and linking

**Email trust.** An account is created or linked only when both of these hold:

1. the parent asserts `email_verified` exactly `true` (the boolean; `"true"` doesn't count) for a well-formed address, and
2. an administrator has marked this parent as trusted for email verification.

Anything else is refused outright: no account, no placeholder address, no linking. Refusals are audited as `nathan_upstream_signin` by `system:nathan-upstream`, with outcome `refused_<reason>`: `email_unverified`, `untrusted_upstream`, `invalid_claims`, `userinfo_subject_mismatch`, `userinfo_unavailable`, `id_token_missing`, `id_token_invalid`, `id_token_nonce` or `client_id_token`.

**Why this differs from enterprise OIDC.** Enterprise OIDC connections ([saml.md](saml.md), `src/auth/enterprise-oidc-policy.mjs`) never trust an IdP's `email_verified` (`trustEmailVerified: false`). A customer's IdP can assert any address, so the only proof Nathan accepts there is the connection's DNS-verified domain. That rule doesn't fit a parent Nathan: its users have arbitrary addresses (gmail and others) that no domain proof covers. The parent, though, is another Nathan instance run by the **same owner**. It proves addresses itself, by email verification or through providers that verify them under the rules in [providers.md](providers.md). So the child accepts the parent's `email_verified`, but only after an administrator explicitly ticks "Trust the parent's email_verified (same owner)". The trust is a property of this configuration, never of the provider name. Don't tick it for a parent operated by someone else. Anyone who controls that parent could then sign in to or create any account here whose address they can mark verified.

**Admission.** Account creation goes through the installation's admission policy ([admission.md](admission.md)) like every other method, with method `social:nathan`. Invitation-only (the default) creates an account only for an address with an open invitation, which a verified parent address can claim. Self-service creates it for any verified parent address. A refused sign-in returns to `/sign-in?error=ACCOUNT_NOT_ADMITTED`. Like a verified social address, a verified parent address replaces a provisional password account someone squatted on an invited address.

**Linking** follows the same rules as social providers ([providers.md](providers.md#email-trust-and-account-linking)). No provider is trusted by name (`trustedProviders: []`). A parent account links to an existing child account only when the parent's address is verified, the child account's address is already verified (`requireLocalEmailVerified`), and the addresses are equal. Different-email linking and profile overwrite are off.

**No borrowed assurance.** The child takes only `sub`, `email`, `email_verified`, `name` and `picture` (HTTPS only) from the parent. The parent's `amr`, `acr` (Nathan sends `acr: "0"`), `auth_time` and any `nathan_amr`/`nathan_acr` claims are ignored. A sign-in through the parent creates no `nathan_admin_assurance` row, so tokens the child issues carry no `nathan_amr`/`nathan_acr` from it, and it never counts as the child's administrator step-up. MFA on the parent isn't local MFA. Administrator rights on the child still need the child's verified-email allowlist and an explicit grant; parent administrators get nothing automatically.

## Studio lifecycle

Identity Studio → **Social login providers** → **Nathan upstream**. Everything in [providers.md](providers.md#studio-rules) applies:

- Save/rotate (verified, enrolled administrator; audited `oauth_provider_update`), which also re-reads discovery. Saving enables the provider and voids its test.
- Enable/disable with `CONFIRM ENABLE nathan` / `CONFIRM DISABLE nathan`, under the last-login-method rule.
- **Test sign-in.** Sign in through the parent as an account linked to a child administrator. The test is recorded against the credential version.
- Isolation: if `NATHAN_CONFIG_KEY` can't decrypt the row, or the parent's discovery fails, only this provider turns off.
- The card links to the parent's Identity Studio (`<issuer origin>/studio`) once an issuer is saved.

## Owner steps

On the **parent** (for example id.gmac.io), in Identity Studio → OAuth clients, register one client per child:

| Field | Value |
| --- | --- |
| Name | e.g. `Insure ID (staging)` / `Insure ID (production)` |
| Kind | `external` (confidential; not public) |
| Redirect URI | `https://<child host>/api/auth/callback/nathan`, e.g. `https://insure-id-stg.gmac.io/api/auth/callback/nathan` |
| Scopes used | `openid email profile` (the child requests no others) |

Studio creates it with `client_secret_basic`, PKCE required and consent on. Copy the client secret: it's shown once. People see the parent's consent page the first time they sign in to each child.

On each **child**, in Identity Studio → Social login providers → Nathan upstream: issuer `https://id.gmac.io/api/auth`, the client ID and secret, an optional button name (e.g. `gmacko ID`), tick the trust box, save, then run **Test sign-in** as an administrator. Choose the admission mode (invitation-only by default) under Account admission.

## Relation to the fleet plan

This is the first, compatible step of track C ("Federation") in [plans/2026-11-22-dogfood-studio-fleet.html](plans/2026-11-22-dogfood-studio-fleet.html): the child adds the parent as an upstream with an exact issuer, endpoints and keys pinned through discovery, issuer-qualified subjects, and the child's admission policy still deciding who gets an account. Admin power on a child still comes only from a child-side grant. Not included yet: enrollment codes, the parent fleet registry, management credentials and the per-child "auto-admit parent users" switch (today, use self-service admission or invitations). The trust flag here is the per-child opt-in that the fleet's enrollment consent will later set.

## Not verified yet

Federation is tested end to end between two built Nathan Workers in workerd (`tests/runtime/nathan-upstream.test.mjs`), and the verifier's rejections (issuer, audience, nonce, expiry, signature, algorithm) in `tests/nathan-upstream.test.mjs`. A live run against id.gmac.io needs the owner's client registration above.
