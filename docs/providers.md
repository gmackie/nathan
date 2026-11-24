# Social login providers

Nathan supports six social login providers: **Google, GitHub, Apple, Discord, Twitch and X**. None of them offers an API to create OAuth clients, so you still create the client in each provider's console. Nathan does the rest. It links straight to the right console page, shows the exact callback URL with a copy button, lists short setup steps, checks your credentials before saving them, and runs a live test sign-in.

All three setup surfaces read the same registry (`src/shared/providers.mjs`), so they show identical callback URLs and steps:

| Surface | Where |
| --- | --- |
| Identity Studio | `/studio` → **Social login providers**: status, guided setup, credential entry, rotation, enable/disable, test sign-in |
| Hosted installer | Step 3, "Configure first sign-in": any of the six as the first administrator's login |
| CLI | `node scripts/nathan.mjs providers guide <id>` and `providers add <id> --apply` |

Provider ids are `google`, `github`, `apple`, `discord`, `twitch` and `twitter` (X keeps Better Auth's `twitter` id, so its callback path ends in `/twitter`). Every callback has the form:

```
https://<identity host>/api/auth/callback/<id>
```

## Storage, secrets and precedence

- Credentials saved in Studio or the installer are stored in the `nathan_oauth_providers` D1 table (migration `0012_social_providers.sql`). Every secret field (client secrets, Apple's `.p8` key) is AES-256-GCM-encrypted under the Worker secret `NATHAN_CONFIG_KEY`. Its authenticated data is bound to the provider and field (`nathan:provider:v2:<id>:<field>`), so a ciphertext cannot be moved to another provider or field. Non-secret fields (client ID, Apple Team ID and Key ID) are stored in clear so Studio can show them.
- No API returns a secret. Studio shows only which secret fields are set.
- Rows written before migration 0012 keep their v1 Google/GitHub client-secret ciphertext until the next rotation.
- **One source of truth per provider.** Nathan reads each provider's credentials from exactly one place, in this order:
  1. the `NATHAN_PROVIDER_<ID>` Worker secret, a JSON credential bundle that `providers add <id> --apply` writes (CLI);
  2. the encrypted `nathan_oauth_providers` D1 row that Identity Studio or the hosted installer saves;
  3. the legacy `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` and `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` Worker secrets.

  Credentials are never copied from one source to another, so a rotation through the source in use always takes effect on the next request. Enabling, disabling or testing a provider never touches its credentials.
- **Studio refuses to save while the CLI secret exists.** A Studio save for a provider with a `NATHAN_PROVIDER_<ID>` secret is refused, audited (`denied_worker_secret`) and explained: rotate with `providers add <id> --apply`, or delete the secret with `npx wrangler secret delete NATHAN_PROVIDER_<ID>` and save in Studio. A CLI secret added later overrides an existing Studio row. Studio then reports the row as present but unused, with the command that hands control back to Studio. Likewise, Studio reports legacy secrets that a Studio row or CLI secret makes unused, and how to delete them. No credential is shadowed silently.
- A malformed `NATHAN_PROVIDER_<ID>` secret turns that provider off and Studio shows the error. It never falls back to an older source.
- **One broken provider never takes the others down (NATH-17).** Each provider's credentials are loaded on their own. Some can't be used: a D1 row that can't be decrypted (wrong or missing `NATHAN_CONFIG_KEY`, a bad restore, damaged ciphertext), a malformed `NATHAN_PROVIDER_<ID>` secret, or an Apple key that can't sign. Then only that provider is turned off: its button disappears and its sign-in is refused. It is **never** replaced by a lower-precedence source, such as the legacy `GITHUB_CLIENT_*` secrets that a Studio row overrides. The other providers, the sign-in page, Identity Studio and the repair path keep working.
  - Nathan marks the provider unavailable in `nathan_provider_health` (migration 0017; a reason code only: `decrypt_failed`, `invalid_worker_secret` or `unusable_credentials`, never a secret). It is audited as `oauth_provider_unavailable` / `skipped_<reason>` at most once per provider per hour while it stays broken, and as `cleared` when it is repaired or disabled.
  - Studio shows it with `available: false`, `unavailable: {reason, since}` and a notice. The public `/healthz` reports only how many providers are unavailable (`detail.socialProviders.unavailableCount`), never which ones or why, while `ok` stays `true`, because the identity Worker and the other methods are healthy. Monitor that count; Studio shows the provider ids and reason codes to administrators.
  - **Repair** by saving new credentials in Studio (or rotating the source in use), or by fixing `NATHAN_CONFIG_KEY`. **Disable** works even when it is the last provider, because a provider that cannot be used is no sign-in method anyone has. Enabling it again needs usable credentials.
- Enable/disable flags and test records live in `nathan_provider_state` for every provider, whichever source holds the credentials. A configured provider is enabled until an administrator disables it, and a disable stays in force when its credentials change.
- Provider configuration is read on every request, so enable, disable and rotation take effect immediately.

## Studio rules

- Every write (save/rotate, enable, disable, test) needs a verified administrator who has completed enrollment; any other session gets 403. Each write is audited without credential values: `oauth_provider_update` (`attempted`, then `succeeded`, `failed_validation`, `failed_config_key`, `denied_worker_secret` or `failed`), `oauth_provider_enable`/`oauth_provider_disable` (`succeeded`, `denied_confirmation`, `denied_not_configured`, `denied_last_method`) and `oauth_provider_test` (`attempted`, `succeeded`, `failed`, `failed_credentials_changed`). An unsupported provider id is audited as `unsupported`, never echoed.
- Enable and disable need the exact confirmation `CONFIRM ENABLE <id>` or `CONFIRM DISABLE <id>`.
- **Credential version.** Each provider's credentials have a version: an HMAC-SHA-256 of the provider id and its credential fields, under a key derived from `BETTER_AUTH_SECRET`. It is stored with test tickets, callback evidence and test records, never shown, and contains no secret. Rotating `BETTER_AUTH_SECRET` voids every test record.
- **Test sign-in.** Studio issues a single-use ticket (10 minutes, stored only as a SHA-256 digest) bound to the provider's current credential version, then signs in through the provider with a callback to `/studio/providers/test-complete`. The test is recorded only if the current session was created by that provider's callback after the ticket was issued, and the ticket, the callback and the provider's current credentials all have the same version. Saving credentials in Studio voids open tickets for that provider. A CLI rotation can't be observed as an event, so the version check catches it at completion. Your browser ends up signed in as whichever account you used.
- **Tests and credential changes.** A test counts only for the credential version it ran against. Changing credentials by any path (Studio, installer, CLI, legacy secrets) voids it. Studio also clears the stored record on save. Studio shows a stale test as "credentials changed after the last successful test sign-in".
- **Last login method.** Disabling a provider succeeds only if, afterwards, administrators can still sign in: another enabled provider has a test sign-in **performed by an account that is currently a Nathan administrator** with that provider's current credentials, or password sign-in is enabled and a current administrator has a password, or enterprise SSO is enabled with a verified domain matching a current administrator's email. A test with a non-administrator test account shows the provider works but does not count. Revoking the administrator who ran a test removes its protection. The check and the write are one conditional D1 statement, so two concurrent disables cannot both pass. The installer's first provider and Worker-secret providers start untested, so run an administrator test before relying on them as the only method.

## Email trust and account linking

Sign-in always uses the redirect flow (state, and PKCE where the provider supports it). Direct ID-token sign-in and linking (`/sign-in/social` or `/link-social` with an `idToken`) is disabled for every provider, so a leaked provider ID token issued to Nathan's client ID cannot be replayed to sign in.

Nathan never trusts a provider by name (`trustedProviders: []`). Better Auth links a social account to an existing Nathan user only when both of these hold:

1. The provider asserts the email is verified, under the per-provider rules below.
2. The existing Nathan user's email is already verified (`requireLocalEmailVerified: true`).

Different-email linking and profile overwrite on link are off. An email that is absent or unverified is replaced by a non-routable placeholder, `<provider account id>@<provider>.placeholder.invalid` (RFC 6761). It can't link to, squat on, or become an administrator address (admin checks need a verified email), and Nathan's ID tokens carry `email_verified: false` for it.

| Provider | Email is kept only when |
| --- | --- |
| Google | the ID token's `email_verified` is `true` |
| GitHub | it is the account's **primary** email and GitHub marks it `verified` (a public profile email is ignored) |
| Apple | the ID token's `email_verified` is `true` or `"true"` |
| Discord | the user object's `verified` flag is `true` |
| Twitch | the ID token's `email_verified` claim is `true` (Nathan requests the `email` and `email_verified` claims) |
| X | X returns `confirmed_email`, which needs email access on the app |

**Admission.** The provider config never sets `disableSignUp`, `disableImplicitSignUp` or any other per-provider sign-up option. New-account admission is therefore identical for all six providers, and is decided by Nathan's installation-wide admission policy ([admission.md](admission.md), NATH-16). It is invitation-only by default: a social sign-in creates an account only for a provider-verified email with an open invitation, or in self-service mode. An unverified provider email becomes a placeholder address and never matches an invitation. Administrator rights still need the verified-email allowlist and an explicit grant.

## Google

- Console: <https://console.cloud.google.com/auth/clients/create> (Google Auth Platform → Clients)
- Callback: `https://login.example.com/api/auth/callback/google`
- Scopes: `openid email profile`
- Credentials: Client ID (`….apps.googleusercontent.com`) and Client secret (usually `GOCSPX-…`).

Create a **Web application** client. Add the callback under *Authorized redirect URIs* and leave *JavaScript origins* empty. Gotcha: while the app's audience is *External* and in **Testing**, only listed test users can sign in. Publish the app for general use.

## GitHub

- Console: <https://github.com/settings/applications/new> (Settings → Developer settings → OAuth Apps)
- Callback: `https://login.example.com/api/auth/callback/github`
- Scopes: `read:user user:email`
- Credentials: Client ID and a 40-character hex client secret. GitHub shows the secret once.

Use organization settings for an organization-owned app. Gotcha: if you use a GitHub **App** rather than an OAuth App, grant the *Email addresses* read-only account permission, or Nathan can't see the primary email.

## Apple

- Console: <https://developer.apple.com/account/resources/identifiers/list/serviceId> (Certificates, Identifiers & Profiles)
- Callback (Return URL): `https://login.example.com/api/auth/callback/apple`
- Scopes: `name email`, with `response_mode=form_post`
- Credentials: **Services ID** (the client ID, for example `com.example.login`), **Team ID**, **Key ID** and the **`.p8` private key**.

Setup:

1. Make sure an App ID has the *Sign in with Apple* capability. This is the primary App ID.
2. Register a Services ID and enable Sign in with Apple on it. Choose the primary App ID, add the identity hostname under *Domains and Subdomains*, and add the callback under *Return URLs*.
3. Create a key with Sign in with Apple enabled and download the `.p8` file. Apple lets you download it only once.

Nathan never stores a client secret for Apple. On each request it mints an ES256 JWT (`iss` = Team ID, `sub` = Services ID, `aud` = `https://appleid.apple.com`, `kid` = Key ID, lifetime one hour) from the encrypted `.p8` key. The JWT is cached only in the isolate's memory and re-minted when less than ten minutes remain. Before saving a key, Studio and the installer prove they can sign with it.

Gotchas:

- **Domain verification.** Apple's console requires the identity hostname to be registered on the Services ID. Some accounts are asked to host `/.well-known/apple-developer-domain-association.txt`. Nathan doesn't serve that file, so if Apple asks for it, complete verification before enabling Apple. This hasn't been checked against a live Apple account.
- Apple **POSTs** the response cross-site. Better Auth keeps OAuth state in D1 and binds it to the browser with a signed `SameSite=Lax` cookie, which browsers do not send with a cross-site POST. The POST leg therefore needs no cookie and only redirects (no token exchange, no session) to a GET on the same callback. That top-level GET navigation does carry Lax cookies, and it runs the state-cookie check, the code exchange and session creation. A GET without the state cookie fails. A form-posted `id_token` is dropped.
- **What is verified in Apple's ID token.** In the redirect flow, Better Auth 1.7.14 decodes the ID token returned by Apple's token endpoint without checking its signature against Apple's JWKS. Trust comes from TLS to `appleid.apple.com` and the code exchange authenticated with Nathan's signed client secret (allowed by OIDC Core 3.1.3.7 step 6). An ID token a client submits directly to `/api/auth/sign-in/social` (`idToken`) is signature-checked against `https://appleid.apple.com/auth/keys`, with issuer and audience checks. Both behaviors are tested in workerd against a mocked Apple that serves a JWKS.
- Apple sends the user's name only on the first authorization. Return URLs must be HTTPS; `localhost` and IP addresses are rejected.
- To email *Hide My Email* (`privaterelay.appleid.com`) addresses, register your sending domain under *Sign in with Apple for Email Communication*.
- If you revoke or rotate the key in Apple's console, save the new Key ID and `.p8` in Studio. Saving clears the test record.

## Discord

- Console: <https://discord.com/developers/applications>
- Callback: `https://login.example.com/api/auth/callback/discord` (OAuth2 → Redirects)
- Scopes: `identify email`
- Credentials: numeric Client ID (snowflake) and the client secret from *Reset Secret*.

Gotchas: leave *Public Client* off. Discord accounts may have unverified emails. Those accounts get a placeholder email in Nathan and never link by email. Better Auth 1.7.14 protects Discord sign-in with server-side state and the confidential client secret; it does not send PKCE to Discord.

## Twitch

- Console: <https://dev.twitch.tv/console/apps/create>
- Callback: `https://login.example.com/api/auth/callback/twitch` (OAuth Redirect URLs)
- Scopes: `openid user:read:email`, plus the `email` and `email_verified` ID-token claims
- Credentials: 30-character Client ID and client secret (*New Secret*). Set Client Type to **Confidential**.

Gotchas: the Twitch console requires two-factor authentication. The redirect URL must match exactly, with no trailing slash.

## X

- Console: <https://developer.x.com/en/portal/projects-and-apps> (your app → *User authentication settings*)
- Callback: `https://login.example.com/api/auth/callback/twitter`
- Scopes: `users.read tweet.read users.email offline.access`
- Credentials: the **OAuth 2.0** Client ID and Client Secret, not the OAuth 1.0a API Key and Secret.

Choose *Web App, Automated App or Bot* (a confidential client). X always uses PKCE; Nathan sends an S256 challenge and authenticates the token request with HTTP Basic.

Gotcha: **email access.** X returns a confirmed email only if the app has *Request email from users* turned on, which requires Terms of Service and Privacy Policy URLs. Without it, Nathan stores a placeholder email and never links X accounts by email. It hasn't been verified live whether X rejects the `users.email` scope for apps without email access, so test sign-in before relying on X.

## CLI

```sh
node scripts/nathan.mjs providers guide apple        # console link, exact callback, steps, gotchas
node scripts/nathan.mjs providers add discord --apply
```

`add` prompts for non-secret fields, masks secrets in a TTY, and reads the Apple key from a `.p8` file path. It validates the values with the shared registry and stores them through `wrangler secret put NATHAN_PROVIDER_<ID>` over stdin. Secrets are never passed as command-line arguments or written to `nathan.config.json`.

The Worker secret then becomes the provider's only credential source: it takes effect on the next request and overrides credentials saved in Studio, which Studio reports as unused. It also voids the previous test sign-in. A provider disabled in Studio stays disabled. To hand control back to Studio, delete the secret (`npx wrangler secret delete NATHAN_PROVIDER_<ID>`) and save the credentials in Studio.

## Passwordless email sign-in (email code)

NATH-49. Better Auth's first-party `emailOTP` plugin, for sign-in only: the person enters an email address, Nathan mails a 6-digit code, and the person enters it on the hosted sign-in page ("Email me a code"). It suits people who have no social account to use and should not hold a password, such as an app's outside bidders. On an instance with `AUTH_MODE=single-app` (NATH-52), the pinned app calls the same checks over `NathanVerifier` and draws its own form; the hosted page on the identity hostname remains the IdP management UI.

**Enable it per instance.** It is off by default and existing instances do not change.

| Setting | Value |
| --- | --- |
| `ENABLE_EMAIL_OTP` (Worker var) | `"true"` turns it on; anything else is off. |
| `RESEND_API_KEY` (Worker secret) | Resend API key. Mail goes only through `src/auth/email.ts`. |
| `EMAIL_FROM` (Worker var or secret) | Sender on a domain verified in Resend, for example `gmacko <login@gmac.io>`. |

With the flag on but Resend not configured, the sign-in page does not offer the method and the send endpoint answers 503 (`EMAIL_SIGN_IN_UNAVAILABLE`): nothing fails silently. The plugin adds no Better Auth tables (codes live in `verification`); migration `0019_email_otp.sql` adds Nathan's email-code session record and limit counters.

**Routes.** `POST /api/auth/email-otp/send-verification-otp` (`{email, type: "sign-in"}`) and `POST /api/auth/sign-in/email-otp` (`{email, otp, oauth_query?}`). Other fields are refused (a first sign-in takes no name, image or other profile from the request). The plugin's other routes (email verification, password reset, email change, code check) are disabled on every instance.

**Codes.** 6 digits, valid 10 minutes, stored hashed, single use. A new code replaces the previous one. After 3 wrong guesses the code is gone and the person requests a new one.

**Rate limits.** Per IP (Better Auth's limiter): 10 sends and 20 sign-in attempts per 10 minutes. Per address (`nathan_email_otp_limits`, fixed windows under SHA-256 keys, so no table holds an address): 3 sends per 10 minutes and 10 a day; 5 sign-in attempts per 10 minutes and 15 a day. Instance-wide: after 500 refused codes in an hour, every sign-in attempt waits for the next hour, which caps guessing spread over many addresses and IPs (audited once as `email_otp_failure_budget_exhausted`). Same-origin requests only. Over a limit the answer is 429 with `X-Retry-After`, audited as `email_otp_rate_limited`.

**No account enumeration.** The send step answers `{success: true}` for every valid address and mails in the background (`waitUntil`), so the answer and its timing do not depend on the address. A code is mailed only to an address that may sign in by code: an existing account that has nothing stronger (see below), or, for a new account, an address that admission would accept (an open invitation, the installer's first administrator, or any address in self-service mode) outside a verified SSO domain. For any other address nothing is mailed, and any code typed fails exactly like a wrong code. Delivery errors are logged by Resend status only; codes and addresses are never logged.

**Mail.** Subject "Your <instance name> sign-in code" (the code is not in the subject); the body has the code, the requesting host, the 10-minute lifetime and a warning to enter it only on that host. No link.

**Admission.** The code proves the address, so the account is created `emailVerified` through the admission guard as method `email-otp`: it can claim an open invitation, the installer's first administrator is admitted, self-service creates the account, and invitation-only refuses an unknown address (`ACCOUNT_NOT_ADMITTED`, no user row). See [admission.md](admission.md).

**Accounts with something stronger.** An emailed code never replaces a stronger way in. These accounts never sign in by code:
- administrators (Better Auth admin role, an administrator grant, or the installer's bound first administrator);
- accounts with a verified TOTP authenticator or a passkey (the code would skip that factor);
- directory (SCIM) accounts, accounts linked to an enterprise SSO connection, and any address in a DNS-verified SSO domain (those people sign in through their IdP, with its MFA and policies).

They get no mail. Better Auth checks the code first (so attempts, expiry and lockout behave exactly as for anyone else) and Nathan then refuses the session with the wrong-code answer, so the responses reveal nothing about the account. An unverified account is never given a session by code unless the code verified it through admission.

**Email-code sessions never administer.** Every session created by a code is recorded (`nathan_email_otp_sessions`), and `mayAdminister` refuses it whatever the security profile, even if the person later becomes an administrator or adds a passkey step-up to that session. (The installer's first administrator may still create the account by code before the bootstrap binds it, as with any method that proves the address; administration then needs a new sign-in by passkey or provider.)

**Assurance.** An emailed code is neither a passkey nor phishing-resistant MFA. The session gets no `nathan_admin_assurance` row, so tokens carry no `nathan_amr`/`nathan_acr`, SAML assertions use the unspecified AuthnContext, and the session never counts as an administrator step-up. For accounts that may use it (no TOTP, passkey, directory or SSO link), whoever controls the mailbox can sign in. Leave it off on instances whose accounts must not be reachable by email alone.

**Audit.** `email_otp_sign_in` (actor: user, target: session, `succeeded`) for each sign-in, written with the email-code session record; if either write fails the session is deleted and the sign-in fails. Refused codes are audited as `email_otp_sign_in` `rejected` with the error code and the hour's refused-code count (at most one row per minute per code), and refused accounts as `refused:<reason>`. Account creation is audited as `account_admission` with method `email-otp`.

**OIDC.** The sign-in page sends the signed `oauth_query`, so `/api/auth/oauth2/authorize` resumes after the code is accepted (workerd-tested).

## Enterprise SSO

Better Auth's SSO plugin supports enterprise OIDC and SAML **as inbound identity sources**. The code enables the plugin via `ENTERPRISE_SSO=true`. Identity Studio registers enterprise OIDC providers and, since NATH-10, inbound SAML connections with metadata validation, DNS domain verification, disabled-by-default enablement, certificate rotation and per-connection provisioning; see [saml.md](saml.md) for Okta, Entra ID and Google Workspace setup. Nathan serving as a SAML IdP downstream is a separate future feature (NATH-12).

## Multi-factor authentication

Passkeys and TOTP are enabled at the Better Auth plugin level. A successful social or email-code sign-in is not NIST AAL2: Nathan never derives an AAL claim from a social provider or an emailed code.

## Not verified yet

All provider behavior above was tested in workerd against **mocked** provider endpoints. Before relying on any provider in production, run a staging sign-in with a real test account for each one (see [staging-checklist.md](staging-checklist.md)). Pay particular attention to Apple domain registration and form_post, X email access, and the Twitch `email_verified` claim.
