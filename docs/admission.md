# Account admission and invitations (NATH-16)

Admission decides whether a **new** Nathan account may be created. It is separate from:

- **application access**: roles and grants per app ([rbac.md](rbac.md)). An admitted account can reach no protected app until it is granted a role;
- **administrator privilege**: the verified-email allowlist plus an explicit grant ([setup-lifecycle.md](setup-lifecycle.md)).

Existing accounts are never affected: admission only runs when an account would be created.

## Modes

One installation-wide setting, changed in Identity Studio → **Account admission and invitations**:

| Mode | Who can create an account |
| --- | --- |
| **Invitation-only** (default) | Only an email address with an open invitation, and only once the sign-in method has proven that address (see below). Also the installer's first administrator. |
| **Self-service** | Anyone who can complete a sign-in method that creates accounts (password sign-up, an enabled social provider, an email sign-in code, enterprise OIDC SSO, a just-in-time SAML or SCIM connection). |

A missing setting, an unknown value or a database error counts as invitation-only, so admission fails closed.

### Upgrading to migration 0017

Installations upgraded to migration 0017 start invitation-only. The migration records this once in the security audit (`admission_default_invitation_only`, target `existing-users` when the installation already had accounts, `no-existing-users` otherwise). On an installation that had accounts, Identity Studio shows a one-time notice above **Account admission and invitations**, with a link to the mode setting, until an administrator changes the mode or dismisses it (audited as `admission_mode_change` or `admission_upgrade_notice_dismiss`).

After the upgrade, until you invite people or switch to self-service:

- sign-ups that used to work (password, social, enterprise SSO) are refused with `ACCOUNT_NOT_ADMITTED`;
- **SCIM just-in-time connections stop creating accounts.** Directory users without a Nathan account stay unlinked, with the reason in their link note. Linking existing accounts is unaffected. Saving the connection's settings again after you switch to self-service (or invite the addresses) creates them.

If your installation relied on open sign-up, switch to self-service in Studio right after upgrading.

## Every method, one rule

An invitation is claimed only by a method that has **proven** the address. For every Better Auth way of creating an account that means `emailVerified === true` on the account being created, set by the method itself and never by an IdP's unchecked claim. Password sign-up is the only exception, because it proves nothing until its verification email is used.

| Method | Where admission is enforced | What proves the address, and when the invitation is claimed |
| --- | --- | --- |
| Password sign-up | Better Auth `databaseHooks.user.create.before`, then `emailVerification.beforeEmailVerification` | Nothing at sign-up. With an open invitation the account is created **provisionally** (unverified, recorded in `nathan_admission_pending`) and claims nothing; it cannot sign in. The invitation is claimed when the person opens the verification link. If by then it was revoked, expired or used by the real person, verification is refused (`ACCOUNT_NOT_ADMITTED`) and the account stays unverified and unusable. |
| Social sign-in (all six providers) | same hook | The provider's verified email; claimed when the account is created. A provider that does not verify the address gives Nathan a placeholder address (`<id>@<provider>.placeholder.invalid`), which never matches an invitation. |
| Email sign-in code (`/sign-in/email-otp`, NATH-49) | same hook (method `email-otp`) | The 6-digit code mailed to the address; claimed when the account is created. In invitation-only mode a code is mailed only to an address with an account, an open invitation or the first-administrator record, and an unknown address creates no account even with a valid code. A code for an existing **unverified** account (for example a squatted password sign-up) runs the same check as a verification link before Better Auth marks it verified: it claims the open invitation (recorded as `email-otp`) or is refused, and the unproven profile, password and sessions are dropped. An address in a verified enterprise SSO domain never gets an account by code. |
| Enterprise OIDC SSO (`/sso/callback/<connection>`) | same hook, after the enterprise OIDC guard (`src/auth/enterprise-oidc-policy.mjs`) | An address inside the connection's DNS-verified domain; claimed when the account is created. Nathan never trusts the IdP's `email_verified` claim (`trustEmailVerified: false`), so, as with SAML, an address outside the verified domain, or a connection whose domain is not verified, creates no account in either mode and claims nothing. |
| SAML just-in-time | same hook, after the SAML connection guard (just-in-time connection, verified domain) | The address the IdP signed, inside the connection's verified domain; claimed when the account is created. |
| SCIM just-in-time | `admitJustInTime` in `src/auth/scim/lifecycle.ts` (SCIM writes D1 directly) | The directory address, inside the connection's verified domain. The invitation is claimed in the same D1 batch that creates the account, so a SCIM claim racing a Better Auth claim for the same invitation leaves exactly one account. |

There is one Better Auth guard (`src/auth/database-hooks.ts` → `admissionUserCreateGuard`). It runs the SAML guard and the enterprise OIDC guard first, then the shared policy in `src/auth/admission-policy.mjs`. SCIM calls the same policy. Any `/sso/` route other than the SAML ACS and the OIDC callback creates no account.

A refused sign-in creates no user row and shows a clear reason. Better Auth error code `ACCOUNT_NOT_ADMITTED`:

- password sign-up answers HTTP 422 with that code and message (and so does a refused verification link);
- social and SAML sign-ins return to `/sign-in?error=ACCOUNT_NOT_ADMITTED`, and the page explains it;
- SCIM records the reason on the directory user's link note (Studio → SCIM connection view).

## Invitations

- An administrator with completed enrollment and a fresh passkey step-up creates them in Studio (`POST /studio/api/admission`, `{op: "invite", email, days}`).
- An invitation is bound to one normalized email address and works **once**. It expires after 1 to 30 days (default 7) and can be revoked (`CONFIRM REVOKE INVITATION <id>`).
- At most one open invitation exists per address. A new one supersedes the previous one.
- An address that already has a verified account gets no invitation. That account simply signs in. For an address held by an **unverified** account, Studio refuses a plain invitation and offers **reissue** (see below).
- Studio lists invitations with their state (`pending`, `used`, `expired`, `revoked`), creator, and the account and method that used them. Rows are never deleted.
- Every change is audited (`admission_mode_change`, `invitation_create`, `invitation_revoke`, `unverified_account_remove`, `admission_upgrade_notice_dismiss`, outcomes `succeeded` or `rejected`). Admission decisions are audited as `account_admission` with the method (`password`, `social:github`, `email-otp`, `enterprise-sso:<connection>`, `saml:<connection>`, `scim:<connection>`) and outcome `admitted_invitation`, `admitted_invitation_pending` (a provisional password sign-up), `admitted_self_service`, `admitted_bootstrap`, `refused` or `refused_at_verification`. Refusals at sign-up are recorded at most once per method per minute.

An invitation is claimed atomically (one statement) when a proving method is about to create the account, or when a provisional password account verifies its address. If Better Auth then fails to create the account (for example, a concurrent sign-up created the same address first), the invitation stays used: create a new one.

There is no invitation token or link. The person signs in with the invited address through any enabled method. So invite only addresses whose owner you trust: whoever proves control of that address through an enabled method gets the account.

### Someone signed up first with the invited address

Anyone who knows an invited address can sign up for it with a password (when password sign-in is enabled). That account is provisional: it claims nothing, the invitation stays open, and it cannot sign in, because the address is unverified. The real person still gets in, without database work:

- **Social sign-in** with a provider that verifies the address: Nathan deletes the provisional account first (it never signed in and holds no passkey), audited as `account_superseded` by `system:admission` (the row records the deleted account, the address and the provider that proved it), and the real person's account is created with the invitation. The squatter's password goes with the deleted account.
- **Any method** (including enterprise SSO): an administrator uses Studio → **Reissue an invitation** (`{op: "reissue", email, confirm: "CONFIRM REISSUE INVITATION <email>"}`; enrolled administrator with a fresh passkey step-up). It removes the unverified account (never a verified one, an administrator, a directory-managed account, or one that has a current session, a passkey, or any social or SSO login — a session ends at sign-out, so a linked login is what proves an account was used), audited as `unverified_account_remove`, and creates a new invitation.

Studio shows which method used each invitation, and the users list shows whether an address is verified. If you do not need it, keep password sign-in disabled (`ENABLE_PASSWORD=false`, the default).

## First administrator

The installer's first administrator is admitted without an invitation, in either mode, when **both** hold:

- the sign-in method proved the address (a verified provider email, an email sign-in code, or an enterprise SSO address inside a verified domain; a password sign-up only when it was invited and then verified its address), and it equals the installer-recorded `admin_email`;
- that account does not exist yet (`admin_user_id` is still empty).

Legacy manual installations have no installer record (`NATHAN_BOOTSTRAP_REQUIRED` is not `true`). There, a proven address in `NATHAN_ADMIN_EMAILS` is admitted the same way. Admission never grants administrator rights; the bootstrap and grant flows do.
