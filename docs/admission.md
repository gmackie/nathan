# Account admission and invitations (NATH-16)

Admission decides whether a **new** Nathan account may be created. It is separate from:

- **application access**: roles and grants per app ([rbac.md](rbac.md)). An admitted account can reach no protected app until it is granted a role;
- **administrator privilege**: the verified-email allowlist plus an explicit grant ([setup-lifecycle.md](setup-lifecycle.md)).

Existing accounts are never affected: admission only runs when an account would be created.

## Modes

One installation-wide setting, changed in Identity Studio → **Account admission and invitations**:

| Mode | Who can create an account |
| --- | --- |
| **Invitation-only** (default) | Only an email address with an open invitation. Also the installer's first administrator (see below). |
| **Self-service** | Anyone who can complete a sign-in method that creates accounts (password sign-up, an enabled social provider, a just-in-time SAML or SCIM connection). |

A missing setting, an unknown value or a database error counts as invitation-only, so admission fails closed. Installations upgraded to migration 0017 start invitation-only. If yours relied on open sign-up, switch to self-service in Studio after upgrading.

## Every method, one rule

| Method | Where admission is enforced | Invitation matching |
| --- | --- | --- |
| Password sign-up | Better Auth `databaseHooks.user.create.before` | The sign-up address. The account still has to verify its email before it can sign in. |
| Social sign-in (all six providers) | same hook | The provider's verified email. A provider that does not verify the address gives Nathan a placeholder address (`<id>@<provider>.placeholder.invalid`), which never matches an invitation. |
| SAML just-in-time | same hook, after the SAML connection guard (just-in-time connection, verified domain) | The address the IdP signed, inside the connection's verified domain. |
| SCIM just-in-time | `admitJustInTime` in `src/auth/scim/lifecycle.ts` (SCIM writes D1 directly) | The directory address, inside the connection's verified domain. The invitation is claimed in the same D1 batch that creates the account. |

There is one Better Auth guard (`src/auth/database-hooks.ts` → `admissionUserCreateGuard`). It runs the SAML guard first, then the shared policy in `src/auth/admission-policy.mjs`. SCIM calls the same policy.

A refused sign-in creates no user row and shows a clear reason. Better Auth error code `ACCOUNT_NOT_ADMITTED`:

- password sign-up answers HTTP 422 with that code and message;
- social and SAML sign-ins return to `/sign-in?error=ACCOUNT_NOT_ADMITTED`, and the page explains it;
- SCIM records the reason on the directory user's link note (Studio → SCIM connection view).

## Invitations

- An administrator with completed enrollment and a fresh passkey step-up creates them in Studio (`POST /studio/api/admission`, `{op: "invite", email, days}`).
- An invitation is bound to one normalized email address and works **once**. It expires after 1 to 30 days (default 7) and can be revoked (`CONFIRM REVOKE INVITATION <id>`).
- At most one open invitation exists per address. A new one supersedes the previous one.
- An address that already has an account gets no invitation. That account simply signs in.
- Studio lists invitations with their state (`pending`, `used`, `expired`, `revoked`), creator, and the account and method that used them. Rows are never deleted.
- Every change is audited (`admission_mode_change`, `invitation_create`, `invitation_revoke`, outcomes `succeeded` or `rejected`). Admission decisions are audited as `account_admission` with the method (`password`, `social:github`, `saml:<connection>`, `scim:<connection>`) and outcome `admitted_invitation`, `admitted_self_service`, `admitted_bootstrap` or `refused`. Refusals are recorded at most once per method per minute.

There is no invitation token or link. The person signs in with the invited address through any enabled method. So invite only addresses whose owner you trust: whoever proves control of that address through an enabled method gets the account.

**Known limitation: password sign-up.** An invitation is used when the account is created, before its address is verified. Someone who knows an invited address could sign up with a password for it. That uses the invitation, but the account cannot sign in until the address is verified, so they gain nothing; the real person then needs a new invitation. Studio shows which method used each invitation, and the users list shows whether the address is verified. If this matters, keep password sign-in disabled (`ENABLE_PASSWORD=false`, the default).

## First administrator

The installer's first administrator is admitted without an invitation, in either mode, when **both** hold:

- the sign-in method proved the address (a verified provider email or a just-in-time SAML assertion, never a password sign-up), and it equals the installer-recorded `admin_email`;
- that account does not exist yet (`admin_user_id` is still empty).

Legacy manual installations have no installer record (`NATHAN_BOOTSTRAP_REQUIRED` is not `true`). There, a proven address in `NATHAN_ADMIN_EMAILS` is admitted the same way. Admission never grants administrator rights; the bootstrap and grant flows do.
