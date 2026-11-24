# App-scoped provisioning

A dedicated ClassCheck installation exposes a server-side service binding for its
admission and grant reconciliation jobs. Pin the binding to the installation's
application ID. Use the dedicated Worker in each environment.

```json
{
  "binding": "NATHAN_PROVISION",
  "service": "nathan-classcheck-stg-auth",
  "entrypoint": "NathanAppProvisioner",
  "props": { "applicationId": "classcheck" }
}
```

The installation needs a complete standalone configuration and an enabled
application registered to its exact customer hostname with `approved` access.
Define its `member` role and attach `profile:read` for ClassCheck self-service.
The provisioner refuses a default member role carrying additional permissions.
Define the other roles and their endpoint permissions from ClassCheck's app
manifest. The school, district and guardian assignments remain in ClassCheck.

## Admit an identity

Call this operation after ClassCheck has established the person's eligibility.
Use the durable ClassCheck user ID for `externalId`. Keep application login and
administrative identities separate.

```ts
const result = await env.NATHAN_PROVISION.provision({ externalId, email });
if ("sub" in result) {
  // Bind the stage's verified issuer and this subject to the existing local ID.
  await saveIdentity(issuer, result.sub, externalId);
}
```

First admission creates an unverified Nathan subject and its baseline app grant
in one transaction. Nathan proves the mailbox during sign-in. Enterprise SSO
and enrolled TOTP retain their existing rules. Retrying the same local ID and
normalized email returns the same live subject. An existing unrelated address,
operator address, changed identity, suspended membership or deleted subject
requires reconciliation. ClassCheck can retry transport failures with the same
inputs. The provisioning operations share a 120-call per-minute app limit.

For new reservations in a verified enterprise SSO domain or one of its subdomains,
Nathan returns `{error: "identity_conflict", reason: "verified_enterprise_domain"}`.
Have the organization establish the identity through its configured SSO provider
and reconcile the verified issuer and subject with the durable ClassCheck user ID.
Studio directs invitation recovery for a source-owned subject back to the application.

## Reconcile grants

Persist each desired role set and its positive, increasing safe-integer revision
in ClassCheck. Deliver it with the original external ID and the exact returned
subject. Every active set includes `member`. The app roles available to this
binding are `member`, `guardian`, `staff`, `driver` and `platform_admin`.
The last role applies exclusively to the ClassCheck application.

```ts
const result = await env.NATHAN_PROVISION.syncGrants({
  externalId, sub, revision, roles: ["member", "guardian"]
});
// A successful reply has the exact sub and revision and a boolean applied flag.
```

A newer revision changes the managed grants, writes the app change feed and
audits the operation in one transaction. An identical replay returns
`{sub, revision, applied: false}`. A conflicting replay returns
`{error: "identity_conflict"}`. A superseded revision returns
`{error: "stale_revision"}`. Other errors are `invalid_input`,
`not_configured`, `rate_limited` and `identity_conflict`; a storage or RPC error
can throw. The caller acknowledges only its matching successful revision, or a
stale delivery for which it can account for the later state.

Apply the packaged migrations through `0026_legacy_erasure_deliveries.sql` before enabling app-scoped provisioning.

Sending `roles: []` suspends app access. While suspended, token exchange and refresh return `invalid_grant`, UserInfo rejects existing access tokens, and the directory reports the current denial. The live verifier denies it even when
the subject also has a grant from another source. A subsequent provision call
cannot undo the suspension. A higher revision may explicitly reinstate the
member. Other principals' grants, independently owned grants and Nathan
administrator privileges remain under their existing owners.
The source can record a newer suspension during an account ban or directory
deactivation. Lifting the ban or reactivating the directory identity preserves
the application's suspension and its revision. After an erasure, delivery of
an older role revision for the exact external ID and subject returns
`stale_revision`. An equal or newer role revision returns `identity_conflict`.

## Erase a verified account

After ClassCheck has verified and durably recorded its account deletion, call
`NATHAN_PROVISION.erase({externalId, sub, revision})`. Choose a new revision
strictly greater than its last acknowledged or queued role revision. First
erasure returns `{sub, revision, applied: true}`. The same completed operation
returns `{sub, revision, applied: false}`. A lower revision returns
`stale_revision`; a reused revision for a different operation or a mismatched
identity returns `identity_conflict`. Retry transient failures with the same
ID, subject and revision.

Nathan removes the user, sessions, credentials, app grants, outstanding email
proofs and OAuth tokens in one transaction. It queues logout for registered
relying parties before their session references disappear. The private issuer
records the client and actual ID-token subject for each issued app session.
An RP that accepts subject-wide logout receives one logout per issued subject.
A session-required RP receives its issued session IDs, including when the
corresponding Nathan session has already expired. Historical stored grants
and consents identify additional participating clients. A historical
JWT-only session issued before migration 0023 with neither a consent nor
a stored token requires reconciliation from the relying party's records.
The same applies to a historical consent without a proven SID at an RP that
requires one. Migration 0026 marks ambiguous pending erasures for those RPs as
`unproven_erasure_session` for operator reconciliation.
The source record
retains hashes of the identifiers and the final revision for idempotence. The
source mailbox is cleared. Account erasure is terminal for that external ID.
An administrator, a directory-linked subject, or a subject with independent
ownership or grants in another application needs operator reconciliation.
Better Auth organization owners must transfer their ownership before erasure.
When a privileged transaction rolls back, Nathan attempts to record one failure
per application and operation per minute without including the submitted identity.
