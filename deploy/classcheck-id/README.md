# ClassCheck identity installations

| Stage | ClassCheck web | Nathan management | Worker and D1 |
| --- | --- | --- | --- |
| Staging | beta.classcheck.io | id-stg.classcheck.io | nathan-classcheck-stg-auth |
| Production | classcheck.io | id.classcheck.io | nathan-classcheck-prod-auth |

The ClassCheck web Worker serves end-user pages and calls its own stage’s named Nathan bindings. Cloudflare Access protects every path on the management custom domain. Nathan authenticates management independently and requires recent management-host passkey evidence for Studio. Each environment has its own D1, signing secret, configuration encryption key, confidential web registration, and Access audience.

## Install and deploy

1. Verify the zone, the D1 UUID, and the exact Access application against the stage’s Wrangler config. The management policy allows the designated operator. Check that every path on that hostname is covered, including paths matched by other Access applications.
2. In the ForgeGraph **classcheck-id** stage, set `BETTER_AUTH_SECRET`, `NATHAN_CONFIG_KEY`, `NATHAN_ADMIN_EMAILS`, and `RESEND_API_KEY`. Generate independent keys in each stage. `NATHAN_CONFIG_KEY` is 32 random bytes encoded in unpadded base64url. Both Nathan Workers send mail through Resend as `ClassCheck <noreply@classcheck.io>`. Verify the `classcheck.io` sending domain in the Resend account for each stage. In the **classcheck** stage, store `NATHAN_CLIENT_ID=classcheck-web-staging` or `classcheck-web-production` and its own high-entropy `NATHAN_CLIENT_SECRET`.
3. Run the normal staged deployment from this directory at the reviewed commit. The target applies D1 migrations, uploads the Worker privately and synchronizes the stage secrets. Its config disables workers.dev and version previews. Confirm the remote Worker has the expected D1, all four secrets and the stage-specific Access audience before attaching its management domain.

   ```sh
   cd deploy/classcheck-id
   forge deploy create staging --target auth --ref "$reviewed_sha" --wait
   ```

4. Initialize the fresh database with the stage-specific app, audience, client verifier, app role definitions, and owner invitation. From the **Nathan checkout root**, with an account-authorized `CLOUDFLARE_API_TOKEN`, pass the ClassCheck stage’s confidential credential on standard input. This operation uses the same D1 batch mechanism as Nathan’s administrative CLI. A unique audit receipt makes retries safe and a conflicting existing tenant aborts the transaction.

   ```sh
   (cd "$classcheck_checkout" && forge secret get NATHAN_CLIENT_SECRET --stage "$stage") |
     NATHAN_ADMIN_EMAILS="$(cd deploy/classcheck-id && forge secret get NATHAN_ADMIN_EMAILS --stage "$stage")" \
     node deploy/classcheck-id/bootstrap.mjs "$stage" --apply
   ```

5. From the Nathan checkout root, apply native-client registration and web logout to the installed staging database before its protocol checks. Each command verifies the stage D1 UUID and the installation receipt, commits the change and audit together, and verifies its own receipt on retry.

   ```sh
   node deploy/classcheck-id/native-clients.mjs staging --apply
   node deploy/classcheck-id/web-logout.mjs staging --apply
   ```

6. Attach the exact management custom domain to the private Worker after verifying Access. Confirm the host redirects an anonymous request to Cloudflare Access and that its workers.dev and preview endpoints are disabled. Before promoting production, request two staging sign-ins from the ClassCheck origin with the QA mailbox. Verify both messages arrive from `ClassCheck <noreply@classcheck.io>`. Redeem the code from the first and the link from the second, completing each flow through consent, callback, session and sign-out. Check MFA with an enrolled account and confirm session revocation.

7. After staging verification and production release approval, apply the guarded upgrades to the installed production database before verifying its native and web flows.

   ```sh
   node deploy/classcheck-id/native-clients.mjs production --apply
   node deploy/classcheck-id/web-logout.mjs production --apply
   ```

   ClassCheck controls its rollout mode and retains its previous web Worker version for rollback.

## Management enrollment

The single owner has a seven-day invitation for independent management password enrollment. At the management root, sign in through Cloudflare Access with the approved account and open `/security/setup-owner`. Choose a password and follow the verification email in that browser. The deployment operator can now promote the matching, verified owner using Nathan’s existing CLI. Use a local Nathan config for the same account, exact stage D1 and operator allowlist.

```sh
node scripts/nathan.mjs admin promote "$stage_nathan_config_json" --apply
```

Sign in at the management hostname, open `/security?setup=admin`, enroll a passkey and TOTP, retain the recovery codes, complete setup, and use the new passkey to open Studio. ClassCheck app roles do not grant Studio access.

## Release and rollback

Use the **classcheck-id** ForgeGraph target for subsequent Nathan releases. Verify the app binding and API audience for the stage. Preserve host-only cookie settings and the prior ClassCheck web and Nathan Worker versions. Roll back a Worker version while retaining its D1 and expand-only application data. The one-time bootstrap leaves completed ownership, revoked invitations, disabled clients and all later grants intact on re-execution.
