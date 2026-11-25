# EducateOS staging identity

The district Worker serves the browser issuer at `https://staging.educateos.io/api/auth`. The private service bindings target `nathan-educateos-stg-auth` with `applicationId: "educateos"`. The district owns the sign-in UI and browser session. Nathan's approved application grants `member` the single permission `profile:read`. The district resolves the verified subject to its existing principal and decides classroom and staff access. The district's teacher MCP client continues to use shared staging Nathan.

## Install

1. Verify the D1 name and UUID against `cloudflare.config.ts`. Apply the owner-only Cloudflare Access policy to the whole management hostname `id-stg.educateos.io` and verify its audience. Generate the Wrangler file with `node deploy/educateos-id/cloudflare.config.ts`. CI checks the committed copy before ForgeGraph adds deployment metadata.
2. Configure the ForgeGraph `educateos-id` staging secrets. Use independent `BETTER_AUTH_SECRET` and `NATHAN_CONFIG_KEY` values (the latter is 32 random bytes in unpadded base64url), the Access operator's normalized email in `NATHAN_ADMIN_EMAILS`, and a verified `EMAIL_FROM` with its authorized `RESEND_API_KEY`. Store the high-entropy confidential `NATHAN_CLIENT_SECRET` on the district stage. The customer sign-in endpoints support verified email and enrolled TOTP. Password and passkey enrollment for management run only after Access authenticates the operator.
3. Deploy the `educateos-id` staging target `auth` at the reviewed revision. The target applies Nathan's D1 migrations and deploys the Worker privately with no workers.dev or preview ingress. Verify the live D1 binding, Access audience, five secret names and cron schedules before attaching the exact management custom domain. Verify an anonymous management request redirects to the operator's Access team.
4. Initialize from the Nathan checkout root. Pass the client secret directly from the district secret store on stdin. Supply the operator's configured email and an account-authorized staging D1 credential to the process. The command checks the account, database name, UUID and a fresh installation, then commits the registration, owner invitation and audit receipt in one D1 batch. Subsequent runs verify the receipt and the active client. Changes made by an operator take precedence and are preserved.

```sh
FG_APP=educateos-staging forge secret get NATHAN_CLIENT_SECRET --stage staging |
  NATHAN_ADMIN_EMAILS="$(FG_APP=educateos-id forge secret get NATHAN_ADMIN_EMAILS --stage staging)" \
  node deploy/educateos-id/bootstrap.mjs --apply
```

For an authorized Cloudflare connector, use the same pipeline with `--batch-out <new-private-file>`. Check the exported account and database against the target. Read `checkReceipt` first. If it returns zero rows, execute `batch` as a single D1 batch. Read `checkReceipt` and `verify` again. Require a receipt row and `configured=1`. Remove the local private file after use; it contains the client verifier. For command-line verification, run the same pipeline with `--verify`.

5. Confirm the web client `educateos-web-staging` has the product's exact `/auth/callback`, `/sign-in` logout return and signed `/auth/backchannel-logout` receiver. Verify browser discovery on the product origin, a teacher's delivered sign-in code, their enrolled classroom, sign-out and signed logout delivery. The management owner uses the separate seven-day invitation at `/security/setup-owner`, verifies their email, and completes Nathan's administrative promotion and passkey step-up.
