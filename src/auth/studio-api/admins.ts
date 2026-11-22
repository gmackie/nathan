/** NATH-24 Studio API v1: administrator grants (bootstrap owner, explicit D1 grants). */
import { listAdminGrants, grantAdmin, revokeAdminGrant } from "../admin-service";
import type { StudioRoute } from "./router";
import { noInput, adminGrantInput, adminRevokeInput } from "./schemas";

export const ADMIN_GRANT_REFUSAL = "Admin grant/revocation denied; check verified identity, confirmation and recovery policy";

export const routes: StudioRoute[] = [
  { method: "GET", path: "/admins", action: "admins.read", input: noInput, run: ({ env }) => listAdminGrants(env) },
  { method: "POST", path: "/admins/grant", action: "admins.grant", input: adminGrantInput, maxBytes: 4096,
    fallback: ADMIN_GRANT_REFUSAL, run: ({ env, actor }, body) => grantAdmin(env, body, actor) },
  { method: "POST", path: "/admins/revoke", action: "admins.revoke", input: adminRevokeInput, maxBytes: 4096,
    fallback: ADMIN_GRANT_REFUSAL, run: ({ env, actor }, body) => revokeAdminGrant(env, body, actor) }
];
