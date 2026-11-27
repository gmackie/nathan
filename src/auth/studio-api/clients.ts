/**
 * NATH-24 Studio API v1: OAuth/OIDC clients and protected applications.
 * setOAuthClientStatus and setApplicationStatus were inline in worker.ts; the legacy routes and
 * this API now share them (same validation, same audit rows).
 */
import type { AuthEnv } from "../env";
import { listClients, listApplications, upsertApplication, setApplicationEnabled, createOAuthClient } from "../admin-service";
import { updateRealmClientStatus } from "../domain-realm";
import type { StudioRoute } from "./router";
import { studioError } from "./http";
import { noInput, clientCreateInput, clientStatusInput, applicationUpsertInput, applicationStatusInput } from "./schemas";

/** Input refused before anything was written; the message is safe to show. */
export class StudioInputError extends Error {}

export const CLIENT_CREATE_REFUSAL = "Client creation rejected; verify exact redirect URI, permitted scopes and provider configuration";
export const CLIENT_STATUS_REFUSAL = "Client update failed or not authorized";
export const APPLICATION_REFUSAL = "Operation denied or rejected by identity provider";

/**
 * Enables or disables an OAuth client (and its domain-realm record). Audited as
 * oauth_client_disable / oauth_client_enable: "attempted", then "succeeded" or "failed".
 * Invalid input throws StudioInputError before anything is written.
 */
export async function setOAuthClientStatus(auth: any, env: AuthEnv, headers: Headers, body: any, actor: string) {
  if (typeof body?.clientId !== "string" || !/^[A-Za-z0-9._-]{1,200}$/.test(body.clientId) || typeof body.disabled !== "boolean")
    throw new StudioInputError("Invalid client status update");
  const auditId = crypto.randomUUID();
  const action = body.disabled ? "oauth_client_disable" : "oauth_client_enable";
  await env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
    .bind(auditId, actor, action, body.clientId, "attempted").run();
  try {
    await auth.api.adminUpdateOAuthClient({ headers, body: { client_id: body.clientId, update: { disabled: body.disabled } } });
    await updateRealmClientStatus(env, body.clientId, body.disabled);
    await env.DB.prepare("UPDATE nathan_security_audit SET outcome=? WHERE id=?").bind("succeeded", auditId).run();
    return { updated: true, clientId: body.clientId as string, disabled: body.disabled as boolean };
  } catch {
    await env.DB.prepare("UPDATE nathan_security_audit SET outcome=? WHERE id=?").bind("failed", auditId).run();
    throw Error(CLIENT_STATUS_REFUSAL);
  }
}

/** Enables or disables a protected application after the exact typed confirmation. */
export async function setApplicationStatus(env: AuthEnv, body: any, actor: string) {
  if (typeof body.enabled !== "boolean" || body.confirm !== ("CONFIRM " + (body.enabled ? "ENABLE " : "DISABLE ") + body.id))
    throw new StudioInputError("Explicit confirmation required");
  return setApplicationEnabled(env, body.id, body.enabled, actor);
}

/** StudioInputError keeps its message (validation, no values); anything else uses `fallback`. */
const inputOr = (fallback: string) => (error: unknown) =>
  error instanceof StudioInputError ? studioError(400, "validation_failed", error.message) : studioError(409, "operation_rejected", fallback);

export const routes: StudioRoute[] = [
  { method: "GET", path: "/clients", action: "clients.read", input: noInput, run: async ({ env }) => ({ clients: await listClients(env) }) },
  { method: "POST", path: "/clients", action: "clients.create", input: clientCreateInput, maxBytes: 8192, fallback: CLIENT_CREATE_REFUSAL,
    run: ({ env, auth, request, actor }, body) => createOAuthClient(auth, env, request.headers, body, actor) },
  { method: "POST", path: "/clients/status", action: "clients.status", input: clientStatusInput, maxBytes: 4096,
    refusal: inputOr(CLIENT_STATUS_REFUSAL), run: ({ env, auth, request, actor }, body) => setOAuthClientStatus(auth, env, request.headers, body, actor) },
  { method: "GET", path: "/apps", action: "apps.read", input: noInput, run: async ({ env }) => ({ applications: await listApplications(env) }) },
  { method: "POST", path: "/apps", action: "apps.upsert", input: applicationUpsertInput, maxBytes: 16384, fallback: APPLICATION_REFUSAL,
    run: ({ env, actor }, body) => upsertApplication(env, body, actor) },
  { method: "POST", path: "/apps/status", action: "apps.status", input: applicationStatusInput, maxBytes: 16384,
    refusal: inputOr(APPLICATION_REFUSAL), run: ({ env, actor }, body) => setApplicationStatus(env, body, actor) }
];
