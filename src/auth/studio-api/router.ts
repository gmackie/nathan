/**
 * NATH-24: a small router for `/studio/api/v1/*`.
 *
 * Request order for every route:
 *   1. match path (404 not_found) and method (405 method_not_allowed);
 *   2. authorizeStudioRequest: same-origin JSON for writes, then session, admin and step-up;
 *   3. read the body with a byte limit (413) and parse JSON (400 invalid_json);
 *   4. check the input against the route's schema, then call the service.
 *
 * Step 4 deliberately calls the service even when the schema refuses the input. The services are
 * the authority (they repeat every check and look up state), and several of them write a security
 * audit row for a refused attempt (RBAC, admission, providers, SCIM, directory clients, SAML IdP).
 * Calling them keeps those rows identical to the legacy `/studio/api/*` routes, so this API adds
 * no write path and changes no audit record. When the schema refused the input and the service
 * refused it too, the response is 400 validation_failed with the schema issues. If the service
 * accepts an input the schema refused, the schema is stricter than the service: the result is
 * returned as on the legacy route and the drift is logged (route action only, never input).
 */
import type { z } from "zod";
import type { AuthEnv } from "../env";
import { readBoundedText } from "../bounded-body.mjs";
import { authorizeStudioRequest, auditActor, type StudioPrincipal, type StudioStepUp } from "./authorize";
import { StudioApiError, studioError, studioFail, studioOk, rejected } from "./http";
import type { StudioIssue } from "./schemas";

export const STUDIO_API_V1 = "/studio/api/v1";

export type StudioContext = {
  request: Request;
  env: AuthEnv;
  auth: any;
  url: URL;
  principal: StudioPrincipal;
  /** Audit actor for service calls (the administrator's user id for `nathan-admin`). */
  actor: string;
};

export type StudioRoute = {
  method: "GET" | "POST";
  /** Path below /studio/api/v1, e.g. "/admins/grant". */
  path: string;
  /** Stable action name, e.g. "admins.grant" (future scoped principals are limited to actions). */
  action: string;
  /** Body schema (POST) or query schema (GET, values are strings). */
  input: z.ZodType;
  /** Body byte limit for writes (the legacy route's limit). */
  maxBytes?: number;
  stepUp?: StudioStepUp;
  /** Calls the service with the raw input (body object or query values). */
  run: (ctx: StudioContext, input: any) => Promise<unknown>;
  /** Maps a service error to a safe refusal. Default: 409 operation_rejected with `fallback`. */
  refusal?: (error: unknown) => StudioApiError;
  /** Safe message for refusals without a specific mapping. */
  fallback?: string;
};

/** Zod issues without input values (path, code and Zod's message only). */
export function schemaIssues(error: z.ZodError): StudioIssue[] {
  return error.issues.slice(0, 20).map(issue => ({
    path: issue.path.map(String).join("."),
    code: issue.code,
    message: issue.message.slice(0, 200)
  }));
}

/** Query parameters as a plain object; a repeated parameter keeps its first value. */
function queryInput(url: URL): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of url.searchParams) if (!Object.hasOwn(out, k)) out[k] = v;
  return out;
}

function refusalOf(route: StudioRoute, error: unknown): StudioApiError {
  if (error instanceof StudioApiError) return error;
  if (route.refusal) return route.refusal(error);
  return rejected(route.fallback ?? "Change rejected");
}

export function createStudioRouter(routes: StudioRoute[]) {
  const byPath = new Map<string, StudioRoute[]>();
  for (const route of routes) {
    const key = STUDIO_API_V1 + route.path;
    if (byPath.get(key)?.some(r => r.method === route.method)) throw Error("Duplicate Studio API route " + route.method + " " + key);
    byPath.set(key, [...(byPath.get(key) ?? []), route]);
  }

  return async function handleStudioApiV1(request: Request, env: AuthEnv, auth: any): Promise<Response> {
    const url = new URL(request.url);
    const candidates = byPath.get(url.pathname);
    if (!candidates) return studioFail(studioError(404, "not_found", "Unknown Studio API route"));
    const route = candidates.find(r => r.method === request.method);
    if (!route) return studioFail(studioError(405, "method_not_allowed", "Method not allowed"), { Allow: candidates.map(r => r.method).join(", ") });

    const write = route.method === "POST";
    const decision = await authorizeStudioRequest(request, env, auth, { action: route.action, write, stepUp: route.stepUp ?? "admin-policy" });
    if (!decision.ok) return studioFail(decision.error);
    const ctx: StudioContext = { request, env, auth, url, principal: decision.principal, actor: auditActor(decision.principal) };

    let input: unknown;
    if (write) {
      const raw = await readBoundedText(request, route.maxBytes ?? 4096);
      if (raw === null) return studioFail(studioError(413, "payload_too_large", "Request too large"));
      try { input = JSON.parse(raw); } catch { return studioFail(studioError(400, "invalid_json", "Invalid JSON")); }
    } else input = queryInput(url);

    const checked = route.input.safeParse(input);
    try {
      const data = await route.run(ctx, input);
      if (!checked.success) console.warn("studio_api_schema_drift", route.action);
      return studioOk(data);
    } catch (error) {
      if (!checked.success) return studioFail(studioError(400, "validation_failed", "Input does not match the request schema", schemaIssues(checked.error)));
      return studioFail(refusalOf(route, error));
    }
  };
}
