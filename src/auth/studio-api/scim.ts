/** NATH-24 Studio API v1: SCIM connections, lifecycle settings, group mappings, reviews and outbox. */
import { listScimConnections, createScimConnection, setScimConnectionEnabled, rotateScimToken } from "../scim/admin";
import { updateScimSettings, changeScimMapping, scimConnectionView, SCIM_ADMIN_ERRORS } from "../scim/lifecycle-admin";
import { scimUserOperation, scimOutboxView, skipScimOutbox, SCIM_REVIEW_ERRORS } from "../scim/reviews";
import type { StudioRoute } from "./router";
import { rejected, studioError } from "./http";
import {
  noInput, scimConnectionCreateInput, scimStatusInput, scimRotateInput, scimConnectionQuery, scimOutboxQuery,
  scimSettingsInput, scimMappingInput, scimUserInput, scimOutboxInput
} from "./schemas";

export const SCIM_CONNECTION_REFUSAL = "SCIM change rejected. Verify connection name, server binding and explicit confirmation.";
/** The service's own message when it is on the allowlist (never submitted values), else `fallback`. */
export const scimMessage = (allow: RegExp, fallback: string) => (error: unknown) =>
  error instanceof Error && allow.test(error.message) ? error.message : fallback;
const adminRefusal = (error: unknown) => rejected(scimMessage(SCIM_ADMIN_ERRORS, "SCIM lifecycle change rejected")(error));
const reviewRefusal = (fallback: string) => (error: unknown) => rejected(scimMessage(SCIM_REVIEW_ERRORS, fallback)(error));

export const routes: StudioRoute[] = [
  { method: "GET", path: "/scim/connections", action: "scim.connections.read", input: noInput,
    run: async ({ env }) => ({ connections: await listScimConnections(env) }) },
  { method: "POST", path: "/scim/connections", action: "scim.connections.create", input: scimConnectionCreateInput, maxBytes: 16384,
    fallback: SCIM_CONNECTION_REFUSAL, run: ({ env, actor }, body) => createScimConnection(env, body, actor) },
  { method: "POST", path: "/scim/status", action: "scim.status", input: scimStatusInput, maxBytes: 16384,
    fallback: SCIM_CONNECTION_REFUSAL, run: ({ env, actor }, body) => setScimConnectionEnabled(env, body, actor) },
  { method: "POST", path: "/scim/rotate", action: "scim.rotate", input: scimRotateInput, maxBytes: 16384,
    fallback: SCIM_CONNECTION_REFUSAL, run: ({ env, actor }, body) => rotateScimToken(env, body, actor) },

  { method: "GET", path: "/scim/connection", action: "scim.connection.read", input: scimConnectionQuery,
    refusal: error => error instanceof Error && error.message === "Invalid review filter"
      ? studioError(400, "validation_failed", "Invalid review filter") : studioError(404, "not_found", "Unknown SCIM connection"),
    run: ({ env }, q) => scimConnectionView(env, q.id ?? null, { reviewState: q.reviewState ?? null, reviewOffset: q.reviewOffset ?? null }) },
  { method: "POST", path: "/scim/settings", action: "scim.settings", input: scimSettingsInput, maxBytes: 4096, refusal: adminRefusal,
    run: ({ env, actor }, body) => updateScimSettings(env, body, actor) },
  { method: "POST", path: "/scim/mappings", action: "scim.mappings", input: scimMappingInput, maxBytes: 4096, refusal: adminRefusal,
    run: ({ env, actor }, body) => changeScimMapping(env, body, actor) },

  { method: "GET", path: "/scim/outbox", action: "scim.outbox.read", input: scimOutboxQuery, refusal: reviewRefusal("SCIM outbox unavailable"),
    run: ({ env }, q) => scimOutboxView(env, q.id ?? null) },
  { method: "POST", path: "/scim/outbox", action: "scim.outbox.skip", input: scimOutboxInput, maxBytes: 4096, refusal: reviewRefusal("SCIM operation rejected"),
    run: ({ env, actor }, body) => skipScimOutbox(env, body, actor) },
  { method: "POST", path: "/scim/users", action: "scim.users.apply", input: scimUserInput, maxBytes: 4096, refusal: reviewRefusal("SCIM operation rejected"),
    run: ({ env, actor }, body) => scimUserOperation(env, body, actor) }
];
