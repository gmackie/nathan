/** NATH-24 Studio API v1: per-application roles, permissions, groups and grants (NATH-13). */
import { rbacOverview, listGroups, groupMembers, applyRbacOperation } from "../rbac";
import type { StudioRoute } from "./router";
import { rejected, studioError } from "./http";
import { noInput, rbacQuery, rbacGroupQuery, rbacInput } from "./schemas";

const RBAC_SAFE = /^(Invalid|Unknown|Explicit|Select|User not found|Declare|Too many|Permission keys|Role keys|Group ids|Grant a role|Membership|Description|Application is not registered)/;
/** The RBAC service's own message when it is a known validation message, else a generic refusal. */
export function rbacRefusalMessage(error: unknown) {
  return error instanceof Error && RBAC_SAFE.test(error.message) ? error.message : "RBAC change rejected";
}
const notFound = () => studioError(404, "not_found", "Unknown application or group");

export const routes: StudioRoute[] = [
  { method: "GET", path: "/rbac", action: "rbac.read", input: rbacQuery, refusal: notFound, run: ({ env }, q) => rbacOverview(env, q.app ?? null) },
  { method: "GET", path: "/rbac/groups", action: "rbac.groups.read", input: noInput, refusal: notFound, run: ({ env }) => listGroups(env) },
  { method: "GET", path: "/rbac/group", action: "rbac.group.read", input: rbacGroupQuery, refusal: notFound, run: ({ env }, q) => groupMembers(env, q.id ?? null) },
  { method: "POST", path: "/rbac", action: "rbac.apply", input: rbacInput, maxBytes: 65536,
    refusal: error => rejected(rbacRefusalMessage(error)), run: ({ env, actor }, body) => applyRbacOperation(env, body, actor) }
];
