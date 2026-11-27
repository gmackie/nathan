/** NATH-24 Studio API v1: token audiences, client principal kinds, machine clients (NATH-15) and directory clients. */
import { tokenOverview, applyTokenOperation } from "../tokens";
import { createDirectoryClient } from "../directory";
import type { StudioRoute } from "./router";
import { rejected } from "./http";
import { rbacRefusalMessage } from "./rbac";
import { noInput, tokenInput, directoryClientInput } from "./schemas";

export function tokenRefusalMessage(error: unknown) {
  return error instanceof Error && /^(Invalid|Unknown|Explicit)/.test(error.message) ? error.message : "Token change rejected";
}

export const routes: StudioRoute[] = [
  { method: "GET", path: "/tokens", action: "tokens.read", input: noInput, run: ({ env }) => tokenOverview(env) },
  { method: "POST", path: "/tokens", action: "tokens.apply", input: tokenInput, maxBytes: 8192,
    refusal: error => rejected(tokenRefusalMessage(error)), run: ({ env, auth, request, actor }, body) => applyTokenOperation(auth, env, request.headers, body, actor) },
  // Legacy POST /studio/api/directory/clients shares the RBAC route and its refusal messages.
  { method: "POST", path: "/directory/clients", action: "directory.clients.create", input: directoryClientInput, maxBytes: 65536,
    refusal: error => rejected(rbacRefusalMessage(error)), run: ({ env, auth, request, actor }, body) => createDirectoryClient(auth, env, request.headers, body, actor) }
];
