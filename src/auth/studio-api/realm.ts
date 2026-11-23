/** NATH-24 Studio API v1: the verified domain realm and its explicitly registered clients. */
import { loadVerifiedRealm, listRealmClients, registerRealmClient, registerRealmClientsBatch } from "../domain-realm";
import type { StudioRoute } from "./router";
import { studioError } from "./http";
import { noInput, realmClientInput, realmClientBatchInput } from "./schemas";

export const REALM_REGISTRATION_REFUSAL =
  "Registration denied or incomplete. Check the exact hostname, existing realm clients and security audit before retrying.";

export const routes: StudioRoute[] = [
  { method: "GET", path: "/realm", action: "realm.read", input: noInput,
    refusal: () => studioError(503, "unavailable", "Domain realm configuration is incomplete or unverified"),
    run: async ({ env }) => ({ realm: await loadVerifiedRealm(env) }) },
  { method: "GET", path: "/realm/clients", action: "realm.clients.read", input: noInput,
    refusal: () => studioError(503, "unavailable", "Cannot load domain realm clients"),
    run: ({ env }) => listRealmClients(env) },
  { method: "POST", path: "/realm/clients", action: "realm.clients.create", input: realmClientInput, maxBytes: 8192,
    fallback: REALM_REGISTRATION_REFUSAL, run: ({ env, auth, request, actor }, body) => registerRealmClient(auth, env, request.headers, body, actor) },
  { method: "POST", path: "/realm/clients/batch", action: "realm.clients.batch", input: realmClientBatchInput, maxBytes: 8192,
    fallback: REALM_REGISTRATION_REFUSAL, run: ({ env, auth, request, actor }, body) => registerRealmClientsBatch(auth, env, request.headers, body, actor) }
];
