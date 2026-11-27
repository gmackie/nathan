/** NATH-24 Studio API v1: the read-only user directory (no credentials or sessions). */
import { listUsers } from "../admin-service";
import type { StudioRoute } from "./router";
import { directoryQuery } from "./schemas";

export const routes: StudioRoute[] = [
  { method: "GET", path: "/users", action: "users.read", input: directoryQuery,
    run: async ({ env }, query) => ({ users: await listUsers(env, query.q?.trim()) }) }
];
