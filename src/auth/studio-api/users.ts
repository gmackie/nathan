/** NATH-24 Studio API v1: the read-only user directory (no credentials or sessions). */
import { listUsers } from "../admin-service";
import type { StudioRoute } from "./router";
import { noInput } from "./schemas";

export const routes: StudioRoute[] = [
  { method: "GET", path: "/users", action: "users.read", input: noInput, run: async ({ env }) => ({ users: await listUsers(env) }) }
];
