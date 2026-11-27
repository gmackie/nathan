/** NATH-24 Studio API v1: the recent security audit log (read). */
import { recentAudit } from "../admin-service";
import type { StudioRoute } from "./router";
import { noInput } from "./schemas";

export const routes: StudioRoute[] = [
  { method: "GET", path: "/audit", action: "audit.read", input: noInput, run: async ({ env }) => ({ events: await recentAudit(env) }) }
];
