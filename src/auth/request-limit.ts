import { sha256 } from "../gateway/crypto.ts";
import type { AuthEnv } from "./env";

/** Atomic fixed-window counters shared with MCP, pruned by the identity Worker's cron. */
export async function allowRequests(env: AuthEnv, name: string, subject: string, limit: number, seconds = 60) {
  const bucket = Math.floor(Date.now() / (seconds * 1000));
  const key = name + ":" + (await sha256(subject)).slice(0, 22) + ":" + bucket;
  const row = await env.DB.prepare("INSERT INTO nathan_mcp_limits(id,request_count,expires_at) VALUES (?,1,?) " +
    "ON CONFLICT(id) DO UPDATE SET request_count=request_count+1 RETURNING request_count")
    .bind(key, (bucket + 2) * seconds).first<{ request_count: number }>();
  return Boolean(row && row.request_count <= limit);
}
