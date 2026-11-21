import { GatekeeperError, record } from "../core/model.ts";
export function httpsUrl(value: unknown): URL {
  if (typeof value !== "string" || value.length > 2048) throw new GatekeeperError("InvalidConfiguration", "Expected a pinned HTTPS URL");
  let url: URL;
  try { url = new URL(value); } catch { throw new GatekeeperError("InvalidConfiguration", "Invalid URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new GatekeeperError("InvalidConfiguration", "Expected HTTPS without credentials or fragment");
  return url;
}
/** Bound JSON trees before traversing/stringifying; no reference expansion, prototype keys or cycles. */
export function boundedJson(value: unknown, limits: {bytes?: number; nodes?: number; depth?: number; references?: boolean} = {}): void {
  let nodes = 0;
  const ancestors = new Set<object>();
  const visit = (v: unknown, depth: number): void => {
    if (++nodes > (limits.nodes ?? 50000) || depth > (limits.depth ?? 32)) throw new GatekeeperError("InputBudgetExceeded", "JSON complexity exceeds budget");
    if (typeof v === "number" && !Number.isFinite(v)) throw new GatekeeperError("InvalidDocument", "Invalid JSON number");
    if (v === null || ["string", "number", "boolean"].includes(typeof v)) return;
    if (!Array.isArray(v) && !record(v)) throw new GatekeeperError("InvalidDocument", "Expected plain JSON data");
    if (ancestors.has(v)) throw new GatekeeperError("InvalidDocument", "Cyclic JSON data");
    ancestors.add(v);
    if (record(v)) for (const key of Object.keys(v)) {
      if (["__proto__", "prototype", "constructor"].includes(key) || (!limits.references && key === "$ref")) throw new GatekeeperError("InvalidDocument", "Unsupported key or reference");
    }
    for (const item of Object.values(v)) visit(item, depth + 1);
    ancestors.delete(v);
  };
  visit(value, 0);
  if (new TextEncoder().encode(JSON.stringify(value)).length > (limits.bytes ?? 1048576)) throw new GatekeeperError("InputBudgetExceeded", "JSON byte budget exceeded");
}
/** Redirects and arbitrary target selection must be rejected by the caller's pinned transport. */
export async function readBoundedJson(response: Response, limit = 65536): Promise<unknown> {
  if (!response.ok || !response.body || response.redirected) throw new GatekeeperError("UpstreamUnavailable", "Upstream JSON unavailable");
  const reader = response.body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new GatekeeperError("InputBudgetExceeded", "Upstream response too large");
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes)); }
  catch { throw new GatekeeperError("InvalidDocument", "Upstream response is not valid JSON"); }
}
