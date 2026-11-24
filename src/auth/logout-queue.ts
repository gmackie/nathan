/**
 * NATH-11: OIDC Back-Channel Logout 1.0 delivery queue.
 *
 * Deliveries are enqueued in the same D1 batch as the revocation they announce (see
 * scim/lifecycle.ts and session-revocation.ts). Directory deprovisioning logs out every session
 * for the subject. Mailbox verification targets the old session IDs at each relying party.
 * Each attempt signs a fresh token with Nathan's ID-token key and a new `jti`.
 * Failures are retried with backoff; after the last attempt a delivery is marked failed and audited.
 *
 * Back-channel logout accelerates logout at relying parties. It is not what blocks a deprovisioned
 * user at Nathan-controlled Workers: the gateway re-resolves access over the NathanVerifier binding
 * at least every 60 s and a banned user is always denied.
 */
import { signJWT } from "better-auth/plugins/jwt";
import { makeSignature } from "better-auth/crypto";
import type { AuthEnv } from "./env";
import { createAuth } from "./instance";
import { issuerOf } from "./rbac";
import { audit } from "./admin-service";
import { fetchNoRedirect } from "../shared/security.mjs";
import { standaloneOrigins } from "./management-ingress";

/** Delay before attempt n+1 after n failed attempts; the queue gives up after the last one. */
export const LOGOUT_RETRY_DELAYS = [15, 60, 300, 900, 3600, 6 * 3600, 12 * 3600];
const TIMEOUT_MS = 5000, TOKEN_LIFETIME = 120;
const EVENT = "http://schemas.openid.net/event/backchannel-logout";

type Due = { id: string; clientId: string; userId: string; sessionId: string | null; issuedSubject: string | null; attempts: number; uri: string | null; disabled: unknown;
  subjectType: string | null; redirectUris: string | null };

// App logout registers its recipients before Better Auth removes the session and clears token FKs.
// A failed deletion keeps the browser session and its pending notifications together for retry.
const released = "(d.reason!='app-session-end' OR NOT EXISTS(SELECT 1 FROM session s WHERE s.id=d.session_id))";

/** Subject the client knows the user by: the user id, or Better Auth's pairwise identifier. */
async function subjectFor(env: AuthEnv, row: Due): Promise<string> {
  if (row.issuedSubject !== null) return row.issuedSubject;
  if (row.subjectType !== "pairwise" || !env.NATHAN_PAIRWISE_SECRET) return row.userId;
  const sector = new URL(JSON.parse(row.redirectUris || "[]")[0]).host;
  return makeSignature(sector + "." + row.userId, env.NATHAN_PAIRWISE_SECRET);
}
export async function nextLogoutDue(env: AuthEnv, connectionId: string | null): Promise<number | null> {
  const row = await env.DB.prepare(
    "SELECT MIN(next_attempt_at) AS due FROM nathan_backchannel_deliveries d WHERE state='pending' AND " + released +
    " AND (?1 IS NULL OR connection_id=?1)"
  ).bind(connectionId).first<{ due: number | null }>();
  return row?.due ?? null;
}

/**
 * Sends due deliveries (optionally only those a connection enqueued). Never throws for a delivery
 * failure; it records the outcome and schedules the retry. Returns the next due time (seconds).
 */
export async function deliverLogouts(env: AuthEnv, { connectionId = null, sessionId = null, limit = 25 }:
    { connectionId?: string | null; sessionId?: string | null; limit?: number } = {}) {
  const due = (await env.DB.prepare(
    'SELECT d.id AS id, d.client_id AS clientId, d.user_id AS userId, d.session_id AS sessionId, d.issued_subject AS issuedSubject, d.attempts AS attempts, c."backchannelLogoutUri" AS uri, ' +
    'c."disabled" AS disabled, c."subjectType" AS subjectType, c."redirectUris" AS redirectUris ' +
    'FROM nathan_backchannel_deliveries d LEFT JOIN "oauthClient" c ON c."clientId"=d.client_id ' +
    "WHERE d.state='pending' AND d.next_attempt_at<=unixepoch() AND " + released +
    " AND (?1 IS NULL OR d.connection_id=?1) AND (?3 IS NULL OR d.session_id=?3) ORDER BY d.next_attempt_at LIMIT ?2"
  ).bind(connectionId, limit, sessionId).all<Due>()).results;
  let delivered = 0;
  if (due.length) {
    // A standalone installation issues customer tokens at the app's origin.
    // Cron runs under the management configuration and must use that same issuer.
    const appOrigin = env.NATHAN_APP_ORIGIN && env.NATHAN_APP_ORIGIN !== env.NATHAN_ISSUER
      ? standaloneOrigins(env)?.app : env.NATHAN_ISSUER;
    if (!appOrigin) throw Error("Standalone logout issuer is unavailable");
    const issuerEnv = { ...env, NATHAN_ISSUER: appOrigin };
    const context: any = await createAuth(issuerEnv).$context;
    const options = context.options.plugins?.find((p: any) => p.id === "jwt")?.options;
    const iss = issuerOf(issuerEnv);
    const outcomes = await Promise.all(due.map(async row => {
      if (!row.uri || row.disabled === 1 || row.disabled === true || row.disabled === "1") return { row, status: "client_unavailable", ok: false, final: true };
      try {
        const iat = Math.floor(Date.now() / 1000);
        const token = await signJWT({ context } as any, {
          options, header: { typ: "logout+jwt" },
          payload: { iss, aud: row.clientId, sub: await subjectFor(env, row), sid: row.sessionId ?? undefined, iat, exp: iat + TOKEN_LIFETIME, jti: crypto.randomUUID(), events: { [EVENT]: {} } }
        });
        const response = await fetchNoRedirect(row.uri, {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
          body: new URLSearchParams({ logout_token: token }).toString(), signal: AbortSignal.timeout(TIMEOUT_MS)
        });
        await response.body?.cancel();
        return { row, status: String(response.status), ok: response.status === 200 || response.status === 204, final: false };
      } catch {
        return { row, status: "network_error", ok: false, final: false };
      }
    }));
    const statements = [];
    for (const { row, status, ok, final } of outcomes) {
      const attempts = row.attempts + 1;
      if (ok) delivered++;
      const failed = !ok && (final || attempts > LOGOUT_RETRY_DELAYS.length);
      statements.push(env.DB.prepare(
        "UPDATE nathan_backchannel_deliveries SET state=?, attempts=?, last_status=?, next_attempt_at=unixepoch()+?, updated_at=unixepoch() WHERE id=? AND state='pending'"
      ).bind(ok ? "delivered" : failed ? "failed" : "pending", attempts, status,
        ok || failed ? 0 : LOGOUT_RETRY_DELAYS[attempts - 1], row.id));
      if (failed) await audit(env, "system:logout-queue", "backchannel_logout_failed", row.clientId + ":" + row.userId, "failed").catch(() => {});
    }
    await env.DB.batch(statements);
  }
  return { attempted: due.length, delivered, nextDue: await nextLogoutDue(env, connectionId) };
}
