import { compactVerify, createLocalJWKSet, decodeJwt, type JSONWebKeySet } from "jose";
import type { AuthEnv } from "./env";
import type { createAuth } from "./instance";
import { deliverLogouts } from "./logout-queue";
import { issuerOf } from "./rbac";

const parameters = new Set(["client_id", "id_token_hint", "post_logout_redirect_uri", "state"]);
const denied = () => Response.json({ error: "invalid_request" }, { status: 400, headers: { "Cache-Control": "no-store" } });
const unavailable = () => Response.json({ error: "temporarily_unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });

export function logoutForm(raw: string, origin: string) {
  const form = new URLSearchParams(raw);
  for (const name of form.keys()) {
    if (!parameters.has(name) || form.getAll(name).length !== 1) return null;
  }
  const client = form.get("client_id"), hint = form.get("id_token_hint"), target = form.get("post_logout_redirect_uri");
  if (!client || client.length > 200 || !hint || target !== origin + "/sign-in") return null;
  const state = form.get("state"), location = new URL(target);
  if (state !== null) {
    if (state.length > 2048 || /\p{Cc}/u.test(state)) return null;
    location.searchParams.set("state", state);
  }
  return { client, hint, location };
}

// Verify a logout hint against the installed issuer's keys without an HTTP trip through ClassCheck.
// OIDC permits expired ID token hints for a current session. Bound that exception to one session
// lifetime and to this issuer's ID-token profile; ordinary token verification keeps its normal expiry.
async function matchesSession(hint: string, keys: JSONWebKeySet, issuer: string, client: string,
    session: { id: string; userId: string }, lifetime: number) {
  try {
    const { protectedHeader } = await compactVerify(hint, createLocalJWKSet(keys), { algorithms: ["EdDSA"] });
    if (typeof protectedHeader.kid !== "string" || !protectedHeader.kid ||
        (protectedHeader.typ !== undefined && protectedHeader.typ !== "JWT")) return false;
    const claims = decodeJwt(hint), now = Math.floor(Date.now() / 1000);
    const { iat, exp, nbf } = claims;
    if (typeof iat !== "number" || !Number.isSafeInteger(iat) || iat > now + 30 || iat < now - lifetime ||
        typeof exp !== "number" || !Number.isSafeInteger(exp) || exp <= iat || exp - iat > lifetime ||
        (nbf !== undefined && (!Number.isSafeInteger(nbf) || nbf > now + 30 || nbf >= exp))) return false;
    return Boolean(session.id && session.userId) &&
      claims.iss === issuer && claims.aud === client && (claims.azp === undefined || claims.azp === client) &&
      claims.sid === session.id && claims.sub === session.userId && typeof claims.at_hash === "string" &&
      /^[A-Za-z0-9_-]{43}$/.test(claims.at_hash) && claims.events === undefined && claims.client_id === undefined &&
      claims.scope === undefined && claims.principal_kind === undefined;
  } catch {
    return false;
  }
}

export async function endAppSession(auth: ReturnType<typeof createAuth>, env: AuthEnv, ctx: ExecutionContext, request: Request,
    form?: NonNullable<ReturnType<typeof logoutForm>>) {
  const headers = request.headers;
  try {
    const current = await auth.api.getSession({ headers, query: { disableCookieCache: true, disableRefresh: true } });
    if (!current) return form ? denied() : auth.handler(request);
    if (form && !await matchesSession(form.hint, await auth.api.getJwks(), issuerOf(env), form.client,
        current.session, (await auth.$context).sessionConfig.expiresIn)) return denied();

    // Better Auth 1.7.14 uses fetch(..., {redirect:"error"}) for logout notifications, which
    // workerd rejects. Capture the hinted client and the other session-bound grants before their
    // sessionId foreign keys are cleared. The queue delivers only after this session is gone.
    await env.DB.prepare("INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,issued_subject,session_id,reason) " +
      "SELECT json_array('app-session-end',?1,c.clientId,t.subject),c.clientId,?2,t.subject,?1,'app-session-end' FROM (" +
      "SELECT ?3 AS client,?2 AS subject WHERE ?3 IS NOT NULL UNION SELECT client_id,issued_subject " +
      "FROM nathan_app_rp_participation WHERE user_id=?2 AND session_id=?1 AND (issued_subject IS NOT NULL OR client_id IS NOT ?3)" +
      ") t JOIN oauthClient c ON c.clientId=t.client WHERE c.backchannelLogoutUri IS NOT NULL AND COALESCE(c.disabled,0)=0 " +
      "AND EXISTS(SELECT 1 FROM session WHERE id=?1 AND userId=?2) ON CONFLICT(id) DO NOTHING")
      .bind(current.session.id, current.session.userId, form?.client ?? null).run();

    // Keep Better Auth's token-revocation hooks and native cookie handling. It can clear the
    // cookie even when a delete fails, so only release the clearances once deletion is durable.
    const result = form ? await auth.api.signOut({ headers, body: { disableRedirect: true }, asResponse: true }) : await auth.handler(request);
    if (!result.ok) return form ? unavailable() : result;
    if (await env.DB.prepare('SELECT 1 FROM "session" WHERE id=?').bind(current.session.id).first())
      return unavailable();
    ctx.waitUntil(deliverLogouts(env, { sessionId: current.session.id }));
    if (!form) return result;
    const response = Response.json({ url: form.location.href }, { headers: { "Cache-Control": "no-store" } });
    for (const cookie of result.headers.getSetCookie()) response.headers.append("Set-Cookie", cookie);
    return response;
  } catch {
    return unavailable();
  }
}
