import { runWithAdapter } from "@better-auth/core/context";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import type { passkey, Passkey } from "@better-auth/passkey";
import { APIError, createAuthEndpoint, getSessionFromCtx } from "better-auth/api";
import { managementEmail, type AuthEnv } from "./env";
import { activeManagementUser, epochSeconds } from "./management-storage";

type VerifyRegistration = ReturnType<typeof passkey>["endpoints"]["verifyPasskeyRegistration"];
type VerifiedPasskey = Omit<Passkey, "id">;
const enrollmentChanged = () => new APIError("FORBIDDEN", { message: "Verify an enrolled sign-in method and try adding the passkey again." });

/** The provider has already verified the WebAuthn challenge and credential. Check enrollment
 * and assurance in the same D1 write that stores it, so concurrent TOTP activation is ordered. */
export async function storeManagementPasskey(env: AuthEnv, sessionId: string, credential: VerifiedPasskey): Promise<Passkey> {
  const db = env.DB, id = crypto.randomUUID();
  const [saved] = await db.batch([
    db.prepare(`
      WITH enrollment AS (
        SELECT u.id, COALESCE(u.twoFactorEnabled,0) AS totp_enabled,
          (SELECT count(*) FROM twoFactor WHERE userId=u.id) AS factor_count,
          EXISTS(SELECT 1 FROM twoFactor WHERE userId=u.id AND verified=1) AS totp_verified,
          EXISTS(SELECT 1 FROM passkey WHERE userId=u.id) AS has_passkey
        FROM user u JOIN session s ON s.userId=u.id
        WHERE u.id=?1 AND lower(u.email)=?2 AND s.id=?3 AND ${activeManagementUser}
          AND ${epochSeconds("s.expiresAt")}>unixepoch()
          AND NOT EXISTS(SELECT 1 FROM nathan_email_otp_sessions WHERE session_id=s.id)
      )
      INSERT INTO passkey(id,userId,name,publicKey,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid)
      SELECT ?4,id,?5,?6,?7,?8,?9,?10,?11,?12,?13 FROM enrollment e
      WHERE e.factor_count<=1 AND e.totp_enabled=e.totp_verified
        AND ((e.has_passkey=0 AND e.totp_verified=0) OR
          (e.has_passkey=1 AND EXISTS(SELECT 1 FROM nathan_admin_assurance a WHERE a.session_id=?3
            AND a.user_id=e.id AND a.method='passkey' AND a.verified_at BETWEEN unixepoch()-900 AND unixepoch())) OR
          (e.totp_verified=1 AND (e.has_passkey=0 OR NOT EXISTS(
            SELECT 1 FROM nathan_security_overrides WHERE id='primary' AND require_recent_admin_passkey=1))
            AND EXISTS(SELECT 1 FROM nathan_management_totp t JOIN twoFactor f ON f.id=t.factor_id
              WHERE f.userId=e.id AND f.verified=1 AND t.session_id=?3 AND t.verified_at BETWEEN unixepoch()-900 AND unixepoch())))
    `).bind(credential.userId, env[managementEmail], sessionId, id, credential.name ?? null, credential.publicKey,
      credential.credentialID, credential.counter, credential.deviceType, Number(credential.backedUp),
      credential.transports ?? null, credential.createdAt.toISOString(), credential.aaguid ?? null),
    db.prepare(`INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
      SELECT ?,?,'management_passkey_enrolled',?,'succeeded' WHERE changes()=1`)
      .bind(crypto.randomUUID(), credential.userId, id)
  ]);
  if (saved.meta.changes !== 1) throw enrollmentChanged();
  return { ...credential, id };
}

/** Keep Better Auth's fresh session, challenge and cryptographic verification. Replace only its
 * passkey INSERT on this dedicated endpoint. D1 cannot transact across provider adapter calls. */
export function managementPasskeyEndpoint(env: AuthEnv, provider: VerifyRegistration): VerifyRegistration {
  return createAuthEndpoint(provider.path, provider.options, async ctx => {
    const current = await getSessionFromCtx(ctx);
    if (!current) throw enrollmentChanged();
    const guard = <A extends DBTransactionAdapter>(base: A): A => ({
      ...base,
      create: (async input => {
        if (input.model !== "passkey") return base.create(input);
        // The pinned passkey verifier constructs this record from attestation.
        const credential = input.data as unknown as VerifiedPasskey;
        if (credential.userId !== current.user.id) throw enrollmentChanged();
        return storeManagementPasskey(env, current.session.id, credential);
      }) as A["create"]
    });
    const base = ctx.context.adapter;
    const adapter = guard(base);
    adapter.transaction = work => base.transaction(transaction => work(guard(transaction)));
    const { response, headers } = await runWithAdapter(adapter, () => provider({
      ...ctx, context: { ...ctx.context, adapter }, asResponse: false, returnHeaders: true, returnStatus: false
    }));
    for (const cookie of headers.getSetCookie()) ctx.responseHeaders.append("Set-Cookie",cookie);
    return response;
  });
}
