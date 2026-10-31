import { createRemoteJWKSet, jwtVerify } from "jose";
import { pkceChallenge, randomId } from "./crypto";
import type { GatewayEnv } from "./env";
import { validateIssuer } from "../shared/security.mjs";

type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};
export async function discover(env: GatewayEnv): Promise<Discovery> {
  const issuer = validateIssuer(env.NATHAN_ISSUER);
  const location = issuer + "/.well-known/openid-configuration";
  const response = await fetch(location, { headers: { Accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(6000) });
  if (!response.ok) throw Error("OIDC discovery failed");
  const metadata = await response.json() as Discovery;
  if (metadata.issuer !== issuer) throw Error("OIDC issuer mismatch");
  const origin = new URL(issuer).origin;
  for (const name of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    const endpoint = new URL(metadata[name]);
    // All endpoints are issued by Nathan, so never accept a different host or insecure URL.
    if (endpoint.protocol !== "https:" || endpoint.origin !== origin) throw Error("Untrusted OIDC endpoint");
  }
  return metadata;
}
export function getCallback(env: GatewayEnv): string {
  return new URL("/__nathan/callback", env.PUBLIC_ORIGIN).href;
}
export async function authorizeUrl(env: GatewayEnv, metadata: Discovery, state: string, nonce: string, verifier: string): Promise<string> {
  const url = new URL(metadata.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: env.OIDC_CLIENT_ID,
    redirect_uri: getCallback(env),
    scope: "openid profile email",
    code_challenge_method: "S256",
    code_challenge: await pkceChallenge(verifier),
    state, nonce
  }).toString();
  return url.href;
}
export async function exchangeCode(env: GatewayEnv, metadata: Discovery, code: string, verifier: string): Promise<{ id_token: string }> {
  if (!env.OIDC_CLIENT_SECRET) throw Error("OIDC client secret missing");
  const basic = btoa(env.OIDC_CLIENT_ID + ":" + env.OIDC_CLIENT_SECRET);
  const response = await fetch(metadata.token_endpoint, {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + basic },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: getCallback(env), code_verifier: verifier
    }),
    signal: AbortSignal.timeout(6000)
  });
  if (!response.ok) throw Error("OIDC token exchange failed");
  const result = await response.json() as { id_token?: unknown };
  if (typeof result.id_token !== "string" || result.id_token.length > 16384) throw Error("OIDC ID token missing");
  return { id_token: result.id_token };
}
export async function verifyIdToken(env: GatewayEnv, metadata: Discovery, token: string, nonce: string) {
  const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
  const { payload } = await jwtVerify(token, jwks, {
    issuer: metadata.issuer,
    audience: env.OIDC_CLIENT_ID,
    algorithms: ["RS256", "ES256", "EdDSA"],
    clockTolerance: 30
  });
  if (payload.nonce !== nonce) throw Error("OIDC nonce mismatch");
  if (!payload.sub || typeof payload.sub !== "string") throw Error("OIDC subject missing");
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== env.OIDC_CLIENT_ID)
    throw Error("OIDC azp mismatch");
  if (env.REQUIRE_AAL2 === "true") {
    const accepted = (env.ACCEPTED_ACRS || "").split(",").map(x => x.trim()).filter(Boolean);
    if (!accepted.length || !accepted.includes(String(payload.acr || "")))
      throw Error("Required authentication assurance was not verified");
  }
  return payload;
}
